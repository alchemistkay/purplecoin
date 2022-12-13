//! X11 resource manager library.
//!
//! Usage example (please cache the database in real applications instead of re-opening it whenever
//! a value is needed):
//! ```
//! use x11rb::{connection::Connection, errors::ReplyError, resource_manager::Database};
//! fn get_xft_dpi(conn: &impl Connection) -> Result<Option<u32>, ReplyError> {
//!     let db = Database::new_from_default(conn)?;
//!     let value = db.get_value("Xft.dpi", "");
//!     Ok(value.ok().flatten())
//! }
//! ```
//!
//! This functionality is similar to what is available to C code through xcb-util-xrm and Xlib's
//! `Xrm*` function family. Not all their functionality is available in this library. Please open a
//! feature request if you need something that is not available.
//!
//! The code in this module is only available when the `resource_manager` feature of the library is
//! enabled.

use std::env::var_os;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::connection::Connection;
use crate::errors::ReplyError;
use crate::protocol::xproto::{AtomEnum, ConnectionExt as _};

mod matcher;
mod parser;

/// Maximum nesting of #include directives, same value as Xlib uses.
/// After following this many `#include` directives, further includes are ignored.
const MAX_INCLUSION_DEPTH: u8 = 100;

/// How tightly does the component of an entry match a query?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binding {
    /// We have a tight match, meaning that the next component of the entry must match the query.
    Tight,
    /// We have a loose match, meaning that any number of components can be skipped before the next
    /// match.
    Loose,
}

/// A component of a database entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Component {
    /// A string component
    Normal(String), // Actually just a-z, A-Z, 0-9 and _ or - is allowed
    /// A wildcard component ("?") that matches anything
    Wildcard,
}

/// A single entry in the resource manager database.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Entry {
    /// The components of the entry describe which queries it matches
    components: Vec<(Binding, Component)>,
    /// The value of the entry is what the caller gets after a match.
    value: Vec<u8>,
}

/// A X11 resource database.
///
/// The recommended way to load a database is through [`Database::new_from_default`].
#[derive(Debug, Default, Clone)]
pub struct Database {
    entries: Vec<Entry>,
}

impl Database {
    /// Create a new X11 resource database from the default locations.
    ///
    /// The default location is a combination of two places. First, the following places are
    /// searched for data:
    /// - The `RESOURCE_MANAGER` property of the first screen's root window (See
    ///   [`Self::new_from_resource_manager`]).
    /// - If not found, the file `$HOME/.Xresources` is loaded.
    /// - If not found, the file `$HOME/.Xdefaults` is loaded.
    ///
    /// The result of the above search of the above search is combined with:
    /// - The contents of the file `$XENVIRONMENT`, if this environment variable is set.
    /// - Otherwise, the contents of `$HOME/.Xdefaults-[hostname]`.
    ///
    /// This function only returns an error if communication with the X11 server fails. All other
    /// errors are ignored. It might be that an empty database is returned.
    ///
    /// The behaviour of this function is mostly equivalent to Xlib's `XGetDefault()`. The
    /// exception is that `XGetDefault()` does not load `$HOME/.Xresources`.
    ///
    /// The behaviour of this function is equivalent to xcb-util-xrm's
    /// `xcb_xrm_database_from_default()`.
    pub fn new_from_default(conn: &impl Connection) -> Result<Self, ReplyError> {
        let cur_dir = Path::new(".");

        // 1. Try to load the RESOURCE_MANAGER property
        let mut entries = if let Some(db) = Self::new_from_resource_manager(conn)? {
            db.entries
        } else {
            let mut entries = Vec::new();
            if let Some(home) = var_os("HOME") {
                // 2. Otherwise, try to load $HOME/.Xresources
                let mut path = PathBuf::from(&home);
                path.push(".Xresources");
                let read_something = if let Ok(data) = std::fs::read(&path) {
                    parse_data_with_base_directory(&mut entries, &data, Path::new(&home), 0);
                    true
                } else {
                    false
                };
                // Restore the path so it refers to $HOME again
                let _ = path.pop();

                if !read_something {
                    // 3. Otherwise, try to load $HOME/.Xdefaults
                    path.push(".Xdefaults");
                    if let Ok(data) = std::fs::read(&path) {
                        parse_data_with_base_directory(&mut entries, &data, Path::new(&home), 0);
                    }
                }
            }
            entries
        };

        // 4. If XENVIRONMENT is specified, merge the database defined by that file
        if let Some(xenv) = var_os("XENVIRONMENT") {
            if let Ok(data) = std::fs::read(&xenv) {
                let base = Path::new(&xenv).parent().unwrap_or(cur_dir);
                parse_data_with_base_directory(&mut entries, &data, base, 0);
            }
        } else {
            // 5. Load `$HOME/.Xdefaults-[hostname]`
            let mut file = std::ffi::OsString::from(".Xdefaults-");
            file.push(gethostname::gethostname());
            let mut path = match var_os("HOME") {
                Some(home) => PathBuf::from(home),
                None => PathBuf::new(),
            };
            path.push(file);
            if let Ok(data) = std::fs::read(&path) {
                let base = path.parent().unwrap_or(cur_dir);
                parse_data_with_base_directory(&mut entries, &data, base, 0);
            }
        }

        Ok(Self { entries })
    }

    /// Create a new X11 resource database from the `RESOURCE_MANAGER` property of the first
    /// screen's root window.
    ///
    /// This function returns an error if the `GetProperty` request to get the `RESOURCE_MANAGER`
    /// property fails. It returns `Ok(None)` if the property does not exist, has the wrong format,
    /// or is empty.
    pub fn new_from_resource_manager(conn: &impl Connection) -> Result<Option<Self>, ReplyError> {
        let max_length = 100_000_000; // This is what Xlib does, so it must be correct (tm)
        let window = conn.setup().roots[0].root;
        let property = conn
            .get_property(
                false,
                window,
                AtomEnum::RESOURCE_MANAGER,
                AtomEnum::STRING,
                0,
                max_length,
            )?
            .reply()?;
        if property.format == 8 && !property.value.is_empty() {
            Ok(Some(Self::new_from_data(&property.value)))
        } else {
            Ok(None)
        }
    }

    /// Construct a new X11 resource database from raw data.
    ///
    /// This function parses data like `Some.Entry: Value\n#include "some_file"\n` and returns the
    /// resulting resource database. Parsing cannot fail since unparsable lines are simply ignored.
    ///
    /// See [`Self::new_from_data_with_base_directory`] for a version that allows to provide a path that
    /// is used for resolving relative `#include` statements.
    pub fn new_from_data(data: &[u8]) -> Self {
        let mut entries = Vec::new();
        parse_data_with_base_directory(&mut entries, data, Path::new("."), 0);
        Self { entries }
    }

    /// Construct a new X11 resource database from raw data.
    ///
    /// This function parses data like `Some.Entry: Value\n#include "some_file"\n` and returns the
    /// resulting resource database. Parsing cannot fail since unparsable lines are simply ignored.
    ///
    /// When a relative `#include` statement is encountered, the file to include is searched
    /// relative to the given `base_path`.
    pub fn new_from_data_with_base_directory(data: &[u8], base_path: impl AsRef<Path>) -> Self {
        fn helper(data: &[u8], base_path: &Path) -> Database {
            let mut entries = Vec::new();
            parse_data_with_base_directory(&mut entries, data, base_path, 0);
            Database { entries }
        }
        helper(data, base_path.as_ref())
    }

    /// Get a value from the resource database as a byte slice.
    ///
    /// The given values describe a query to the resource database. `resource_class` can be an
    /// empty string, but otherwise must contain the same number of components as `resource_name`.
    /// Both strings may only contain alphanumeric characters or '-', '_', and '.'.
    ///
    /// For example, this is how Xterm could query one of its settings if it where written in Rust
    /// (see `man xterm`):
    /// ```
    /// use x11rb::resource_manager::Database;
    /// fn get_pointer_shape(db: &Database) -> &[u8] {
    ///     db.get_bytes("XTerm.vt100.pointerShape", "XTerm.VT100.Cursor").unwrap_or(b"xterm")
    /// }
    /// ```
    pub fn get_bytes(&self, resource_name: &str, resource_class: &str) -> Option<&[u8]> {
        matcher::match_entry(&self.entries, resource_name, resource_class)
    }

    /// Get a value from the resource database as a byte slice.
    ///
    /// The given values describe a query to the resource database. `resource_class` can be an
    /// empty string, but otherwise must contain the same number of components as `resource_name`.
    /// Both strings may only contain alphanumeric characters or '-', '_', and '.'.
    ///
    /// If an entry is found that is not a valid utf8 `str`, `None` is returned.
    ///
    /// For example, this is how Xterm could query one of its settings if it where written in Rust
    /// (see `man xterm`):
    /// ```
    /// use x11rb::resource_manager::Database;
    /// fn get_pointer_shape(db: &Database) -> &str {
    ///     db.get_string("XTerm.vt100.pointerShape", "XTerm.VT100.Cursor").unwrap_or("xterm")
    /// }
    /// ```
    pub fn get_string(&self, resource_name: &str, resource_class: &str) -> Option<&str> {
        std::str::from_utf8(self.get_bytes(resource_name, resource_class)?).ok()
    }

    /// Get a value from the resource database as a byte slice.
    ///
    /// The given values describe a query to the resource database. `resource_class` can be an
    /// empty string, but otherwise must contain the same number of components as `resource_name`.
    /// Both strings may only contain alphanumeric characters or '-', '_', and '.'.
    ///
    /// This function interprets "true", "on", "yes" as true-ish and "false", "off", "no" als
    /// false-ish. Numbers are parsed and are true if they are not zero. Unknown values are mapped
    /// to `None`.
    ///
    /// For example, this is how Xterm could query one of its settings if it where written in Rust
    /// (see `man xterm`):
    /// ```
    /// use x11rb::resource_manager::Database;
    /// fn get_bell_is_urgent(db: &Database) -> bool {
    ///     db.get_bool("XTerm.vt100.bellIsUrgent", "XTerm.VT100.BellIsUrgent").unwrap_or(false)
    /// }
    /// ```
    pub fn get_bool(&self, resource_name: &str, resource_class: &str) -> Option<bool> {
        to_bool(self.get_string(resource_name, resource_class)?)
    }

    /// Get a value from the resource database and parse it.
    ///
    /// The given values describe a query to the resource database. `resource_class` can be an
    /// empty string, but otherwise must contain the same number of components as `resource_name`.
    /// Both strings may only contain alphanumeric characters or '-', '_', and '.'.
    ///
    /// If no value is found, `Ok(None)` is returned. Otherwise, the result from
    /// [`FromStr::from_str]` is returned with `Ok(value)` replaced with `Ok(Some(value))`.
    ///
    /// For example, this is how Xterm could query one of its settings if it where written in Rust
    /// (see `man xterm`):
    /// ```
    /// use x11rb::resource_manager::Database;
    /// fn get_print_attributes(db: &Database) -> u8 {
    ///     db.get_value("XTerm.vt100.printAttributes", "XTerm.VT100.PrintAttributes")
    ///             .ok().flatten().unwrap_or(1)
    /// }
    /// ```
    pub fn get_value<T>(
        &self,
        resource_name: &str,
        resource_class: &str,
    ) -> Result<Option<T>, T::Err>
    where
        T: FromStr,
    {
        self.get_string(resource_name, resource_class)
            .map(T::from_str)
            .transpose()
    }
}

/// Parse the given data as a resource database.
///
/// The parsed entries are appended to `result`. `#include`s are resolved relative to the given
/// `base_path`. `depth` is the number of includes that we are already handling. This value is used
/// to prevent endless loops when a file (directly or indirectly) includes itself.
fn parse_data_with_base_directory(
    result: &mut Vec<Entry>,
    data: &[u8],
    base_path: &Path,
    depth: u8,
) {
    if depth > MAX_INCLUSION_DEPTH {
        return;
    }
    parser::parse_database(data, result, |path, entries| {
        // Construct the name of the file to include
        if let Ok(path) = std::str::from_utf8(path) {
            let mut path_buf = PathBuf::from(base_path);
            path_buf.push(path);

            // Read the file contents
            if let Ok(new_data) = std::fs::read(&path_buf) {
                // Parse the file contents with the new base path
                let new_base = path_buf.parent().unwrap_or(base_path);
                parse_data_with_base_directory(entries, &new_data, new_base, depth + 1);
            }
        }
    });
}

/// Parse a value to a boolean, returning `None` if this is not possible.
fn to_bool(data: &str) -> Option<bool> {
    if let Ok(num) = i64::from_str(data) {
        return Some(num != 0);
    }
    match data.to_lowercase().as_bytes() {
        b"true" => Some(true),
        b"on" => Some(true),
        b"yes" => Some(true),
        b"false" => Some(false),
        b"off" => Some(false),
        b"no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::{to_bool, Database};

    #[test]
    fn test_bool_true() {
        let data = ["1", "10", "true", "TRUE", "on", "ON", "yes", "YES"];
        for input in &data {
            assert_eq!(Some(true), to_bool(input));
        }
    }

    #[test]
    fn test_bool_false() {
        let data = ["0", "false", "FALSE", "off", "OFF", "no", "NO"];
        for input in &data {
            assert_eq!(Some(false), to_bool(input));
        }
    }

    #[test]
    fn test_bool_none() {
        let data = ["", "abc"];
        for input in &data {
            assert_eq!(None, to_bool(input));
        }
    }

    #[test]
    fn test_parse_i32_fail() {
        let db = Database::new_from_data(b"a:");
        assert_eq!(db.get_string("a", "a"), Some(""));
        assert!(db.get_value::<i32>("a", "a").is_err());
    }

    #[test]
    fn test_parse_i32_success() {
        let data = [
            (&b"a: 0"[..], 0),
            (b"a: 1", 1),
            (b"a: -1", -1),
            (b"a: 100", 100),
        ];
        for (input, expected) in data.iter() {
            let db = Database::new_from_data(input);
            let result = db.get_value::<i32>("a", "a");
            assert_eq!(result.unwrap().unwrap(), *expected);
        }
    }
}
