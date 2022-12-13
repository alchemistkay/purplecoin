//! This crate allows you to specify an offset for reads and writes, without changing the current
//! position in a file. This is similar to [`pread()` and `pwrite()`][pread] in C.
//!
//! The major advantages of this type of I/O are:
//!
//! * You don't need to seek before doing a random-access read or write, which is convenient.
//! * Reads don't modify the file at all, so don't require mutability.
//!
//! [pread]: http://man7.org/linux/man-pages/man2/pread.2.html
//!
//! The repository is at https://github.com/vasi/positioned-io
//!
//!
//! # Examples
//!
//! Read the fifth 512-byte sector of a file:
//!
//! ```no_run
//! # use std::io;
//! # use std::fs::File;
//! use positioned_io::ReadAt;
//!
//! # fn foo() -> io::Result<()> {
//! // Note that file does not need to be mut!
//! let file = try!(File::open("foo.data"));
//! let mut buf = vec![0; 512];
//! let bytes_read = try!(file.read_at(2048, &mut buf));
//! # Ok(())
//! # }
//! ```
//!
//! Write an integer to the middle of a file:
//!
//! ```no_run
//! # extern crate positioned_io;
//! # extern crate byteorder;
//! # use std::io;
//! # use std::fs::OpenOptions;
//! use positioned_io::WriteAt;
//! use byteorder::{ByteOrder, LittleEndian};
//!
//! # fn foo() -> io::Result<()> {
//! // Put the integer in a buffer.
//! let mut buf = vec![0; 4];
//! LittleEndian::write_u32(&mut buf, 1234);
//!
//! // Write it to the file.
//! let mut file = try!(OpenOptions::new().write(true).open("foo.data"));
//! try!(file.write_all_at(1 << 20, &buf));
//! # Ok(())
//! # }
//! # fn main() { foo().unwrap() }
//! ```
//!
//! Or, more simply:
//!
//! ```no_run
//! # extern crate positioned_io;
//! # extern crate byteorder;
//! # use std::io;
//! # use std::fs::OpenOptions;
//! # use byteorder::LittleEndian;
//! // Extend files with writing integers at offsets.
//! use positioned_io::WriteBytesExt;
//!
//! # fn foo() -> io::Result<()> {
//! let mut file = try!(OpenOptions::new().write(true).open("foo.data"));
//! try!(file.write_u32_at::<LittleEndian>(1 << 20, 1234));
//! # Ok(())
//! # }
//! # fn main() { foo().unwrap() }
//! ```
//!
//! Read from anything else that supports ReadAt, like a byte array:
//!
//! ```rust
//! # extern crate positioned_io;
//! # extern crate byteorder;
//! # use std::io;
//! # use byteorder::BigEndian;
//! use positioned_io::ReadBytesExt;
//!
//! # fn foo() -> io::Result<()> {
//! let buf = [0, 5, 254, 212, 0, 3];
//! let n = try!(buf.as_ref().read_i16_at::<BigEndian>(2));
//! assert_eq!(n, -300);
//! # Ok(())
//! # }
//! # fn main() { foo().unwrap() }
//! ```

mod byteorder;
pub use byteorder::{ReadBytesExt, WriteBytesExt};
pub use byteorder::byteio::{ByteIo, ReadInt, WriteInt, ReadIntAt, WriteIntAt};

mod cursor;
pub use cursor::{Cursor, SizeCursor};

mod slice;
pub use slice::Slice;

extern crate byteorder as extbyteorder;

use std::io::{Error, ErrorKind, Result};
use std::fs::File;

/// Trait for reading at an offset.
///
/// Implementations should be able to read bytes without changing any sort of read-position.
/// Self should not change at all. Buffering reads is unlikely to be useful, since each time
/// `read_at()` is called, the position may be completely different.
///
/// # Examples
///
/// Read the fifth 512-byte sector of a file:
///
/// ```no_run
/// # use std::io;
/// # use std::fs::File;
/// use positioned_io::ReadAt;
///
/// # fn foo() -> io::Result<()> {
/// let file = try!(File::open("foo.data"));
/// let mut buf = vec![0; 512];
/// let bytes_read = try!(file.read_at(2048, &mut buf));
/// # Ok(())
/// # }
/// ```
pub trait ReadAt {
    /// Read bytes from an offset in this source into a buffer, returning how many bytes were read.
    ///
    /// This function may yield fewer bytes than the size of `buf`, if it was interrupted or hit
    /// end-of-file.
    ///
    /// See [`Read::read()`](https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read).
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> Result<usize>;

    /// Read the exact number of bytes required to fill `buf`, from an offset.
    ///
    /// If only a lesser number of bytes can be read, will yield an error.
    fn read_exact_at(&self, mut pos: u64, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read_at(pos, buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    pos += n as u64;
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if !buf.is_empty() {
            Err(Error::new(ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
        } else {
            Ok(())
        }
    }
}

/// Trait for writing at an offset.
///
/// Implementations should be able to write bytes at an offset, without changing any sort of
/// write-position. Self should not change at all.
///
/// # Examples
///
/// ```no_run
/// # extern crate positioned_io;
/// # extern crate byteorder;
/// # use std::io;
/// # use std::fs::OpenOptions;
/// use positioned_io::WriteAt;
/// use byteorder::{ByteOrder, LittleEndian};
///
/// # fn foo() -> io::Result<()> {
/// // Put the integer in a buffer.
/// let mut buf = vec![0; 4];
/// LittleEndian::write_u32(&mut buf, 1234);
///
/// // Write it to the file.
/// let mut file = try!(OpenOptions::new().write(true).open("foo.data"));
/// try!(file.write_all_at(1 << 20, &buf));
/// # Ok(())
/// # }
/// # fn main() { foo().unwrap() }
/// ```
pub trait WriteAt {
    /// Write a buffer at an offset, returning the number of bytes written.
    ///
    /// This function may write fewer bytes than the size of `buf`, for example if it is
    /// interrupted.
    ///
    /// See [`Write::write()`](https://doc.rust-lang.org/std/io/trait.Write.html#tymethod.write).
    fn write_at(&mut self, pos: u64, buf: &[u8]) -> Result<usize>;

    /// Write a complete buffer at an offset.
    ///
    /// If only a lesser number of bytes can be written, will yield an error.
    fn write_all_at(&mut self, mut pos: u64, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write_at(pos, buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &tmp[n..];
                    pos += n as u64;
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Flush this writer, ensuring that any buffered data is written.
    ///
    /// This should rarely do anything, since buffering is not very useful for positioned writes.
    fn flush(&mut self) -> Result<()>;
}

/// Trait to get the size of an I/O object.
///
/// Implementing this for a ReadAt or WriteAt makes it easier for users to predict whether they
/// will read past end-of-file. However, it may not be possible to implement for certain readers
/// or writers that have unknown size.
///
/// # Examples
///
/// ```no_run
/// # use std::io;
/// # use std::fs::File;
/// use positioned_io::Size;
///
/// # fn foo() -> io::Result<()> {
/// let file = try!(File::open("foo.txt"));
/// let size = try!(file.size());
/// assert_eq!(size, Some(22));
///
/// // Special files probably don't have a size.
/// let file = try!(File::open("/dev/stdin"));
/// let size = try!(file.size());
/// assert_eq!(size, None);
/// # Ok(())
/// # }
/// ```
pub trait Size {
    /// Get the size of this object, in bytes.
    ///
    /// This function may return Ok(None) if the size is unknown, for example if a file is a pipe.
    ///
    /// If a positive value is returned, it should be the value such that reading at greater
    /// offsets always yields end-of-file.
    fn size(&self) -> Result<Option<u64>>;
}

impl Size for File {
    fn size(&self) -> Result<Option<u64>> {
        let md = try!(self.metadata());
        if md.is_file() {
            Ok(Some(md.len()))
        } else {
            Ok(None)
        }
    }
}

// Implementation for Unix files.
#[cfg(unix)]
mod unix;

// Implementation for Windows files.
#[cfg(windows)]
mod windows;

// Implementation for arrays, vectors.
mod array;
mod vec;
mod refs;

#[cfg(test)]
mod test;
