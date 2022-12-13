//! Utility functions for X11 things.
//!
//! The most important definitions in this module are the [`TryParse`], [`TryParseFd`] and
//! [`Serialize`] traits. These traits are used internally for parsing incoming data and producing
//! outgoing data when talking with the X11 server.

use std::convert::TryInto;

use crate::errors::ParseError;
use crate::protocol::{request_name, ErrorKind};
use crate::utils::RawFdContainer;

/// Representation of an X11 error packet that was sent by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X11Error {
    /// The kind of error that occurred.
    pub error_kind: ErrorKind,
    /// The kind of error that occurred as it appears "on the wire".
    pub error_code: u8,
    /// The sequence number of the request that caused this error.
    pub sequence: u16,
    /// The value in the request that caused the error.
    pub bad_value: u32,
    /// The minor opcode of the request that caused this error.
    pub minor_opcode: u16,
    /// The major opcode of the request that caused this error.
    pub major_opcode: u8,
    /// Name of the extension that caused this error, if known.
    pub extension_name: Option<String>,
    /// Name of the request that caused this error, if known.
    pub request_name: Option<&'static str>,
}

impl X11Error {
    /// Parse an X11 error.
    pub fn try_parse(
        data: &[u8],
        ext_info_provider: &dyn ExtInfoProvider,
    ) -> Result<Self, ParseError> {
        let (response_type, remaining) = u8::try_parse(data)?;
        let (error_code, remaining) = u8::try_parse(remaining)?;
        let (sequence, remaining) = u16::try_parse(remaining)?;
        let (bad_value, remaining) = u32::try_parse(remaining)?;
        let (minor_opcode, remaining) = u16::try_parse(remaining)?;
        let (major_opcode, _) = u8::try_parse(remaining)?;
        if response_type != 0 {
            Err(ParseError::InvalidValue)
        } else {
            let error_kind = ErrorKind::from_wire_error_code(error_code, ext_info_provider);
            let extension_name = ext_info_provider
                .get_from_major_opcode(major_opcode)
                .map(|(name, _)| name.to_string());
            let request_name = request_name(extension_name.as_deref(), major_opcode, minor_opcode);
            Ok(X11Error {
                error_kind,
                error_code,
                sequence,
                bad_value,
                minor_opcode,
                major_opcode,
                extension_name,
                request_name,
            })
        }
    }
}

impl From<&X11Error> for [u8; 32] {
    fn from(input: &X11Error) -> Self {
        let sequence_bytes = input.sequence.serialize();
        let bad_value_bytes = input.bad_value.serialize();
        let minor_opcode_bytes = input.minor_opcode.serialize();
        [
            0,
            input.error_code,
            sequence_bytes[0],
            sequence_bytes[1],
            bad_value_bytes[0],
            bad_value_bytes[1],
            bad_value_bytes[2],
            bad_value_bytes[3],
            minor_opcode_bytes[0],
            minor_opcode_bytes[1],
            input.major_opcode,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    }
}
impl From<X11Error> for [u8; 32] {
    fn from(input: X11Error) -> Self {
        Self::from(&input)
    }
}

/// Information about a X11 extension.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ExtensionInformation {
    /// Major opcode used in request
    pub major_opcode: u8,
    /// Lowest event number used by the extension.
    pub first_event: u8,
    /// Lowest error number used by the extension.
    pub first_error: u8,
}

/// Trait to provide information about extensions.
pub trait ExtInfoProvider {
    /// Returns the information of the extension that whose
    /// opcode is `major_opcode`.
    fn get_from_major_opcode(&self, major_opcode: u8) -> Option<(&str, ExtensionInformation)>;

    /// Returns the information of the extension that whose
    /// event number range includes `event_number`.
    fn get_from_event_code(&self, event_code: u8) -> Option<(&str, ExtensionInformation)>;

    /// Returns the information of the extension that whose
    /// error number range includes `error_number`.
    fn get_from_error_code(&self, error_code: u8) -> Option<(&str, ExtensionInformation)>;
}

/// A type implementing this trait can be parsed from some raw bytes.
pub trait TryParse: Sized {
    /// Try to parse the given values into an instance of this type.
    ///
    /// If parsing is successful, an instance of the type and a slice for the remaining data should
    /// be returned. Otherwise, an error is returned.
    fn try_parse(value: &[u8]) -> Result<(Self, &[u8]), ParseError>;
}

/// A type implementing this trait can be parsed from some raw bytes and a list of fds.
pub trait TryParseFd: Sized {
    /// Try to parse the given values into an instance of this type.
    ///
    /// File descriptors are consumed by removing them from the beginning of the given `fds` `Vec`.
    /// If a file descriptor is expected, but missing, a `ParseError` should be returned. If more file
    /// descriptors are provided than expected, this is not an error and the remaining descriptors
    /// should be left in the `Vec`.
    ///
    /// If parsing is successful, an instance of the type and a slice for the remaining data should
    /// be returned. Otherwise, an error is returned.
    fn try_parse_fd<'a>(
        value: &'a [u8],
        fds: &mut Vec<RawFdContainer>,
    ) -> Result<(Self, &'a [u8]), ParseError>;
}

impl<T: TryParse> TryParseFd for T {
    fn try_parse_fd<'a>(
        value: &'a [u8],
        _: &mut Vec<RawFdContainer>,
    ) -> Result<(Self, &'a [u8]), ParseError> {
        T::try_parse(value)
    }
}

/// A representation of the header of a request.
#[derive(Debug, Clone, Copy)]
pub struct RequestHeader {
    /// The major opcode of the request.
    pub major_opcode: u8,
    /// The minor opcode of the request (which, for some requests, may not be an
    /// opcode at all).
    pub minor_opcode: u8,
    /// The remaining length of the request, measured in 4 bytes units. Unlike the wire format,
    /// this does *not* include the header itself, which is 1 unit (or 2 if BigRequests is
    /// enabled and the length in the first unit is zero). If the BigRequests extension is
    /// enabled this can be greater than u16::max_value - 1.
    pub remaining_length: u32,
}

/// Has the BigRequests extension been enabled?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigRequests {
    /// The BigRequests extension has been enabled.
    Enabled,
    /// The BigRequests extension has not been enabled.
    NotEnabled,
}

/// Parse the given input for a RequestHeader and the remaining input.
pub fn parse_request_header(
    input: &[u8],
    big_requests_enabled: BigRequests,
) -> Result<(RequestHeader, &[u8]), ParseError> {
    let (major_opcode, remaining) = u8::try_parse(input)?;
    let (minor_opcode, remaining) = u8::try_parse(remaining)?;
    let (length, remaining) = u16::try_parse(remaining)?;
    let (remaining_length, finally_remaining) = if length == 0 {
        if big_requests_enabled == BigRequests::NotEnabled {
            return Err(ParseError::InvalidValue);
        }

        let (length, remaining) = u32::try_parse(remaining)?;
        if length < 2 {
            return Err(ParseError::InvalidValue);
        }
        // Adjust length for the size of this header (two 4 byte units).
        (length - 2, remaining)
    } else {
        // Adjust length for the size of this header (one 4 byte unit).
        (u32::from(length) - 1, remaining)
    };
    Ok((
        RequestHeader {
            major_opcode,
            minor_opcode,
            remaining_length,
        },
        finally_remaining,
    ))
}

/// A type implementing this trait is an X11 request.
pub trait Request {
    /// The kind of reply that this request generates.
    type Reply: Into<crate::protocol::Reply> + TryParseFd;

    /// Parse a reply to this request.
    ///
    /// The default implementation of this function uses `Self::Reply::try_parse_fd`. There should
    /// not be a reason why you need different behaviour.
    fn parse_reply<'a>(
        bytes: &'a [u8],
        fds: &mut Vec<RawFdContainer>,
    ) -> Result<(crate::protocol::Reply, &'a [u8]), ParseError> {
        let (reply, remaining) = Self::Reply::try_parse_fd(bytes, fds)?;
        Ok((reply.into(), remaining))
    }
}

/// A type alias for reply parsers (matches the signature of TryParseFd).
pub type ReplyParsingFunction =
    for<'a> fn(
        &'a [u8],
        &mut Vec<RawFdContainer>,
    ) -> Result<(crate::protocol::Reply, &'a [u8]), ParseError>;

/// A type implementing this trait can be serialized into X11 raw bytes.
pub trait Serialize {
    /// The value returned by `serialize`.
    ///
    /// This should be `Vec<u8>` in most cases. However, arrays like `[u8; 4]` should also be
    /// allowed and thus this is an associated type.
    ///
    /// If generic associated types were available, implementing `AsRef<[u8]>` would be required.
    type Bytes;

    /// Serialize this value into X11 raw bytes.
    fn serialize(&self) -> Self::Bytes;

    /// Serialize this value into X11 raw bytes, appending the result into `bytes`.
    ///
    /// When calling this method, the given vector must satisfy `assert_eq!(bytes.len() % 4, 0);`.
    /// In words: Its length must be a multiple of four.
    fn serialize_into(&self, bytes: &mut Vec<u8>);
}

// Now implement TryParse and Serialize for some primitive data types that we need.

macro_rules! implement_try_parse {
    ($t:ty) => {
        impl TryParse for $t {
            fn try_parse(value: &[u8]) -> Result<(Self, &[u8]), ParseError> {
                let len = std::mem::size_of::<$t>();
                let bytes = value
                    .get(..len)
                    .ok_or(ParseError::InsufficientData)?
                    .try_into() // TryInto<[u8; len]>
                    .unwrap();
                Ok((<$t>::from_ne_bytes(bytes), &value[len..]))
            }
        }
    };
}

macro_rules! implement_serialize {
    ($t:ty: $size:expr) => {
        impl Serialize for $t {
            type Bytes = [u8; $size];
            fn serialize(&self) -> Self::Bytes {
                self.to_ne_bytes()
            }
            fn serialize_into(&self, bytes: &mut Vec<u8>) {
                bytes.extend_from_slice(&self.to_ne_bytes());
            }
        }
    };
}

macro_rules! forward_float {
    ($from:ty: $to:ty) => {
        impl TryParse for $from {
            fn try_parse(value: &[u8]) -> Result<(Self, &[u8]), ParseError> {
                let (data, remaining) = <$to>::try_parse(value)?;
                Ok((<$from>::from_bits(data), remaining))
            }
        }
        impl Serialize for $from {
            type Bytes = <$to as Serialize>::Bytes;
            fn serialize(&self) -> Self::Bytes {
                self.to_bits().serialize()
            }
            fn serialize_into(&self, bytes: &mut Vec<u8>) {
                self.to_bits().serialize_into(bytes);
            }
        }
    };
}

implement_try_parse!(u8);
implement_try_parse!(i8);
implement_try_parse!(u16);
implement_try_parse!(i16);
implement_try_parse!(u32);
implement_try_parse!(i32);
implement_try_parse!(u64);
implement_try_parse!(i64);

implement_serialize!(u8: 1);
implement_serialize!(i8: 1);
implement_serialize!(u16: 2);
implement_serialize!(i16: 2);
implement_serialize!(u32: 4);
implement_serialize!(i32: 4);
implement_serialize!(u64: 8);
implement_serialize!(i64: 8);

forward_float!(f32: u32);
forward_float!(f64: u64);

impl TryParse for bool {
    fn try_parse(value: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        let (data, remaining) = u8::try_parse(value)?;
        Ok((data != 0, remaining))
    }
}

impl Serialize for bool {
    type Bytes = [u8; 1];
    fn serialize(&self) -> Self::Bytes {
        [u8::from(*self)]
    }
    fn serialize_into(&self, bytes: &mut Vec<u8>) {
        bytes.push(u8::from(*self));
    }
}

// Tuple handling

macro_rules! tuple_try_parse {
    ($($name:ident)*) => {
        impl<$($name,)*> TryParse for ($($name,)*)
        where $($name: TryParse,)*
        {
            #[allow(non_snake_case)]
            fn try_parse(remaining: &[u8]) -> Result<(($($name,)*), &[u8]), ParseError> {
                $(let ($name, remaining) = $name::try_parse(remaining)?;)*
                Ok((($($name,)*), remaining))
            }
        }
    }
}

macro_rules! tuple_serialize {
    ($($name:ident:$idx:tt)*) => {
        impl<$($name,)*> Serialize for ($($name,)*)
        where $($name: Serialize,)*
        {
            type Bytes = Vec<u8>;
            fn serialize(&self) -> Self::Bytes {
                let mut result = Vec::new();
                self.serialize_into(&mut result);
                result
            }
            fn serialize_into(&self, bytes: &mut Vec<u8>) {
                $(self.$idx.serialize_into(bytes);)*
            }
        }
    }
}

macro_rules! tuple_impls {
    ($($name:ident:$idx:tt)*) => {
        tuple_try_parse!($($name)*);
        tuple_serialize!($($name:$idx)*);
    }
}

// We can optimise serialisation of empty tuples or one-element-tuples with different Bytes type
impl Serialize for () {
    type Bytes = [u8; 0];
    fn serialize(&self) -> Self::Bytes {
        []
    }
    fn serialize_into(&self, _bytes: &mut Vec<u8>) {}
}

impl<T: Serialize> Serialize for (T,) {
    type Bytes = T::Bytes;
    fn serialize(&self) -> Self::Bytes {
        self.0.serialize()
    }
    fn serialize_into(&self, bytes: &mut Vec<u8>) {
        self.0.serialize_into(bytes)
    }
}

tuple_try_parse!();
tuple_try_parse!(A);
tuple_impls!(A:0 B:1);
tuple_impls!(A:0 B:1 C:2);
tuple_impls!(A:0 B:1 C:2 D:3);
tuple_impls!(A:0 B:1 C:2 D:3 E:4);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6 H:7);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6 H:7 I:8);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6 H:7 I:8 J:9);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6 H:7 I:8 J:9 K:10);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6 H:7 I:8 J:9 K:10 L:11);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6 H:7 I:8 J:9 K:10 L:11 M:12);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6 H:7 I:8 J:9 K:10 L:11 M:12 N:13);
tuple_impls!(A:0 B:1 C:2 D:3 E:4 F:5 G:6 H:7 I:8 J:9 K:10 L:11 M:12 N:13 O:14);

/// Parse a list of objects from the given data.
///
/// This function parses a list of objects where the length of the list was specified externally.
/// The wire format for `list_length` instances of `T` will be read from the given data.
pub fn parse_list<T>(data: &[u8], list_length: usize) -> Result<(Vec<T>, &[u8]), ParseError>
where
    T: TryParse,
{
    let mut remaining = data;
    let mut result = Vec::with_capacity(list_length);
    for _ in 0..list_length {
        let (entry, new_remaining) = T::try_parse(remaining)?;
        result.push(entry);
        remaining = new_remaining;
    }
    Ok((result, remaining))
}

/// Parse a list of `u8` from the given data.
pub fn parse_u8_list(data: &[u8], list_length: usize) -> Result<(&[u8], &[u8]), ParseError> {
    if data.len() < list_length {
        Err(ParseError::InsufficientData)
    } else {
        Ok(data.split_at(list_length))
    }
}

impl<T: Serialize> Serialize for [T] {
    type Bytes = Vec<u8>;
    fn serialize(&self) -> Self::Bytes {
        let mut result = Vec::new();
        self.serialize_into(&mut result);
        result
    }
    fn serialize_into(&self, bytes: &mut Vec<u8>) {
        for item in self {
            item.serialize_into(bytes);
        }
    }
}

// This macro is used by the generated code to implement `std::ops::BitOr` and
// `std::ops::BitOrAssign`.
macro_rules! bitmask_binop {
    ($t:ty, $u:ty) => {
        impl std::ops::BitOr for $t {
            type Output = $t;
            fn bitor(self, other: Self) -> Self::Output {
                Self::from(<$u>::from(self) | <$u>::from(other))
            }
        }
        impl std::ops::BitOr<$u> for $t {
            type Output = $t;
            fn bitor(self, other: $u) -> Self::Output {
                self | Self::from(other)
            }
        }
        impl std::ops::BitOr<$t> for $u {
            type Output = $t;
            fn bitor(self, other: $t) -> Self::Output {
                <$t>::from(self) | other
            }
        }
        impl std::ops::BitOrAssign<$t> for $u {
            fn bitor_assign(&mut self, other: $t) {
                *self |= Self::from(other)
            }
        }
        impl std::ops::BitOrAssign<$u> for $t {
            fn bitor_assign(&mut self, other: $u) {
                *self = *self | Self::from(other)
            }
        }
    };
}

/// Wrapper around TryInto that produces a ParseError.
///
/// This trait shortens `x.try_into().or(Err(ParseError::ConversionFailed))` to `x.try_to_usize()`.
pub(crate) trait TryIntoUSize: TryInto<usize> {
    /// Attempt the conversion
    fn try_to_usize(self) -> Result<usize, ParseError> {
        self.try_into().or(Err(ParseError::ConversionFailed))
    }
}

impl TryIntoUSize for u8 {}
impl TryIntoUSize for u16 {}
impl TryIntoUSize for u32 {}
impl TryIntoUSize for u64 {}
impl TryIntoUSize for i8 {}
impl TryIntoUSize for i16 {}
impl TryIntoUSize for i32 {}
impl TryIntoUSize for i64 {}

/// A helper macro for managing atoms
///
/// If we need to use multiple atoms, one would normally write code such as
/// ```
/// # use x11rb::protocol::xproto::{Atom, ConnectionExt, InternAtomReply};
/// # use x11rb::errors::{ConnectionError, ReplyError};
/// # use x11rb::cookie::Cookie;
/// #[allow(non_snake_case)]
/// pub struct AtomCollection {
///     pub _NET_WM_NAME: Atom,
///     pub _NET_WM_ICON: Atom,
///     pub ATOM_WITH_SPACES: Atom,
///     pub WHATEVER: Atom,
/// }
///
/// #[allow(non_snake_case)]
/// struct AtomCollectionCookie<'c, C: ConnectionExt> {
///     _NET_WM_NAME: Cookie<'c, C, InternAtomReply>,
///     _NET_WM_ICON: Cookie<'c, C, InternAtomReply>,
///     ATOM_WITH_SPACES: Cookie<'c, C, InternAtomReply>,
///     WHATEVER: Cookie<'c, C, InternAtomReply>,
/// }
///
/// impl AtomCollection {
///     pub fn new<C: ConnectionExt>(
///         conn: &C,
///     ) -> Result<AtomCollectionCookie<'_, C>, ConnectionError> {
///         Ok(AtomCollectionCookie {
///             _NET_WM_NAME: conn.intern_atom(false, b"_NET_WM_NAME")?,
///             _NET_WM_ICON: conn.intern_atom(false, b"_NET_WM_ICON")?,
///             ATOM_WITH_SPACES: conn.intern_atom(false, b"ATOM WITH SPACES")?,
///             WHATEVER: conn.intern_atom(false, b"WHATEVER")?,
///         })
///     }
/// }
///
/// impl<'c, C> AtomCollectionCookie<'c, C>
/// where
///     C: ConnectionExt,
/// {
///     pub fn reply(self) -> Result<AtomCollection, ReplyError> {
///         Ok(AtomCollection {
///             _NET_WM_NAME: self._NET_WM_NAME.reply()?.atom,
///             _NET_WM_ICON: self._NET_WM_ICON.reply()?.atom,
///             ATOM_WITH_SPACES: self.ATOM_WITH_SPACES.reply()?.atom,
///             WHATEVER: self.WHATEVER.reply()?.atom,
///         })
///     }
/// }
/// ```
/// This macro automatically produces this code with
/// ```
/// # use x11rb::atom_manager;
/// atom_manager! {
///     pub AtomCollection: AtomCollectionCookie {
///         _NET_WM_NAME,
///         _NET_WM_ICON,
///         ATOM_WITH_SPACES: b"ATOM WITH SPACES",
///         WHATEVER,
///     }
/// }
/// ```
#[macro_export]
macro_rules! atom_manager {
    {
        $vis:vis $struct_name:ident: $cookie_name:ident {
            $($field_name:ident$(: $atom_value:expr)?,)*
        }
    } => {
        // Cookie version
        #[allow(non_snake_case)]
        #[derive(Debug)]
        $vis struct $cookie_name<'a, C: $crate::protocol::xproto::ConnectionExt> {
            phantom: std::marker::PhantomData<&'a C>,
            $(
                $field_name: $crate::cookie::Cookie<'a, C, $crate::protocol::xproto::InternAtomReply>,
            )*
        }

        // Replies
        #[allow(non_snake_case)]
        #[derive(Debug, Clone, Copy)]
        $vis struct $struct_name {
            $(
                $vis $field_name: $crate::protocol::xproto::Atom,
            )*
        }

        impl $struct_name {
            $vis fn new<C: $crate::protocol::xproto::ConnectionExt>(
                _conn: &C,
            ) -> ::std::result::Result<$cookie_name<'_, C>, $crate::errors::ConnectionError> {
                Ok($cookie_name {
                    phantom: std::marker::PhantomData,
                    $(
                        $field_name: _conn.intern_atom(
                            false,
                            $crate::__atom_manager_atom_value!($field_name$(: $atom_value)?),
                        )?,
                    )*
                })
            }
        }

        impl<'a, C: $crate::protocol::xproto::ConnectionExt> $cookie_name<'a, C> {
            $vis fn reply(self) -> ::std::result::Result<$struct_name, $crate::errors::ReplyError> {
                Ok($struct_name {
                    $(
                        $field_name: self.$field_name.reply()?.atom,
                    )*
                })
            }
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __atom_manager_atom_value {
    ($field_name:ident) => {
        stringify!($field_name).as_bytes()
    };
    ($field_name:ident: $atom_value:expr) => {
        $atom_value
    };
}
