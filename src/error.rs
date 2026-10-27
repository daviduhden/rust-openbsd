// Copyright (c) 2026, David Uhden Collado <david@uhden.dev>
// Copyright (c) 2024-2026, Zack Newman <zack@philomathiclife.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Error type and `errno` integration.
//!
//! OpenBSD error numbers are represented directly rather than delegated to a
//! cross-platform crate. The known values are contiguous from 1 through
//! `EPROTO` (95), which is the invariant used by [`Errno::from_raw`]. Unknown
//! values, including zero, become [`Errno::Other`]. The native `__errno()`
//! pointer is thread-local; wrappers read it immediately after a failing call
//! so another native operation cannot overwrite the error first.

use core::{
    error::Error,
    ffi::c_int,
    fmt::{self, Display, Formatter},
    mem,
};

#[cfg(feature = "std")]
use std::io::Error as StdErr;

use crate::ffi;

/// An OpenBSD `errno` value.
///
/// The variants are the error numbers defined by OpenBSD's
/// [`sys/sys/errno.h`](https://github.com/openbsd/src/blob/master/sys/sys/errno.h),
/// which is what makes this type usable without pulling in a platform
/// definitions crate. Values that OpenBSD does not define are represented by
/// [`Errno::Other`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to match an error against `Other`; match on `_`
    /// instead.
    #[doc(hidden)]
    Other,
    /// Operation not permitted.
    EPERM,
    /// No such file or directory.
    ENOENT,
    /// No such process.
    ESRCH,
    /// Interrupted system call.
    EINTR,
    /// Input/output error.
    EIO,
    /// Device not configured.
    ENXIO,
    /// Argument list too long.
    E2BIG,
    /// Exec format error.
    ENOEXEC,
    /// Bad file descriptor.
    EBADF,
    /// No child processes.
    ECHILD,
    /// Resource deadlock avoided.
    EDEADLK,
    /// Cannot allocate memory.
    ENOMEM,
    /// Permission denied.
    EACCES,
    /// Bad address.
    EFAULT,
    /// Block device required.
    ENOTBLK,
    /// Device busy.
    EBUSY,
    /// File exists.
    EEXIST,
    /// Cross-device link.
    EXDEV,
    /// Operation not supported by device.
    ENODEV,
    /// Not a directory.
    ENOTDIR,
    /// Is a directory.
    EISDIR,
    /// Invalid argument.
    EINVAL,
    /// Too many open files in system.
    ENFILE,
    /// Too many open files.
    EMFILE,
    /// Inappropriate ioctl for device.
    ENOTTY,
    /// Text file busy.
    ETXTBSY,
    /// File too large.
    EFBIG,
    /// No space left on device.
    ENOSPC,
    /// Illegal seek.
    ESPIPE,
    /// Read-only file system.
    EROFS,
    /// Too many links.
    EMLINK,
    /// Broken pipe.
    EPIPE,
    /// Numerical argument out of domain.
    EDOM,
    /// Result too large.
    ERANGE,
    /// Operation would block.
    EWOULDBLOCK,
    /// Operation now in progress.
    EINPROGRESS,
    /// Operation already in progress.
    EALREADY,
    /// Socket operation on non-socket.
    ENOTSOCK,
    /// Destination address required.
    EDESTADDRREQ,
    /// Message too long.
    EMSGSIZE,
    /// Protocol wrong type for socket.
    EPROTOTYPE,
    /// Protocol not available.
    ENOPROTOOPT,
    /// Protocol not supported.
    EPROTONOSUPPORT,
    /// Socket type not supported.
    ESOCKTNOSUPPORT,
    /// Operation not supported.
    EOPNOTSUPP,
    /// Protocol family not supported.
    EPFNOSUPPORT,
    /// Address family not supported by protocol family.
    EAFNOSUPPORT,
    /// Address already in use.
    EADDRINUSE,
    /// Can't assign requested address.
    EADDRNOTAVAIL,
    /// Network is down.
    ENETDOWN,
    /// Network is unreachable.
    ENETUNREACH,
    /// Network dropped connection on reset.
    ENETRESET,
    /// Software caused connection abort.
    ECONNABORTED,
    /// Connection reset by peer.
    ECONNRESET,
    /// No buffer space available.
    ENOBUFS,
    /// Socket is already connected.
    EISCONN,
    /// Socket is not connected.
    ENOTCONN,
    /// Can't send after socket shutdown.
    ESHUTDOWN,
    /// Too many references: can't splice.
    ETOOMANYREFS,
    /// Operation timed out.
    ETIMEDOUT,
    /// Connection refused.
    ECONNREFUSED,
    /// Too many levels of symbolic links.
    ELOOP,
    /// File name too long.
    ENAMETOOLONG,
    /// Host is down.
    EHOSTDOWN,
    /// No route to host.
    EHOSTUNREACH,
    /// Directory not empty.
    ENOTEMPTY,
    /// Too many processes.
    EPROCLIM,
    /// Too many users.
    EUSERS,
    /// Disk quota exceeded.
    EDQUOT,
    /// Stale NFS file handle.
    ESTALE,
    /// Too many levels of remote in path.
    EREMOTE,
    /// RPC struct is bad.
    EBADRPC,
    /// RPC version wrong.
    ERPCMISMATCH,
    /// RPC program not available.
    EPROGUNAVAIL,
    /// Program version wrong.
    EPROGMISMATCH,
    /// Bad procedure for program.
    EPROCUNAVAIL,
    /// No locks available.
    ENOLCK,
    /// Function not implemented.
    ENOSYS,
    /// Inappropriate file type or format.
    EFTYPE,
    /// Authentication error.
    EAUTH,
    /// Need authenticator.
    ENEEDAUTH,
    /// IPsec processing failure.
    #[expect(clippy::doc_markdown, reason = "false positive")]
    EIPSEC,
    /// Attribute not found.
    ENOATTR,
    /// Illegal byte sequence.
    EILSEQ,
    /// No medium found.
    ENOMEDIUM,
    /// Wrong medium type.
    EMEDIUMTYPE,
    /// Value too large to be stored in data type.
    EOVERFLOW,
    /// Operation canceled.
    ECANCELED,
    /// Identifier removed.
    EIDRM,
    /// No message of desired type.
    ENOMSG,
    /// Not supported.
    ENOTSUP,
    /// Bad message.
    EBADMSG,
    /// State not recoverable.
    ENOTRECOVERABLE,
    /// Previous owner died.
    EOWNERDEAD,
    /// Protocol error.
    EPROTO,
}

impl Errno {
    /// Resource temporarily unavailable.
    ///
    /// OpenBSD defines `EAGAIN` and `EWOULDBLOCK` to be the same value.
    pub const EAGAIN: Self = Self::EWOULDBLOCK;

    /// The largest `Errno` value OpenBSD defines (`EPROTO`).
    pub const LAST: Self = Self::EPROTO;

    /// Returns the `Self` equivalent to the raw error `code`.
    ///
    /// Codes that OpenBSD does not define (including `0`) map to
    /// [`Errno::Other`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Errno;
    /// assert_eq!(Errno::from_raw(1), Errno::EPERM);
    /// assert_eq!(Errno::from_raw(0), Errno::Other);
    /// ```
    #[expect(unsafe_code, reason = "`Self` is `repr(i32)` and `code` is checked")]
    #[inline]
    #[must_use]
    pub const fn from_raw(code: i32) -> Self {
        // OpenBSD defines `1..=95` (`ELAST == EPROTO == 95`). Keep this
        // range aligned with `LAST`; `errno_boundaries` in `src/tests.rs`
        // checks the endpoint. A range pattern is used instead of a bounds
        // check so that the const function stays const-compatible.
        match code {
            ..=0 | 96.. => Self::Other,
            _ => {
                // SAFETY:
                // `Self` is `repr(i32)` with contiguous discriminants, and the
                // arm above guarantees `code` is a valid discriminant.
                unsafe { mem::transmute::<i32, Self>(code) }
            }
        }
    }

    /// Returns the raw error code `self` is equivalent to.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Errno;
    /// assert_eq!(Errno::EPERM.into_raw(), 1);
    /// ```
    #[expect(clippy::as_conversions, reason = "`Self` is `repr(i32)`")]
    #[inline]
    #[must_use]
    pub const fn into_raw(self) -> i32 {
        self as i32
    }

    /// Returns a pointer to the thread-local `errno` value.
    #[expect(unsafe_code, reason = "`errno` is a thread-local accessed through FFI")]
    #[inline]
    fn get_raw_err_ptr() -> *mut c_int {
        // SAFETY:
        // `errno` is a thread-local variable and `__errno` returns a valid, non-null pointer to
        // it for the calling thread.
        unsafe { ffi::__errno() }
    }

    /// Sets the thread-local `errno` value to `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Errno;
    /// Errno::ENOENT.set();
    /// ```
    #[expect(unsafe_code, reason = "`errno` is a thread-local accessed through FFI")]
    #[inline]
    pub fn set(self) {
        let ptr = Self::get_raw_err_ptr();
        debug_assert!(
            !ptr.is_null() && ptr.is_aligned(),
            "libc errno pointer was null or unaligned"
        );
        // SAFETY:
        // `__errno` returns a valid, aligned, non-null pointer to the calling thread's `errno`.
        unsafe { *ptr = self.into_raw() };
    }

    /// Returns the current raw `errno` value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Errno;
    /// Errno::EPERM.set();
    /// assert_eq!(Errno::last_raw(), Errno::EPERM.into_raw());
    /// ```
    #[expect(unsafe_code, reason = "`errno` is a thread-local accessed through FFI")]
    #[inline]
    #[must_use]
    pub fn last_raw() -> i32 {
        let ptr = Self::get_raw_err_ptr();
        debug_assert!(
            !ptr.is_null() && ptr.is_aligned(),
            "libc errno pointer was null or unaligned"
        );
        // SAFETY:
        // `__errno` returns a valid, aligned, non-null pointer to the calling thread's `errno`.
        unsafe { *ptr }
    }

    /// Returns the current `errno`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Errno;
    /// Errno::ENOENT.set();
    /// assert_eq!(Errno::last(), Errno::ENOENT);
    /// ```
    #[inline]
    #[must_use]
    pub fn last() -> Self {
        Self::from_raw(Self::last_raw())
    }

    /// Clears `errno`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Errno;
    /// Errno::clear();
    /// assert_eq!(Errno::last().into_raw(), 0);
    /// ```
    #[inline]
    pub fn clear() {
        Self::Other.set();
    }
}

impl From<Errno> for i32 {
    #[inline]
    fn from(value: Errno) -> Self {
        value.into_raw()
    }
}

impl From<i32> for Errno {
    #[inline]
    fn from(value: i32) -> Self {
        Self::from_raw(value)
    }
}

impl Error for Errno {}

impl Display for Errno {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "Input/output error",
            Self::ENXIO => "Device not configured",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file descriptor",
            Self::ECHILD => "No child processes",
            Self::EDEADLK => "Resource deadlock avoided",
            Self::ENOMEM => "Cannot allocate memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "Operation not supported by device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "Too many open files in system",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Inappropriate ioctl for device",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only file system",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Numerical argument out of domain",
            Self::ERANGE => "Result too large",
            Self::EWOULDBLOCK => "Operation would block",
            Self::EINPROGRESS => "Operation now in progress",
            Self::EALREADY => "Operation already in progress",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::EOPNOTSUPP => "Operation not supported",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol family",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Can't assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Network dropped connection on reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Socket is already connected",
            Self::ENOTCONN => "Socket is not connected",
            Self::ESHUTDOWN => "Can't send after socket shutdown",
            Self::ETOOMANYREFS => "Too many references: can't splice",
            Self::ETIMEDOUT => "Operation timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::ELOOP => "Too many levels of symbolic links",
            Self::ENAMETOOLONG => "File name too long",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::ENOTEMPTY => "Directory not empty",
            Self::EPROCLIM => "Too many processes",
            Self::EUSERS => "Too many users",
            Self::EDQUOT => "Disk quota exceeded",
            Self::ESTALE => "Stale NFS file handle",
            Self::EREMOTE => "Too many levels of remote in path",
            Self::EBADRPC => "RPC struct is bad",
            Self::ERPCMISMATCH => "RPC version wrong",
            Self::EPROGUNAVAIL => "RPC program not available",
            Self::EPROGMISMATCH => "Program version wrong",
            Self::EPROCUNAVAIL => "Bad procedure for program",
            Self::ENOLCK => "No locks available",
            Self::ENOSYS => "Function not implemented",
            Self::EFTYPE => "Inappropriate file type or format",
            Self::EAUTH => "Authentication error",
            Self::ENEEDAUTH => "Need authenticator",
            Self::EIPSEC => "IPsec processing failure",
            Self::ENOATTR => "Attribute not found",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ENOMEDIUM => "No medium found",
            Self::EMEDIUMTYPE => "Wrong medium type",
            Self::EOVERFLOW => "Value too large to be stored in data type",
            Self::ECANCELED => "Operation canceled",
            Self::EIDRM => "Identifier removed",
            Self::ENOMSG => "No message of desired type",
            Self::ENOTSUP => "Not supported",
            Self::EBADMSG => "Bad message",
            Self::ENOTRECOVERABLE => "State not recoverable",
            Self::EOWNERDEAD => "Previous owner died",
            Self::EPROTO => "Protocol error",
        })
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl From<Errno> for StdErr {
    #[inline]
    fn from(value: Errno) -> Self {
        Self::from_raw_os_error(value.into_raw())
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl TryFrom<StdErr> for Errno {
    type Error = StdErr;

    #[inline]
    fn try_from(value: StdErr) -> Result<Self, Self::Error> {
        value.raw_os_error().ok_or(value).map(Self::from_raw)
    }
}
