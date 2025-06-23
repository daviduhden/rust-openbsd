//! [![git]](https://git.philomathiclife.com/priv_sep/log.html)&ensp;[![crates-io]](https://crates.io/crates/priv_sep)&ensp;[![docs-rs]](crate)
//!
//! [git]: https://git.philomathiclife.com/git_badge.svg
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! `priv_sep` is a library that uses the system's libc to perform privilege separation and privilege reduction.
//!
//! ## `priv_sep` in action for OpenBSD
//!
//! ```no_run
//! use core::convert::Infallible;
//! # #[cfg(target_os = "openbsd")]
//! use priv_sep::{Permissions, PrivDropErr, Promise, Promises};
//! use std::{
//!     fs,
//!     io::Error,
//!     net::{Ipv6Addr, SocketAddrV6},
//! };
//! use tokio::net::TcpListener;
//! # #[cfg(not(target_os = "openbsd"))]
//! # fn main() {}
//! # #[cfg(target_os = "openbsd")]
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<Infallible, PrivDropErr<Error>> {
//!     /// Config file.
//!     const CONFIG: &str = "config";
//!     // Get the user ID and group ID for nobody from `passwd(5)`.
//!     // `chroot(2)` to `/path/chroot/` and `chdir(2)` to `/`.
//!     // `pledge(2)` `id`, `inet`, `rpath`, `stdio`, and `unveil`.
//!     // Bind to TCP `[::1]:443` as root.
//!     // `setresgid(2)` to the group ID associated with nobody.
//!     // `setresuid(2)` to the user ID associated with nobody.
//!     // Remove `id` from our `pledge(2)`d promises.
//!     let (listener, mut promises) = Promises::new_chroot_then_priv_drop_async(
//!         "nobody",
//!         "/path/chroot/",
//!         [Promise::Inet, Promise::Rpath, Promise::Unveil],
//!         false,
//!         async || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await,
//!     ).await?;
//!     // At this point, the process is running under nobody.
//!     // Only allow file system access to `config` and only allow read access to it.
//!     Permissions::READ.unveil(CONFIG)?;
//!     // Read `config`.
//!     // This will of course fail if the file does not exist or nobody does not
//!     // have read permissions.
//!     let config = fs::read(CONFIG)?;
//!     // Remove file system access.
//!     Permissions::NONE.unveil(CONFIG)?;
//!     // Remove `rpath` and `unveil` from our `pledge(2)`d promises
//!     // (i.e., only have `inet` and `stdio` abilities when we begin accepting TCP connections).
//!     promises.remove_promises_then_pledge([Promise::Rpath, Promise::Unveil])?;
//!     loop {
//!         // Handle TCP connections.
//!         if let Ok((_, ip)) = listener.accept().await {
//!             assert!(ip.is_ipv6());
//!         }
//!     }
//! }
//! ```
//!
//! ## `priv_sep` in action for Unix-like OSes
//!
//! ```no_run
//! use core::convert::Infallible;
//! use priv_sep::{UserInfo, PrivDropErr};
//! use std::{
//!     io::Error,
//!     net::{Ipv6Addr, SocketAddrV6},
//! };
//! use tokio::net::TcpListener;
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<Infallible, PrivDropErr<Error>> {
//!     // Get the user ID and group ID for nobody from `passwd(5)`.
//!     // `chroot(2)` to `/path/chroot/` and `chdir(2)` to `/`.
//!     // Bind to TCP `[::1]:443` as root.
//!     // `setresgid(2)` to the group ID associated with nobody.
//!     // `setresuid(2)` to the user ID associated with nobody.
//!     let listener = UserInfo::chroot_then_priv_drop_async("nobody", "/path/chroot/", false, async || {
//!         TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
//!     }).await?;
//!     // At this point, the process is running under nobody.
//!     loop {
//!         // Handle TCP connections.
//!         if let Ok((_, ip)) = listener.accept().await {
//!             assert!(ip.is_ipv6());
//!         }
//!     }
//! }
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::pub_use, reason = "don't want openbsd types in a module")]
extern crate alloc;
/// C FFI.
mod c;
/// OpenBSD
#[cfg(any(doc, target_os = "openbsd"))]
mod openbsd;
use alloc::ffi::{CString, NulError};
use c::{IdT, SUCCESS};
use core::{
    error::Error as CoreErr,
    ffi::{CStr, c_char, c_int},
    fmt::{self, Display, Formatter},
    mem::MaybeUninit,
    ptr,
};
#[cfg_attr(docsrs, doc(cfg(target_os = "openbsd")))]
#[cfg(any(doc, target_os = "openbsd"))]
pub use openbsd::{Permission, Permissions, Promise, Promises};
use std::{io::Error, os::unix::ffi::OsStrExt as _, path::Path};
/// [`uid_t`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/basedefs/sys_types.h.html).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Uid(pub IdT);
impl Uid {
    /// The root user ID (i.e., 0).
    pub const ROOT: Self = Self(0);
    /// Returns `true` iff `self` is [`Self::ROOT`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::Uid;
    /// assert!(Uid::ROOT.is_root());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_root(self) -> bool {
        self.0 == Self::ROOT.0
    }
    /// [`getuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getuid.html).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::Uid;
    /// assert_eq!(Uid::getuid(), 1000);
    /// ```
    #[inline]
    #[must_use]
    pub fn getuid() -> Self {
        Self(c::getuid())
    }
    /// [`geteuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/geteuid.html).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::Uid;
    /// assert_eq!(Uid::geteuid(), 1000);
    /// ```
    #[inline]
    #[must_use]
    pub fn geteuid() -> Self {
        Self(c::geteuid())
    }
    /// Calls [`setresuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresuid.html)
    /// passing `self` for the real, effective, and saved user IDs.
    ///
    /// # Errors
    ///
    /// Errors iff `setresuid` does.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::Uid;
    /// assert!(Uid(1000).setresuid().is_ok());
    /// ```
    #[inline]
    pub fn setresuid(self) -> Result<(), Error> {
        if c::setresuid(self.0, self.0, self.0) == SUCCESS {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    }
}
impl PartialEq<&Self> for Uid {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Uid> for &Uid {
    #[inline]
    fn eq(&self, other: &Uid) -> bool {
        **self == *other
    }
}
impl PartialEq<IdT> for Uid {
    #[inline]
    fn eq(&self, other: &IdT) -> bool {
        self.0 == *other
    }
}
impl From<Uid> for IdT {
    #[inline]
    fn from(value: Uid) -> Self {
        value.0
    }
}
impl From<IdT> for Uid {
    #[inline]
    fn from(value: IdT) -> Self {
        Self(value)
    }
}
/// [`gid_t`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/basedefs/sys_types.h.html).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gid(pub IdT);
impl Gid {
    /// [`getgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getgid.html).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::Gid;
    /// assert_eq!(Gid::getgid(), 1000);
    /// ```
    #[inline]
    #[must_use]
    pub fn getgid() -> Self {
        Self(c::getgid())
    }
    /// [`getegid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getegid.html).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::Gid;
    /// assert_eq!(Gid::getegid(), 1000);
    /// ```
    #[inline]
    #[must_use]
    pub fn getegid() -> Self {
        Self(c::getegid())
    }
    /// Calls [`setresgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresgid.html)
    /// passing `self` for the real, effective, and saved group IDs.
    ///
    /// # Errors
    ///
    /// Errors iff `setresgid` does.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::Gid;
    /// assert!(Gid(1000).setresgid().is_ok());
    /// ```
    #[inline]
    pub fn setresgid(self) -> Result<(), Error> {
        if c::setresgid(self.0, self.0, self.0) == SUCCESS {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    }
}
impl PartialEq<&Self> for Gid {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Gid> for &Gid {
    #[inline]
    fn eq(&self, other: &Gid) -> bool {
        **self == *other
    }
}
impl PartialEq<IdT> for Gid {
    #[inline]
    fn eq(&self, other: &IdT) -> bool {
        self.0 == *other
    }
}
impl From<Gid> for IdT {
    #[inline]
    fn from(value: Gid) -> Self {
        value.0
    }
}
impl From<IdT> for Gid {
    #[inline]
    fn from(value: IdT) -> Self {
        Self(value)
    }
}
/// Error when [`CString::new`] errors or an I/O error occurs due to a libc call.
#[derive(Debug)]
pub enum NulOrIoErr {
    /// Error returned from [`CString::new`].
    Nul(NulError),
    /// Generic I/O error returned from a libc call.
    Io(Error),
}
impl Display for NulOrIoErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Nul(ref err) => write!(f, "CString could not be created: {err}"),
            Self::Io(ref err) => write!(f, "libc I/O error: {err}"),
        }
    }
}
impl CoreErr for NulOrIoErr {}
impl From<NulError> for NulOrIoErr {
    #[inline]
    fn from(value: NulError) -> Self {
        Self::Nul(value)
    }
}
impl From<Error> for NulOrIoErr {
    #[inline]
    fn from(value: Error) -> Self {
        Self::Io(value)
    }
}
/// [`chroot(2)`](https://manned.org/chroot.2).
///
/// # Errors
///
/// Returns [`NulError`] iff [`CString::new`] does.
/// Returns [`Error`] iff `chroot(2)` errors.
///
/// # Examples
///
/// ```no_run
/// assert!(priv_sep::chroot("./").is_ok());
/// ```
#[expect(unsafe_code, reason = "chroot(2) takes a pointer")]
#[inline]
pub fn chroot<P: AsRef<Path>>(path: P) -> Result<(), NulOrIoErr> {
    CString::new(path.as_ref().as_os_str().as_bytes())
        .map_err(NulOrIoErr::Nul)
        .and_then(|c_path| {
            let ptr = c_path.as_ptr();
            // SAFETY:
            // `ptr` is valid and not null.
            if unsafe { c::chroot(ptr) } == SUCCESS {
                Ok(())
            } else {
                Err(NulOrIoErr::Io(Error::last_os_error()))
            }
        })
}
/// [`chdir`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/chdir.html).
///
/// This function MUST only be called by `chdir` and `chroot_then_chdir`.
#[expect(unsafe_code, reason = "chdir(2) takes a pointer")]
fn private_chdir(path: *const c_char) -> Result<(), Error> {
    // SAFETY:
    // `path` is valid and not null as can be seen in the only functions that call this function:
    // `chdir` and `chroot_then_chdir`.
    if unsafe { c::chdir(path) } == SUCCESS {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}
/// [`chdir`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/chdir.html).
///
/// # Errors
///
/// Returns [`NulError`] iff [`CString::new`] does.
/// Returns [`Error`] iff `chdir` errors.
///
/// # Examples
///
/// ```no_run
/// assert!(priv_sep::chdir("/").is_ok());
/// ```
#[inline]
pub fn chdir<P: AsRef<Path>>(path: P) -> Result<(), NulOrIoErr> {
    CString::new(path.as_ref().as_os_str().as_bytes())
        .map_err(NulOrIoErr::Nul)
        .and_then(|c_path| private_chdir(c_path.as_ptr()).map_err(NulOrIoErr::Io))
}
/// Calls [`chroot`] on `path` followed by a call to [`chdir`] on `"/"`.
///
/// # Errors
///
/// Errors iff `chroot` or `chdir` do.
///
/// # Examples
///
/// ```no_run
/// assert!(priv_sep::chroot_then_chdir("./").is_ok());
/// ```
#[inline]
pub fn chroot_then_chdir<P: AsRef<Path>>(path: P) -> Result<(), NulOrIoErr> {
    /// Root directory.
    const ROOT: *const c_char = c"/".as_ptr();
    chroot(path).and_then(|()| private_chdir(ROOT).map_err(NulOrIoErr::Io))
}
/// Error returned when dropping privileges.
#[derive(Debug)]
pub enum PrivDropErr<E> {
    /// Error when [`CString::new`] errors.
    Nul(NulError),
    /// Error when an I/O error occurs from a libc call.
    Io(Error),
    /// Error when there is no entry in the user database corresponding to the passed username.
    NoPasswdEntry,
    /// Error when [`UserInfo::is_root`].
    RootEntry,
    /// Error returned from the user-provided function that is invoked before calling [`UserInfo::setresid`].
    Other(E),
}
impl<E: Display> Display for PrivDropErr<E> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Nul(ref err) => write!(
                f,
                "CString could not be created from the username to drop privileges to: {err}"
            ),
            Self::Io(ref err) => write!(f, "libc I/O error when dropping privileges: {err}"),
            Self::NoPasswdEntry => f.write_str("no passwd(5) entry to drop privileges to"),
            Self::RootEntry => f.write_str(
                "setresuid(2) is not allowed to be called on uid 0 when dropping privileges",
            ),
            Self::Other(ref err) => write!(
                f,
                "error calling function before dropping privileges: {err}"
            ),
        }
    }
}
impl<E: CoreErr> CoreErr for PrivDropErr<E> {}
impl<E> From<NulError> for PrivDropErr<E> {
    #[inline]
    fn from(value: NulError) -> Self {
        Self::Nul(value)
    }
}
impl<E> From<Error> for PrivDropErr<E> {
    #[inline]
    fn from(value: Error) -> Self {
        Self::Io(value)
    }
}
impl<E> From<NulOrIoErr> for PrivDropErr<E> {
    #[inline]
    fn from(value: NulOrIoErr) -> Self {
        match value {
            NulOrIoErr::Nul(e) => Self::Nul(e),
            NulOrIoErr::Io(e) => Self::Io(e),
        }
    }
}
/// Error returned from [`UserInfo::setresid_if_valid`].
#[derive(Debug)]
pub enum SetresidErr {
    /// Error when an I/O error occurs from a libc call.
    Io(Error),
    /// Error when there is no entry in the user database corresponding to [`UserInfo::uid`].
    NoPasswdEntry,
    /// Error when the entry in the user database has a different gid than [`UserInfo::gid`].
    GidMismatch,
}
impl Display for SetresidErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Io(ref err) => write!(f, "libc I/O error when dropping privileges: {err}"),
            Self::NoPasswdEntry => f.write_str("no passwd(5) entry to drop privileges to"),
            Self::GidMismatch => f.write_str("gid in passwd(5) does match the expected gid"),
        }
    }
}
impl CoreErr for SetresidErr {}
impl From<Error> for SetresidErr {
    #[inline]
    fn from(value: Error) -> Self {
        Self::Io(value)
    }
}
/// Used by [`UserInfo::getpw_entry`].
trait PwEntry {
    /// Calling code must uphold the following safety invariants:
    /// * `buf` must be a valid, initialized, non-null pointer
    /// * `size` must be the length of `buf`
    /// * `result` must be a valid, initialized non-null pointer referencing a valid and initialized pointer that
    ///   is allowed to be null.
    ///
    /// Implementors MUST only _write_ to `pwd` and never read from it (i.e., `pwd` is allowed to be unitialized).
    #[expect(
        unsafe_code,
        reason = "getpwnam_r(3) and getpwuid_r(3) take in pointers"
    )]
    unsafe fn getpw(
        self,
        pwd: *mut c::Passwd,
        buf: *mut c_char,
        size: usize,
        result: *mut *mut c::Passwd,
    ) -> c_int;
}
impl PwEntry for Uid {
    #[expect(unsafe_code, reason = "getpwuid_r(3) take in pointers")]
    unsafe fn getpw(
        self,
        pwd: *mut c::Passwd,
        buf: *mut c_char,
        size: usize,
        result: *mut *mut c::Passwd,
    ) -> c_int {
        // SAFETY:
        // Calling code must uphold safety invariants.
        // `pwd` is never read from.
        unsafe { c::getpwuid_r(self.0, pwd, buf, size, result) }
    }
}
/// `newtype` around `CStr`.
#[derive(Clone, Copy)]
struct CStrWrapper<'a>(&'a CStr);
impl PwEntry for CStrWrapper<'_> {
    #[expect(unsafe_code, reason = "getpwnam_r(3) takes in pointers")]
    unsafe fn getpw(
        self,
        pwd: *mut c::Passwd,
        buf: *mut c_char,
        size: usize,
        result: *mut *mut c::Passwd,
    ) -> c_int {
        let ptr = self.0.as_ptr();
        // SAFETY:
        // Calling code must uphold safety invariants.
        // `ptr` is valid, initialized, and not null.
        // `pwd` is never read from.
        unsafe { c::getpwnam_r(ptr, pwd, buf, size, result) }
    }
}
/// User and group ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserInfo {
    /// The user ID.
    pub uid: Uid,
    /// The group ID.
    pub gid: Gid,
}
impl UserInfo {
    /// Returns `true` iff [`Uid::is_root`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::{Gid, Uid, UserInfo};
    /// assert!(UserInfo { uid: Uid::ROOT, gid: Gid(0), }.is_root());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_root(self) -> bool {
        self.uid.is_root()
    }
    /// [`getpwnam_r`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getpwnam_r.html).
    ///
    /// Uses `buffer` to write the user database entry into returning `None` iff there is no entry; otherwise
    /// returns `Self`.
    ///
    /// Note it is the caller's responsibility to ensure `buffer` is large enough; otherwise an [`Error`] will
    /// be returned.
    ///
    /// # Errors
    ///
    /// Returns [`NulError`] iff [`CString::new`] does.
    /// Returns [`Error`] iff `getpwnam_r` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::{Uid, UserInfo};
    /// assert!(UserInfo::with_buffer("root", [0; 128].as_mut_slice())?.map_or(false, |info| info.is_root()));
    /// # Ok::<_, priv_sep::NulOrIoErr>(())
    /// ```
    #[expect(unsafe_code, reason = "getpwnam_r(3) takes in pointers")]
    #[inline]
    pub fn with_buffer<T: Into<Vec<u8>>>(
        name: T,
        buffer: &mut [c_char],
    ) -> Result<Option<Self>, NulOrIoErr> {
        CString::new(name).map_err(NulOrIoErr::Nul).and_then(|n| {
            let ptr = n.as_ptr();
            let mut pwd = MaybeUninit::<c::Passwd>::uninit();
            let pwd_ptr = pwd.as_mut_ptr();
            let buf_ptr = buffer.as_mut_ptr();
            let len = buffer.len();
            let mut result = ptr::null_mut();
            let res_ptr = &mut result;
            // SAFETY:
            // `pwd_ptr` is only written to; thus the fact `pwd` is unitialized is fine.
            // `buf_ptr` is valid, initialized, and not null.
            // `len` is the length of `buf_ptr`.
            // `res_ptr` is valid, initialized, and not null.
            // `result` is valid, initialized, and allowed to be null.
            let code = unsafe { c::getpwnam_r(ptr, pwd_ptr, buf_ptr, len, res_ptr) };
            if code == SUCCESS {
                if result.is_null() {
                    Ok(None)
                } else {
                    // SAFETY:
                    // `c::getpwnam_r` writes to `pwd` iff `result` is not null.
                    Ok(Some(unsafe { pwd.assume_init() }.into_user_info()))
                }
            } else {
                Err(NulOrIoErr::Io(Error::from_raw_os_error(code)))
            }
        })
    }
    /// Helper for [`Self::new`] and [`Self::setresid_if_exists`].
    #[expect(
        unsafe_code,
        reason = "getpwnam_r(3) and getpwuid_r(3) take in pointers"
    )]
    fn getpw_entry<P: Copy + PwEntry>(u: P) -> Result<Option<Self>, Error> {
        /// Initial buffer size.
        const INIT_CAP: usize = 128;
        // `2 * (MAX_CAP - 1) <= isize::MAX` MUST be true.
        /// Maximum buffer size.
        const MAX_CAP: usize = 0x4000;
        /// [`ERANGE`](https://man.openbsd.org/errno#Result).
        const ERANGE: c_int = 34;
        let mut buffer = Vec::with_capacity(INIT_CAP);
        let mut cap = buffer.capacity();
        let mut pwd = MaybeUninit::<c::Passwd>::uninit();
        let mut result = ptr::null_mut();
        let mut pwd_ptr;
        let mut res_ptr;
        let mut code;
        let mut buf_ptr;
        loop {
            pwd_ptr = pwd.as_mut_ptr();
            res_ptr = &mut result;
            buf_ptr = buffer.as_mut_ptr();
            // SAFETY:
            // `pwd_ptr` is only written to; thus the fact `pwd` is unitialized is fine.
            // `buf_ptr` is valid, initialized, and not null.
            // `cap` is the length of `buf_ptr`.
            // `res_ptr` is valid, initialized, and not null.
            // `result` is valid, initialized, and allowed to be null.
            code = unsafe { u.getpw(pwd_ptr, buf_ptr, cap, res_ptr) };
            if code == SUCCESS {
                return Ok(if result.is_null() {
                    None
                } else {
                    // SAFETY:
                    // `CStrWrapper::getpw` writes to `pwd` iff `result` is not null.
                    Some(unsafe { pwd.assume_init() }.into_user_info())
                });
            } else if code == ERANGE {
                if cap >= MAX_CAP {
                    return Err(Error::from_raw_os_error(code));
                }
                // `cap < MAX_CAP` and
                // `2 * (MAX_CAP - 1) < isize::MAX`, so overflow is not possible.
                buffer.reserve(cap << 1);
                cap = buffer.capacity();
            } else {
                return Err(Error::from_raw_os_error(code));
            }
        }
    }
    /// Same as [`Self::with_buffer`] except repeated attempts are made with progressively larger buffers up to
    /// 16 KiB.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::with_buffer`] does for a 16 KiB buffer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::UserInfo;
    /// assert!(UserInfo::new("root")?.map_or(false, |info| info.is_root()));
    /// # Ok::<_, priv_sep::NulOrIoErr>(())
    /// ```
    #[inline]
    pub fn new<T: Into<Vec<u8>>>(name: T) -> Result<Option<Self>, NulOrIoErr> {
        CString::new(name)
            .map_err(NulOrIoErr::Nul)
            .and_then(|n| Self::getpw_entry(CStrWrapper(n.as_c_str())).map_err(NulOrIoErr::Io))
    }
    /// Calls [`Gid::setresgid`] and [`Uid::setresuid`].
    ///
    /// # Errors
    ///
    /// Errors iff `Gid::setresgid` or `Uid::setresuid` error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::UserInfo;
    /// if let Some(user) = UserInfo::new("nobody")? {
    ///     user.setresid()?;
    /// }
    /// # Ok::<_, priv_sep::NulOrIoErr>(())
    /// ```
    #[inline]
    pub fn setresid(self) -> Result<(), Error> {
        self.gid.setresgid().and_then(|()| self.uid.setresuid())
    }
    /// Same as [`Self::setresid`] except
    /// [`getpwuid_r`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getpwuid_r.html)
    /// is used to first confirm the existence of [`Self::uid`] and [`Self::gid`].
    ///
    /// Note this should rarely be used since most will rely on [`Self::new`], [`Self::with_buffer`],
    /// [`Self::priv_drop`], or [`Self::chroot_then_priv_drop`].
    ///
    /// Like [`Self::new`], this will fail if the buffer needed exceeds 16 KiB.
    ///
    /// # Errors
    ///
    /// Errors iff `getpwuid_r` errors for a 16 KiB buffer, [`Self::uid`] and [`Self::gid`] don't exist in the user
    /// database, [`Gid::setresgid`] errors, or [`Uid::setresuid`] errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::{Gid, Uid, UserInfo};
    /// UserInfo { uid: Uid(1000), gid: Gid(1000), }.setresid_if_valid()?;
    /// # Ok::<_, priv_sep::SetresidErr>(())
    /// ```
    #[inline]
    pub fn setresid_if_valid(self) -> Result<(), SetresidErr> {
        Self::getpw_entry(self.uid)
            .map_err(SetresidErr::Io)
            .and_then(|opt| {
                opt.ok_or(SetresidErr::NoPasswdEntry).and_then(|info| {
                    if info.gid == self.gid {
                        self.setresid().map_err(SetresidErr::Io)
                    } else {
                        Err(SetresidErr::GidMismatch)
                    }
                })
            })
    }
    /// Calls [`Self::new`], invokes `f`, then calls [`Self::setresid`].
    ///
    /// Dropping privileges is necessary when needing to perform certain actions as root before no longer needing
    /// such abilities; at which point, one calls
    /// [`setresgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresgid.html) and
    /// [`setresuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresuid.html)
    /// using a lesser privileged gid and uid.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::new`], `f`, or [`Self::setresid`] do or there is no entry in the user database
    /// corresponding to `name` or the entry has uid 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use priv_sep::{PrivDropErr, UserInfo};
    /// # use std::{io::Error, net::TcpListener};
    /// let listener = UserInfo::priv_drop("nobody", || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
    /// })?;
    /// # Ok::<_, PrivDropErr<Error>>(())
    /// ```
    #[inline]
    pub fn priv_drop<U: Into<Vec<u8>>, T, E, F: FnOnce() -> Result<T, E>>(
        name: U,
        f: F,
    ) -> Result<T, PrivDropErr<E>> {
        Self::new(name).map_err(PrivDropErr::from).and_then(|opt| {
            opt.ok_or_else(|| PrivDropErr::NoPasswdEntry)
                .and_then(|info| {
                    if info.is_root() {
                        Err(PrivDropErr::RootEntry)
                    } else {
                        f().map_err(PrivDropErr::Other)
                            .and_then(|res| info.setresid().map_err(PrivDropErr::Io).map(|()| res))
                    }
                })
        })
    }
    /// Same as [`Self::priv_drop`] except `f` is `async`.
    ///
    /// # Errors
    ///
    /// Read [`Self::priv_drop`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use priv_sep::UserInfo;
    /// # use tokio::net::TcpListener;
    /// let listener_fut = UserInfo::priv_drop_async("nobody", async || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
    /// });
    /// ```
    #[inline]
    pub async fn priv_drop_async<U: Into<Vec<u8>>, T, E, F: AsyncFnOnce() -> Result<T, E>>(
        name: U,
        f: F,
    ) -> Result<T, PrivDropErr<E>> {
        match Self::new(name) {
            Ok(opt) => match opt {
                None => Err(PrivDropErr::NoPasswdEntry),
                Some(info) => {
                    if info.is_root() {
                        Err(PrivDropErr::RootEntry)
                    } else {
                        f().await
                            .map_err(PrivDropErr::Other)
                            .and_then(|res| info.setresid().map_err(PrivDropErr::Io).map(|()| res))
                    }
                }
            },
            Err(err) => Err(PrivDropErr::from(err)),
        }
    }
    /// Same as [`Self::priv_drop`] except [`chroot_then_chdir`] is called before or after invoking `f` based on
    /// `chroot_after_f`.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::priv_drop`] or [`chroot_then_chdir`] do.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use priv_sep::{PrivDropErr, UserInfo};
    /// # use std::{io::Error, net::TcpListener};
    /// let listener = UserInfo::chroot_then_priv_drop("nobody", "./", false, || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
    /// })?;
    /// # Ok::<_, PrivDropErr<Error>>(())
    /// ```
    #[inline]
    pub fn chroot_then_priv_drop<
        U: Into<Vec<u8>>,
        P: AsRef<Path>,
        T,
        E,
        F: FnOnce() -> Result<T, E>,
    >(
        name: U,
        path: P,
        chroot_after_f: bool,
        f: F,
    ) -> Result<T, PrivDropErr<E>> {
        Self::new(name).map_err(PrivDropErr::from).and_then(|opt| {
            opt.ok_or_else(|| PrivDropErr::NoPasswdEntry)
                .and_then(|info| {
                    if info.is_root() {
                        Err(PrivDropErr::RootEntry)
                    } else if chroot_after_f {
                        f().map_err(PrivDropErr::Other).and_then(|res| {
                            chroot_then_chdir(path)
                                .map_err(PrivDropErr::from)
                                .map(|()| res)
                        })
                    } else {
                        chroot_then_chdir(path)
                            .map_err(PrivDropErr::from)
                            .and_then(|()| f().map_err(PrivDropErr::Other))
                    }
                    .and_then(|res| info.setresid().map_err(PrivDropErr::Io).map(|()| res))
                })
        })
    }
    /// Same as [`Self::chroot_then_priv_drop`] except `f` is `async`.
    ///
    /// # Errors
    ///
    /// Read [`Self::chroot_then_priv_drop`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use priv_sep::UserInfo;
    /// # use tokio::net::TcpListener;
    /// let listener_fut = UserInfo::chroot_then_priv_drop_async("nobody", "./", false, async || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
    /// });
    /// ```
    #[inline]
    pub async fn chroot_then_priv_drop_async<
        U: Into<Vec<u8>>,
        P: AsRef<Path>,
        T,
        E,
        F: AsyncFnOnce() -> Result<T, E>,
    >(
        name: U,
        path: P,
        chroot_after_f: bool,
        f: F,
    ) -> Result<T, PrivDropErr<E>> {
        match Self::new(name) {
            Ok(opt) => match opt {
                None => Err(PrivDropErr::NoPasswdEntry),
                Some(info) => if info.is_root() {
                    Err(PrivDropErr::RootEntry)
                } else if chroot_after_f {
                    f().await.map_err(PrivDropErr::Other).and_then(|res| {
                        chroot_then_chdir(path)
                            .map_err(PrivDropErr::from)
                            .map(|()| res)
                    })
                } else {
                    match chroot_then_chdir(path) {
                        Ok(()) => f().await.map_err(PrivDropErr::Other),
                        Err(err) => Err(PrivDropErr::from(err)),
                    }
                }
                .and_then(|res| info.setresid().map_err(PrivDropErr::Io).map(|()| res)),
            },
            Err(err) => Err(PrivDropErr::from(err)),
        }
    }
}
impl PartialEq<&Self> for UserInfo {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<UserInfo> for &UserInfo {
    #[inline]
    fn eq(&self, other: &UserInfo) -> bool {
        **self == *other
    }
}
#[cfg(test)]
mod tests {
    use super::{Gid, NulOrIoErr, PrivDropErr, SetresidErr, Uid, UserInfo};
    #[cfg(target_os = "openbsd")]
    use super::{Permissions, Promise, Promises};
    use core::net::{Ipv6Addr, SocketAddrV6};
    use std::{fs, io::Error, net::TcpListener};
    use tokio as _;
    const README: &str = "README.md";
    #[test]
    fn test_getuid() {
        _ = Uid::getuid();
    }
    #[test]
    fn test_geteuid() {
        _ = Uid::geteuid();
    }
    #[test]
    fn test_getgid() {
        _ = Gid::getgid();
    }
    #[test]
    fn test_getegid() {
        _ = Gid::getegid();
    }
    #[test]
    fn test_setresuid() -> Result<(), Error> {
        Uid::geteuid().setresuid()
    }
    #[test]
    fn test_setresgid() -> Result<(), Error> {
        Gid::getegid().setresgid()
    }
    #[test]
    fn test_user_info_new() -> Result<(), NulOrIoErr> {
        if let Some(user) = UserInfo::new("root")? {
            assert!(user.is_root());
        }
        Ok(())
    }
    #[test]
    fn test_user_info_with_buffer() -> Result<(), NulOrIoErr> {
        if let Some(user) = UserInfo::with_buffer("root", [0; 512].as_mut_slice())? {
            assert!(user.is_root());
        }
        Ok(())
    }
    #[test]
    fn test_user_info_setresid() -> Result<(), Error> {
        UserInfo {
            uid: Uid::geteuid(),
            gid: Gid::getegid(),
        }
        .setresid()
    }
    #[test]
    fn test_user_info_setresid_if_exists() -> Result<(), SetresidErr> {
        UserInfo {
            uid: Uid::geteuid(),
            gid: Gid::getegid(),
        }
        .setresid_if_valid()
    }
    #[test]
    fn test_user_info_setresid_if_exists_failure() {
        assert!(
            UserInfo {
                uid: Uid::geteuid(),
                gid: Gid(u32::MAX),
            }
            .setresid_if_valid()
            .map_or_else(|e| matches!(e, SetresidErr::GidMismatch), |_| false)
        );
    }
    #[test]
    #[ignore]
    fn test_priv_drop() -> Result<(), PrivDropErr<Error>> {
        if Uid::geteuid().is_root() {
            UserInfo::priv_drop("zack", || {
                TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
            })
            .map(|_| {
                assert!(
                    TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0)).is_err()
                );
            })
        } else {
            assert!(
                UserInfo::priv_drop("root", || Ok::<_, Error>(()))
                    .map_or_else(|e| matches!(e, PrivDropErr::RootEntry), |_| false)
            );
            Ok(())
        }
    }
    #[test]
    #[ignore]
    fn test_chroot_priv_drop() -> Result<(), PrivDropErr<Error>> {
        if Uid::geteuid().is_root() {
            UserInfo::chroot_then_priv_drop("zack", "./", false, || {
                TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
            })
            .and_then(|_| {
                fs::exists(README).map_err(PrivDropErr::Io).map(|exists| {
                    assert!(exists);
                    assert!(
                        TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0))
                            .is_err()
                    );
                })
            })
        } else {
            Ok(())
        }
    }
    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore]
    fn test_pledge_unveil() {
        const FILE_EXISTS: &str = "/home/zack/foo.txt";
        _ = fs::metadata(FILE_EXISTS)
            .expect(format!("{FILE_EXISTS} does not exist, so unit testing cannot occur").as_str());
        const FILE_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23";
        drop(fs::metadata(FILE_NOT_EXISTS).expect_err(
            format!("{FILE_NOT_EXISTS} exists, so unit testing cannot occur").as_str(),
        ));
        const DIR_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23/";
        drop(
            fs::metadata(DIR_NOT_EXISTS).expect_err(
                format!("{DIR_NOT_EXISTS} exists, so unit testing cannot occur").as_str(),
            ),
        );
        // This tests that a NULL `promise` does nothing.
        assert!(Promises::pledge_none().is_ok());
        print!("");
        assert!(Promises::ALL.pledge().is_ok());
        // This tests that duplicates are ignored as well as the implementation of PartialEq.
        let mut initial_promises = Promises::new([
            Promise::Stdio,
            Promise::Unveil,
            Promise::Rpath,
            Promise::Stdio,
        ]);
        assert!(initial_promises.len() == 3);
        assert!(
            initial_promises == Promises::new([Promise::Rpath, Promise::Stdio, Promise::Unveil])
        );
        // Test retain.
        assert!({
            let mut vals = Promises::new([
                Promise::Audio,
                Promise::Bpf,
                Promise::Chown,
                Promise::Cpath,
                Promise::Error,
                Promise::Exec,
            ]);
            vals.retain([Promise::Error, Promise::Chown]);
            vals.len() == 2 && vals.contains(Promise::Chown) && vals.contains(Promise::Error)
        });
        assert!(initial_promises.pledge().is_ok());
        // This tests unveil with no permissions.
        assert!(Permissions::NONE.unveil(FILE_EXISTS).is_ok());
        assert!(fs::metadata(FILE_EXISTS).is_err());
        // This tests unveil with read permissions,
        // and one can unveil more permissions (unlike pledge which can only remove promises).
        assert!(Permissions::READ.unveil(FILE_EXISTS).is_ok());
        assert!(fs::metadata(FILE_EXISTS).is_ok());
        // This tests that calls to unveil on missing files don't error.
        assert!(Permissions::NONE.unveil(FILE_NOT_EXISTS).is_ok());
        // This tests that calls to unveil on missing directories error.
        assert!(Permissions::NONE.unveil(DIR_NOT_EXISTS).is_err());
        // This tests that unveil can no longer be called.
        assert!(Permissions::unveil_no_more().is_ok());
        assert!(Permissions::NONE.unveil(FILE_EXISTS).is_err());
        assert!(fs::metadata(FILE_EXISTS).is_ok());
        // The below tests that Promises can only be removed and not added.
        initial_promises.remove_promises([Promise::Unveil]);
        assert_eq!(initial_promises.len(), 2);
        initial_promises.remove(Promise::Rpath);
        assert_eq!(initial_promises.len(), 1);
        initial_promises.remove(Promise::Rpath);
        assert_eq!(initial_promises.len(), 1);
        assert!(initial_promises.pledge().is_ok());
        print!("");
        assert!(Promises::new([Promise::Rpath]).pledge().is_err());
        // If the below is uncommented, the program should crash since the above
        // call to pledge no longer allows access to the file system.
        // drop(fs::metadata(FILE_EXISTS));
    }
    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore]
    fn test_pledge_priv_drop() -> Result<(), PrivDropErr<Error>> {
        if Uid::geteuid().is_root() {
            Promises::new_priv_drop(
                "zack",
                [Promise::Inet, Promise::Rpath, Promise::Unveil],
                false,
                || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
            )
            .and_then(|(_, mut promises)| {
                Permissions::READ
                    .unveil(README)
                    .map_err(PrivDropErr::from)
                    .and_then(|()| {
                        fs::exists(README)
                            .map_err(PrivDropErr::Io)
                            .and_then(|exists| {
                                Permissions::NONE
                                    .unveil(README)
                                    .map_err(PrivDropErr::from)
                                    .and_then(|()| {
                                        promises
                                            .remove_promises_then_pledge([
                                                Promise::Rpath,
                                                Promise::Unveil,
                                            ])
                                            .map_err(PrivDropErr::Io)
                                            .map(|()| {
                                                assert!(exists);
                                                assert!(
                                                    TcpListener::bind(SocketAddrV6::new(
                                                        Ipv6Addr::LOCALHOST,
                                                        80,
                                                        0,
                                                        0
                                                    ))
                                                    .is_err()
                                                );
                                            })
                                    })
                            })
                    })
            })
        } else {
            Ok(())
        }
    }
    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore]
    fn test_pledge_chroot_priv_drop() -> Result<(), PrivDropErr<Error>> {
        if Uid::geteuid().is_root() {
            Promises::new_chroot_then_priv_drop(
                "zack",
                "./",
                [Promise::Inet, Promise::Rpath, Promise::Unveil],
                false,
                || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
            )
            .and_then(|(_, mut promises)| {
                Permissions::READ
                    .unveil(README)
                    .map_err(PrivDropErr::from)
                    .and_then(|()| {
                        fs::exists(README)
                            .map_err(PrivDropErr::Io)
                            .and_then(|exists| {
                                Permissions::NONE
                                    .unveil(README)
                                    .map_err(PrivDropErr::from)
                                    .and_then(|()| {
                                        promises
                                            .remove_promises_then_pledge([
                                                Promise::Rpath,
                                                Promise::Unveil,
                                            ])
                                            .map_err(PrivDropErr::Io)
                                            .map(|()| {
                                                assert!(exists);
                                                assert!(
                                                    TcpListener::bind(SocketAddrV6::new(
                                                        Ipv6Addr::LOCALHOST,
                                                        80,
                                                        0,
                                                        0
                                                    ))
                                                    .is_err()
                                                );
                                            })
                                    })
                            })
                    })
            })
        } else {
            Ok(())
        }
    }
}
