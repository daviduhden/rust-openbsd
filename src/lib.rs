//! [![git]](https://git.philomathiclife.com/priv_sep/log.html)&ensp;[![crates-io]](https://crates.io/crates/priv_sep)&ensp;[![docs-rs]](crate)
//!
//! [git]: https://git.philomathiclife.com/git_badge.svg
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! `priv_sep` is a library that uses the system's libc to perform privilege separation and privilege reduction
//! for Unix-like platforms. The following `target_os` values are supported:
//!
//! * `dragonfly`
//! * `freebsd`
//! * `linux`
//! * `macos`
//! * `netbsd`
//! * `openbsd`
//!
//! ## `priv_sep` in action
//!
//! ```no_run
//! use core::convert::Infallible;
//! use priv_sep::{PrivDropErr, UserInfo};
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
//!     // `setgroups(2)` to drop all supplementary groups.
//!     // `setresgid(2)` to the group ID associated with nobody.
//!     // `setresuid(2)` to the user ID associated with nobody.
//!     let listener =
//!         UserInfo::chroot_then_priv_drop_async(c"nobody", c"/path/chroot/", false, async || {
//!             TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
//!         })
//!         .await?;
//!     // At this point, the process is running under nobody.
//!     loop {
//!         // Handle TCP connections.
//!         if let Ok((_, ip)) = listener.accept().await {
//!             assert!(ip.is_ipv6());
//!         }
//!     }
//! }
//! ```
//!
//! <details>
//! <summary>Incorporating <a href="https://man.openbsd.org/pledge.2"><code>pledge(2)</code></a> and <a href="https://man.openbsd.org/unveil.2"><code>unveil(2)</code></a> on OpenBSD</summary>
//!
//! ```no_run
//! # #[cfg(target_os = "openbsd")]
//! use core::convert::Infallible;
//! # #[cfg(target_os = "openbsd")]
//! use priv_sep::{Permissions, PrivDropErr, Promise, Promises};
//! # #[cfg(target_os = "openbsd")]
//! use std::{
//!     fs,
//!     io::Error,
//!     net::{Ipv6Addr, SocketAddrV6},
//! };
//! # #[cfg(target_os = "openbsd")]
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
//!     // `setgroups(2)` to drop all supplementary groups.
//!     // `setresgid(2)` to the group ID associated with nobody.
//!     // `setresuid(2)` to the user ID associated with nobody.
//!     // Remove `id` from our `pledge(2)`d promises.
//!     let (listener, mut promises) = Promises::new_chroot_then_priv_drop_async(
//!         c"nobody",
//!         c"/path/chroot/",
//!         [Promise::Inet, Promise::Rpath, Promise::Unveil],
//!         false,
//!         async || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await,
//!     )
//!     .await?;
//!     // At this point, the process is running under nobody.
//!     // Only allow file system access to `config` and only allow read access to it.
//!     Permissions::READ.unveil(CONFIG)?;
//!     // Read `config`.
//!     // This will of course fail if the file does not exist or nobody does not
//!     // have read permissions.
//!     let config = fs::read(CONFIG).map_err(PrivDropErr::Other)?;
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
//! </details>
//!
//! ## Cargo "features"
//!
//! ### `alloc`
//!
//! Enables `alloc` support. While "typical" use of `priv_sep` should work without `alloc`, there are cases
//! where one may desire heap allocation. For example if a database entry associated with a user requires
//! more than 1 KiB of space, [`UserInfo::new`] will error with [`Errno::ERANGE`] when `alloc` is not enabled.
//!
//! Additional [`CStrHelper`] `impl`s are exposed as well (e.g.,
//! [`String`](./trait.CStrHelper.html#impl-CStrHelper-for-String)).
//!
//! ### `std`
//!
//! Enables `std` support. This is useful for additional [`CStrHelper`] `impl`s (e.g.,
//! [`OsStr`](./trait.CStrHelper.html#impl-CStrHelper-for-OsStr)) as well as
//! [`TryFrom<Error>`](./enum.Errno.html#impl-TryFrom%3CError%3E-for-Errno)
//! and [`From<Errno>`](./enum.Errno.html#impl-From%3CErrno%3E-for-Error).
//!
//! This feature implies [`alloc`](#alloc) and is enabled by default via the `default` feature.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg = false))]
#![no_std]
#![cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#![expect(
    clippy::pub_use,
    reason = "don't want Errno nor openbsd types in a module"
)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;
/// C FFI.
mod c;
/// Errno.
mod err;
/// OpenBSD
#[cfg(any(doc, target_os = "openbsd"))]
mod openbsd;
#[cfg(feature = "std")]
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
use alloc::{ffi::CString, string::String, vec};
use c::SUCCESS;
use core::{
    error::Error as CoreErr,
    ffi::{CStr, c_char, c_int},
    fmt::{self, Display, Formatter},
    mem::MaybeUninit,
    ptr, slice,
};
pub use err::Errno;
#[cfg_attr(docsrs, doc(cfg(target_os = "openbsd")))]
#[cfg(any(doc, target_os = "openbsd"))]
pub use openbsd::{Permission, Permissions, Promise, Promises};
#[cfg(feature = "std")]
use std::{
    ffi::{OsStr, OsString},
    path::{Component, Components, Iter, Path, PathBuf},
};
/// [`uid_t`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/basedefs/sys_types.h.html).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Uid(pub u32);
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
    /// Note on some platforms `setuid` is called using `self`.
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
    pub fn setresuid(self) -> Result<(), Errno> {
        #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "linux",
            target_os = "openbsd"
        ))]
        let code = c::setresuid(self.0, self.0, self.0);
        #[cfg(any(target_os = "macos", target_os = "netbsd"))]
        let code = c::setuid(self.0);
        if code == SUCCESS {
            Ok(())
        } else {
            Err(Errno::last())
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
impl PartialEq<u32> for Uid {
    #[inline]
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}
impl From<Uid> for u32 {
    #[inline]
    fn from(value: Uid) -> Self {
        value.0
    }
}
impl From<u32> for Uid {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value)
    }
}
/// [`gid_t`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/basedefs/sys_types.h.html).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Gid(pub u32);
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
    /// Note on some platforms `setgid` is called using `self`.
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
    pub fn setresgid(self) -> Result<(), Errno> {
        #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "linux",
            target_os = "openbsd"
        ))]
        let code = c::setresgid(self.0, self.0, self.0);
        #[cfg(any(target_os = "macos", target_os = "netbsd"))]
        let code = c::setgid(self.0);
        if code == SUCCESS {
            Ok(())
        } else {
            Err(Errno::last())
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
impl PartialEq<u32> for Gid {
    #[inline]
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}
impl From<Gid> for u32 {
    #[inline]
    fn from(value: Gid) -> Self {
        value.0
    }
}
impl From<u32> for Gid {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value)
    }
}
/// Primarily an internal `trait` that allows one to use a variety of types in lieu of
/// [`CStr`](https://doc.rust-lang.org/stable/core/ffi/struct.CStr.html).
pub trait CStrHelper {
    /// First converts `self` into a
    /// [`CStr`](https://doc.rust-lang.org/stable/core/ffi/struct.CStr.html)
    /// before passing it into `f`.
    ///
    /// # Errors
    ///
    /// Errors whenever necessary.
    ///
    /// If an error occurs due to insufficient buffer space (e.g., when [`alloc`](./index.html#alloc) is not
    /// enabled and a `str` is used with length greater than 1023), then [`Errno::ERANGE`] must be returned.
    ///
    /// If an error occurs from converting `self` into a `CStr` due to nul bytes, then [`Errno::EINVAL`]
    /// must be returned.
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(&self, f: F)
    -> Result<T, Errno>;
}
impl CStrHelper for CStr {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&Self) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        f(self)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
impl CStrHelper for CString {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_c_str().convert_then_apply(f)
    }
}
/// Converts `val` into a `CStr` via heap allocation before applying `f` to it.
#[cold]
#[inline(never)]
#[cfg(feature = "alloc")]
fn c_str_allocating<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
    bytes: &[u8],
    f: F,
) -> Result<T, Errno> {
    CString::new(bytes)
        .map_err(|_e| Errno::EINVAL)
        .and_then(|c| f(&c))
}
impl CStrHelper for [u8] {
    #[expect(unsafe_code, reason = "comments justify correctness")]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment justifies correctness"
    )]
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        /// Maximum stack allocation for `CStr` conversion.
        const C_STR_MAX_STACK_ALLOCATION: usize = 0x400;
        let len = self.len();
        if len < C_STR_MAX_STACK_ALLOCATION {
            let mut buf = MaybeUninit::<[u8; C_STR_MAX_STACK_ALLOCATION]>::uninit();
            let buf_ptr = buf.as_mut_ptr().cast();
            let slice_ptr = self.as_ptr();
            // SAFETY:
            // `slice_ptr` was created from `self` which has length `len` thus is valid for `len` bytes.
            // `buf_ptr` was created from `buf` which has length `C_STR_MAX_STACK_ALLOCATION > len`; thus
            // it too is valid for `len` bytes.
            // `buf`, while unitialized, is only written to before ever being read from.
            // `slice_ptr` and `buf_ptr` are properly aligned.
            // `slice_ptr` and `buf_ptr` point to completely separate allocations.
            unsafe { ptr::copy_nonoverlapping(slice_ptr, buf_ptr, len) };
            // SAFETY:
            // We just wrote `len` bytes into `buf` (which `buf_ptr` points to).
            let nul_pos = unsafe { buf_ptr.add(len) };
            // SAFETY:
            // `buf.len() > len`; thus we know we have at least one byte of space to write `0` to.
            unsafe { nul_pos.write(0) };
            // `len <= isize::MAX`; thus this cannot overflow `usize::MAX`.
            let final_len = len + 1;
            // SAFETY:
            // The first `final_len` bytes of `buf` (which `buf_ptr` points to) is initialized, aligned, valid, and
            // not null.
            // `CStr::from_bytes_with_nul` doesn't mutate `raw_slice`.
            let raw_slice = unsafe { slice::from_raw_parts(buf_ptr, final_len) };
            CStr::from_bytes_with_nul(raw_slice)
                .map_err(|_e| Errno::EINVAL)
                .and_then(f)
        } else {
            #[cfg(not(feature = "alloc"))]
            let res = Err(Errno::ERANGE);
            #[cfg(feature = "alloc")]
            let res = c_str_allocating(self, f);
            res
        }
    }
}
impl CStrHelper for str {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_bytes().convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
impl CStrHelper for String {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_str().convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl CStrHelper for OsStr {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_encoded_bytes().convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl CStrHelper for OsString {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_os_str().convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl CStrHelper for Cow<'_, OsStr> {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        (**self).convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl CStrHelper for Path {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_os_str().convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl CStrHelper for PathBuf {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_os_str().convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl CStrHelper for Component<'_> {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_os_str().convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl CStrHelper for Components<'_> {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_path().convert_then_apply(f)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl CStrHelper for Iter<'_> {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_path().convert_then_apply(f)
    }
}
impl<C: CStrHelper + ?Sized> CStrHelper for &C {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        (**self).convert_then_apply(f)
    }
}
impl<C: CStrHelper + ?Sized> CStrHelper for &mut C {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        (**self).convert_then_apply(f)
    }
}
/// [`chroot(2)`](https://manned.org/chroot.2).
///
/// # Errors
///
/// Errors iff `chroot(2)` does.
///
/// # Examples
///
/// ```no_run
/// assert!(priv_sep::chroot(c"./").is_ok());
/// ```
#[expect(unsafe_code, reason = "chroot(2) takes a pointer")]
#[inline]
pub fn chroot<P: CStrHelper>(path: P) -> Result<(), Errno> {
    fn f(path: &CStr) -> Result<(), Errno> {
        let ptr = path.as_ptr();
        // SAFETY:
        // `ptr` is valid and not null.
        if unsafe { c::chroot(ptr) } == SUCCESS {
            Ok(())
        } else {
            Err(Errno::last())
        }
    }
    path.convert_then_apply(f)
}
/// [`chdir`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/chdir.html).
///
/// This function MUST only be called by `chdir` and `chroot_then_chdir`.
#[expect(unsafe_code, reason = "chdir(2) takes a pointer")]
fn private_chdir(path: *const c_char) -> Result<(), Errno> {
    // SAFETY:
    // `path` is valid and not null as can be seen in the only functions that call this function:
    // `chdir` and `chroot_then_chdir`.
    if unsafe { c::chdir(path) } == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}
/// [`chdir`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/chdir.html).
///
/// # Errors
///
/// Errors iff `chdir` does.
///
/// # Examples
///
/// ```no_run
/// assert!(priv_sep::chdir(c"/").is_ok());
/// ```
#[inline]
pub fn chdir<P: CStrHelper>(path: P) -> Result<(), Errno> {
    fn f(path: &CStr) -> Result<(), Errno> {
        private_chdir(path.as_ptr())
    }
    path.convert_then_apply(f)
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
/// assert!(priv_sep::chroot_then_chdir(c"./").is_ok());
/// ```
#[inline]
pub fn chroot_then_chdir<P: CStrHelper>(path: P) -> Result<(), Errno> {
    /// Root directory.
    const ROOT: *const c_char = c"/".as_ptr();
    chroot(path).and_then(|()| private_chdir(ROOT))
}
/// Error returned when dropping privileges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivDropErr<E> {
    /// Error when an error occurs from a libc call.
    Libc(Errno),
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
            Self::Libc(err) => write!(f, "libc error when dropping privileges: {err}"),
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
impl<E> From<Errno> for PrivDropErr<E> {
    #[inline]
    fn from(value: Errno) -> Self {
        Self::Libc(value)
    }
}
/// Error returned from [`UserInfo::setresid_if_valid`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetresidErr {
    /// Error when an error occurs from a libc call.
    Libc(Errno),
    /// Error when there is no entry in the user database corresponding to [`UserInfo::uid`].
    NoPasswdEntry,
    /// Error when the entry in the user database has a different gid than [`UserInfo::gid`].
    GidMismatch,
}
impl Display for SetresidErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Libc(err) => write!(f, "libc error when dropping privileges: {err}"),
            Self::NoPasswdEntry => f.write_str("no passwd(5) entry to drop privileges to"),
            Self::GidMismatch => f.write_str("gid in passwd(5) does match the expected gid"),
        }
    }
}
impl CoreErr for SetresidErr {}
impl From<Errno> for SetresidErr {
    #[inline]
    fn from(value: Errno) -> Self {
        Self::Libc(value)
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
    /// Helper for [`Self::new`] and [`Self::setresid_if_valid`].
    #[expect(
        unsafe_code,
        reason = "getpwnam_r(3) and getpwuid_r(3) take in pointers"
    )]
    fn getpw_entry<P: Copy + PwEntry>(u: P, buffer: &mut [c_char]) -> Result<Option<Self>, Errno> {
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
        let code = unsafe { u.getpw(pwd_ptr, buf_ptr, len, res_ptr) };
        if code == SUCCESS {
            if result.is_null() {
                Ok(None)
            } else {
                debug_assert!(
                    result.is_aligned(),
                    "libc getpwnam_r or getpwuid_r result was not aligned. Something is terribly wrong with your system"
                );
                // SAFETY:
                // Verified above that `result` is not null and aligned. Note while we only verify the pointer
                // is aligned on non-release builds, the situation is so dire that one could argue we are
                // already in "undefined" territory.
                // When `result` is not null, the platform is supposed to have written to `pwd`.
                Ok(Some(unsafe { pwd.assume_init() }.into_user_info()))
            }
        } else {
            Err(Errno::from_raw(code))
        }
    }
    /// [`getpwnam_r`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getpwnam_r.html).
    ///
    /// Obtains the user database entry returning `None` iff there is no entry; otherwise returns `Self`.
    ///
    /// A 1 KiB stack-allocated buffer is used to write the database entry into. If [`Errno::ERANGE`]
    /// is returned, then the following will occur:
    ///
    /// * If [`alloc`](./index.html#alloc) is not enabled, then the error is returned.
    /// * If [`alloc`](./index.html#alloc) is enabled and a 16-bit architecture is used, then a heap-allocated buffer of 16 KiB
    ///   is used. If this errors, then the error is returned.
    /// * If [`alloc`](./index.html#alloc) is enabled and a non-16-bit architecture is used, then a heap-allocated buffer of 1 MiB
    ///   is used. If this errors, then the error is returned.
    ///
    /// # Errors
    ///
    /// Errors iff `getpwnam_r` does.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::UserInfo;
    /// assert!(UserInfo::new(c"root")?.map_or(false, |info| info.is_root()));
    /// # Ok::<_, priv_sep::Errno>(())
    /// ```
    #[inline]
    pub fn new<C: CStrHelper>(name: C) -> Result<Option<Self>, Errno> {
        fn f(name: &CStr) -> Result<Option<UserInfo>, Errno> {
            let wrapper = CStrWrapper(name);
            let res = UserInfo::getpw_entry(wrapper, &mut [0; 0x400]);
            #[cfg(not(feature = "alloc"))]
            let res_final = res;
            #[cfg(all(target_pointer_width = "16", feature = "alloc"))]
            let res_final = res.or_else(|e| {
                if matches!(e, Errno::ERANGE) {
                    Self::getpw_entry(wrapper, vec![0; 0x4000].as_mut_slice())
                } else {
                    Err(e)
                }
            });
            #[cfg(all(not(target_pointer_width = "16"), feature = "alloc"))]
            let res_final = res.or_else(|e| {
                if matches!(e, Errno::ERANGE) {
                    UserInfo::getpw_entry(wrapper, vec![0; 0x10_0000].as_mut_slice())
                } else {
                    Err(e)
                }
            });
            res_final
        }
        name.convert_then_apply(f)
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
    /// if let Some(user) = UserInfo::new(c"nobody")? {
    ///     user.setresid()?;
    /// }
    /// # Ok::<_, priv_sep::Errno>(())
    /// ```
    #[inline]
    pub fn setresid(self) -> Result<(), Errno> {
        self.gid.setresgid().and_then(|()| self.uid.setresuid())
    }
    /// Same as [`Self::setresid`] except
    /// [`getpwuid_r`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getpwuid_r.html)
    /// is used to first confirm the existence of [`Self::uid`] and [`Self::gid`].
    ///
    /// Note this should rarely be used since most will rely on [`Self::new`], [`Self::priv_drop`], or
    /// [`Self::chroot_then_priv_drop`].
    ///
    /// Read [`Self::new`] for more information on the buffering strategy.
    ///
    /// # Errors
    ///
    /// Errors iff `getpwuid_r` errors, [`Self::uid`] and [`Self::gid`] don't exist in the user
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
        let res = Self::getpw_entry(self.uid, &mut [0; 0x400]);
        #[cfg(not(feature = "alloc"))]
        let res_final = res;
        #[cfg(all(target_pointer_width = "16", feature = "alloc"))]
        let res_final = res.or_else(|e| {
            if matches!(e, Errno::ERANGE) {
                Self::getpw_entry(self.uid, vec![0; 0x4000].as_mut_slice())
            } else {
                Err(e)
            }
        });
        #[cfg(all(not(target_pointer_width = "16"), feature = "alloc"))]
        let res_final = res.or_else(|e| {
            if matches!(e, Errno::ERANGE) {
                Self::getpw_entry(self.uid, vec![0; 0x10_0000].as_mut_slice())
            } else {
                Err(e)
            }
        });
        res_final.map_err(SetresidErr::Libc).and_then(|opt| {
            opt.ok_or(SetresidErr::NoPasswdEntry).and_then(|info| {
                if info.gid == self.gid {
                    self.setresid().map_err(SetresidErr::Libc)
                } else {
                    Err(SetresidErr::GidMismatch)
                }
            })
        })
    }
    /// Helper to unify targets that don't support `setgroups(2)`.
    ///
    /// No-op.
    #[cfg(target_os = "macos")]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "unify with platforms that support `setgroups`"
    )]
    const fn drop_sup_groups<Never>() -> Result<(), Never> {
        Ok(())
    }
    /// Helper to unify targets that don't support `setgroups(2)`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    fn drop_sup_groups() -> Result<(), Errno> {
        drop_supplementary_groups()
    }
    /// Calls [`Self::new`], invokes `f`, calls [`drop_supplementary_groups`] (if the platform supports
    /// `setgroups(2)`), then calls [`Self::setresid`].
    ///
    /// Dropping privileges is necessary when needing to perform certain actions as root before no longer needing
    /// such abilities; at which point, one calls
    /// [`setgroups(2)`](https://www.man7.org/linux/man-pages/man2/setgroups.2.html),
    /// [`setresgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresgid.html), and
    /// [`setresuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresuid.html)
    /// using a lesser privileged gid and uid.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::new`], `f`, [`drop_supplementary_groups`], or [`Self::setresid`] do or there is no entry in the user database
    /// corresponding to `name` or the entry has uid 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use priv_sep::{PrivDropErr, UserInfo};
    /// # use std::{io::Error, net::TcpListener};
    /// let listener = UserInfo::priv_drop(c"nobody", || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
    /// })?;
    /// # Ok::<_, PrivDropErr<Error>>(())
    /// ```
    #[inline]
    pub fn priv_drop<C: CStrHelper, T, E, F: FnOnce() -> Result<T, E>>(
        name: C,
        f: F,
    ) -> Result<T, PrivDropErr<E>> {
        Self::new(name).map_err(PrivDropErr::Libc).and_then(|opt| {
            opt.ok_or_else(|| PrivDropErr::NoPasswdEntry)
                .and_then(|info| {
                    if info.is_root() {
                        Err(PrivDropErr::RootEntry)
                    } else {
                        f().map_err(PrivDropErr::Other).and_then(|res| {
                            Self::drop_sup_groups()
                                .and_then(|()| info.setresid().map(|()| res))
                                .map_err(PrivDropErr::Libc)
                        })
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
    /// let listener_fut = UserInfo::priv_drop_async(c"nobody", async || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
    /// });
    /// ```
    #[inline]
    pub async fn priv_drop_async<C: CStrHelper, T, E, F: AsyncFnOnce() -> Result<T, E>>(
        name: C,
        f: F,
    ) -> Result<T, PrivDropErr<E>> {
        match Self::new(name) {
            Ok(opt) => match opt {
                None => Err(PrivDropErr::NoPasswdEntry),
                Some(info) => {
                    if info.is_root() {
                        Err(PrivDropErr::RootEntry)
                    } else {
                        f().await.map_err(PrivDropErr::Other).and_then(|res| {
                            Self::drop_sup_groups()
                                .and_then(|()| info.setresid().map(|()| res))
                                .map_err(PrivDropErr::Libc)
                        })
                    }
                }
            },
            Err(err) => Err(PrivDropErr::Libc(err)),
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
    /// let listener = UserInfo::chroot_then_priv_drop(c"nobody", c"./", false, || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
    /// })?;
    /// # Ok::<_, PrivDropErr<Error>>(())
    /// ```
    #[inline]
    pub fn chroot_then_priv_drop<
        N: CStrHelper,
        P: CStrHelper,
        T,
        E,
        F: FnOnce() -> Result<T, E>,
    >(
        name: N,
        path: P,
        chroot_after_f: bool,
        f: F,
    ) -> Result<T, PrivDropErr<E>> {
        Self::new(name).map_err(PrivDropErr::Libc).and_then(|opt| {
            opt.ok_or_else(|| PrivDropErr::NoPasswdEntry)
                .and_then(|info| {
                    if info.is_root() {
                        Err(PrivDropErr::RootEntry)
                    } else if chroot_after_f {
                        f().map_err(PrivDropErr::Other).and_then(|res| {
                            chroot_then_chdir(path)
                                .map_err(PrivDropErr::Libc)
                                .map(|()| res)
                        })
                    } else {
                        chroot_then_chdir(path)
                            .map_err(PrivDropErr::Libc)
                            .and_then(|()| f().map_err(PrivDropErr::Other))
                    }
                    .and_then(|res| {
                        Self::drop_sup_groups()
                            .and_then(|()| info.setresid().map(|()| res))
                            .map_err(PrivDropErr::Libc)
                    })
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
    /// let listener_fut = UserInfo::chroot_then_priv_drop_async(c"nobody", c"./", false, async || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
    /// });
    /// ```
    #[inline]
    pub async fn chroot_then_priv_drop_async<
        N: CStrHelper,
        P: CStrHelper,
        T,
        E,
        F: AsyncFnOnce() -> Result<T, E>,
    >(
        name: N,
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
                            .map_err(PrivDropErr::Libc)
                            .map(|()| res)
                    })
                } else {
                    match chroot_then_chdir(path) {
                        Ok(()) => f().await.map_err(PrivDropErr::Other),
                        Err(err) => Err(PrivDropErr::Libc(err)),
                    }
                }
                .and_then(|res| {
                    Self::drop_sup_groups()
                        .and_then(|()| info.setresid().map(|()| res))
                        .map_err(PrivDropErr::Libc)
                }),
            },
            Err(err) => Err(PrivDropErr::Libc(err)),
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
/// [`setgroups(2)`](https://www.man7.org/linux/man-pages/man2/setgroups.2.html).
///
/// # Errors
///
/// Errors iff `setgroups` does.
///
/// # Examples
///
/// ```no_run
/// assert!(priv_sep::setgroups(&[]).is_ok());
/// ```
#[cfg_attr(docsrs, doc(cfg(not(target_os = "macos"))))]
#[cfg(any(doc, not(target_os = "macos")))]
#[expect(unsafe_code, reason = "setgroups(2) takes a pointer")]
#[inline]
pub fn setgroups(groups: &[Gid]) -> Result<(), Errno> {
    #[cfg(target_os = "linux")]
    let size = groups.len();
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    let size = c_int::try_from(groups.len()).map_err(|_e| Errno::EINVAL)?;
    let gids = groups.as_ptr().cast();
    // SAFETY:
    // `size` is the length of `gids`, and `gids` is a valid, non-null, aligned pointer to
    // `u32`s. Note that `Gid` is a `newtype` around `u32` with `repr(transparent)`; thus the above
    // pointer cast is fine.
    let code = unsafe { c::setgroups(size, gids) };
    if code == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}
/// [`setgroups(2)`](https://www.man7.org/linux/man-pages/man2/setgroups.2.html) passing in
/// 0 and a null pointer.
///
/// If successful, this drops all supplementary groups.
///
/// # Errors
///
/// Errors iff `setgroups` does.
///
/// # Examples
///
/// ```no_run
/// assert!(priv_sep::drop_supplementary_groups().is_ok());
/// ```
#[cfg_attr(docsrs, doc(cfg(not(target_os = "macos"))))]
#[cfg(any(doc, not(target_os = "macos")))]
#[expect(unsafe_code, reason = "setgroups(2) takes a pointer")]
#[inline]
pub fn drop_supplementary_groups() -> Result<(), Errno> {
    #[cfg(target_os = "linux")]
    let size: usize = 0;
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    let size: c_int = 0;
    let gids = ptr::null();
    // SAFETY:
    // Passing in 0 and a null pointer is valid and causes all supplementary groups to be dropped.
    let code = unsafe { c::setgroups(size, gids) };
    if code == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}
#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use super::PrivDropErr;
    use super::{Errno, Gid, SetresidErr, Uid, UserInfo};
    #[cfg(all(feature = "std", target_os = "openbsd"))]
    use super::{Permissions, Promise, Promises};
    #[cfg(feature = "std")]
    use core::net::{Ipv6Addr, SocketAddrV6};
    #[cfg(all(feature = "std", target_os = "openbsd"))]
    extern crate alloc;
    #[cfg(all(feature = "std", target_os = "openbsd"))]
    use alloc::format;
    #[cfg(all(feature = "std", target_os = "openbsd"))]
    use std::io::{self, Write as _};
    #[cfg(feature = "std")]
    use std::{
        fs,
        io::{Error, ErrorKind},
        net::TcpListener,
    };
    use tokio as _;
    #[cfg(feature = "std")]
    const README: &str = "README.md";
    #[test]
    fn getuid() {
        _ = Uid::getuid();
    }
    #[test]
    fn geteuid() {
        _ = Uid::geteuid();
    }
    #[test]
    fn getgid() {
        _ = Gid::getgid();
    }
    #[test]
    fn getegid() {
        _ = Gid::getegid();
    }
    #[test]
    fn setresuid() -> Result<(), Errno> {
        Uid::geteuid().setresuid()
    }
    #[test]
    fn setresgid() -> Result<(), Errno> {
        Gid::getegid().setresgid()
    }
    #[test]
    fn user_info_new() {
        assert_eq!(
            UserInfo::new(c"root"),
            Ok(Some(UserInfo {
                uid: Uid::ROOT,
                gid: Gid(0),
            }))
        );
    }
    #[test]
    fn user_info_setresid() -> Result<(), Errno> {
        UserInfo {
            uid: Uid::geteuid(),
            gid: Gid::getegid(),
        }
        .setresid()
    }
    #[test]
    fn user_info_setresid_if_valid() -> Result<(), SetresidErr> {
        UserInfo {
            uid: Uid::geteuid(),
            gid: Gid::getegid(),
        }
        .setresid_if_valid()
    }
    #[test]
    fn user_info_setresid_if_valid_failure() {
        assert_eq!(
            UserInfo {
                uid: Uid::geteuid(),
                gid: Gid(u32::MAX),
            }
            .setresid_if_valid(),
            Err(SetresidErr::GidMismatch)
        );
    }
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "primarily useful for root and interferes with chroot_drop_priv"]
    fn priv_drop() {
        if Uid::geteuid().is_root() {
            assert!(
                UserInfo::priv_drop(c"nobody", || {
                    TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
                })
                .is_ok_and(|_| true)
            );
            assert!(
                TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0)).map_or_else(
                    |e| matches!(e.kind(), ErrorKind::PermissionDenied),
                    |_| false
                )
            );
        } else {
            assert!(
                UserInfo::priv_drop(c"root", || Ok::<_, Error>(()))
                    .map_or_else(|e| matches!(e, PrivDropErr::RootEntry), |()| false)
            );
        }
    }
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "primarily useful for root and interferes with priv_drop"]
    fn chroot_drop_priv() {
        if Uid::geteuid().is_root() {
            assert!(
                UserInfo::chroot_then_priv_drop(c"nobody", c"./", false, || {
                    TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 987, 0, 0))
                })
                .is_ok_and(|_| {
                    fs::exists(README).is_ok_and(|exists| {
                        exists
                            && TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 82, 0, 0))
                                .map_or_else(
                                    |e| matches!(e.kind(), ErrorKind::PermissionDenied),
                                    |_| false,
                                )
                    })
                })
            );
        }
    }
    #[expect(
        clippy::panic,
        reason = "reasonable to expect files to not exist that need to in order to test pledge and unveil"
    )]
    #[expect(
        clippy::expect_used,
        reason = "kinda reasonable to expect files to exist that mustn't in order to test pledge and unveil"
    )]
    #[cfg(all(feature = "std", target_os = "openbsd"))]
    #[test]
    #[ignore = "interferes with other tests"]
    fn unveil_pledge() {
        const FILE_EXISTS: &str = "/home/zack/foo.txt";
        const FILE_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23";
        const DIR_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23/";
        _ = fs::metadata(FILE_EXISTS).unwrap_or_else(|_e| {
            panic!("{FILE_EXISTS} does not exist, so unit testing cannot occur")
        });
        drop(fs::metadata(FILE_NOT_EXISTS).expect_err(
            format!("{FILE_NOT_EXISTS} exists, so unit testing cannot occur").as_str(),
        ));
        drop(
            fs::metadata(DIR_NOT_EXISTS).expect_err(
                format!("{DIR_NOT_EXISTS} exists, so unit testing cannot occur").as_str(),
            ),
        );
        // This tests that a NULL `promise` does nothing.
        assert_eq!(Promises::pledge_none(), Ok(()));
        assert!(writeln!(io::stdout()).is_ok_and(|()| true));
        assert_eq!(Promises::ALL.pledge(), Ok(()));
        // This tests that duplicates are ignored as well as the implementation of PartialEq.
        let mut initial_promises = Promises::new([
            Promise::Stdio,
            Promise::Unveil,
            Promise::Rpath,
            Promise::Stdio,
        ]);
        assert_eq!(initial_promises.len(), 3);
        assert_eq!(
            initial_promises,
            Promises::new([Promise::Rpath, Promise::Stdio, Promise::Unveil])
        );
        // Test retain.
        let mut vals = Promises::new([
            Promise::Audio,
            Promise::Bpf,
            Promise::Chown,
            Promise::Cpath,
            Promise::Error,
            Promise::Exec,
        ]);
        vals.retain([Promise::Error, Promise::Chown]);
        assert_eq!(vals.len(), 2);
        assert!(vals.contains(Promise::Chown));
        assert!(vals.contains(Promise::Error));
        assert_eq!(initial_promises.pledge(), Ok(()));
        // This tests unveil with no permissions.
        assert_eq!(Permissions::NONE.unveil(FILE_EXISTS), Ok(()));
        assert!(fs::metadata(FILE_EXISTS).map_or_else(
            |e| matches!(e.kind(), ErrorKind::PermissionDenied),
            |_| false
        ));
        // This tests unveil with read permissions,
        // and one can unveil more permissions (unlike pledge which can only remove promises).
        assert_eq!(Permissions::READ.unveil(FILE_EXISTS), Ok(()));
        assert!(fs::metadata(FILE_EXISTS).is_ok_and(|_| true));
        // This tests that calls to unveil on missing files don't error.
        assert_eq!(Permissions::NONE.unveil(FILE_NOT_EXISTS), Ok(()));
        // This tests that calls to unveil on missing directories error.
        assert_eq!(Permissions::NONE.unveil(DIR_NOT_EXISTS), Err(Errno::ENOENT));
        // This tests that unveil can no longer be called.
        assert_eq!(Permissions::unveil_no_more(), Ok(()));
        assert_eq!(Permissions::NONE.unveil(FILE_EXISTS), Err(Errno::EPERM));
        assert!(fs::metadata(FILE_EXISTS).is_ok_and(|_| true));
        // The below tests that Promises can only be removed and not added.
        initial_promises.remove_promises([Promise::Unveil]);
        assert_eq!(initial_promises.len(), 2);
        initial_promises.remove(Promise::Rpath);
        assert_eq!(initial_promises.len(), 1);
        initial_promises.remove(Promise::Rpath);
        assert_eq!(initial_promises.len(), 1);
        assert_eq!(initial_promises.pledge(), Ok(()));
        assert!(writeln!(io::stdout()).is_ok_and(|()| true));
        assert_eq!(Promises::new([Promise::Rpath]).pledge(), Err(Errno::EPERM));
        // If the below is uncommented, the program should crash since the above
        // call to pledge no longer allows access to the file system.
        // drop(fs::metadata(FILE_EXISTS));
    }
    #[cfg(all(feature = "std", target_os = "openbsd"))]
    #[test]
    #[ignore = "interferes with other tests when root"]
    fn pledge_inet_drop_priv() {
        if Uid::geteuid().is_root() {
            assert!(
                Promises::new_priv_drop(
                    c"nobody",
                    [Promise::Inet, Promise::Rpath, Promise::Unveil],
                    false,
                    || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 47, 0, 0)),
                )
                .is_ok_and(|(_, _)| {
                    Permissions::unveil_raw(README, c"r").is_ok_and(|()| {
                        fs::exists(README).is_ok_and(|exists| {
                            Permissions::NONE.unveil(README).is_ok_and(|()| {
                                Promises::pledge_raw(c"inet stdio").is_ok_and(|()| {
                                    exists
                                        && TcpListener::bind(SocketAddrV6::new(
                                            Ipv6Addr::LOCALHOST,
                                            792,
                                            0,
                                            0,
                                        ))
                                        .map_or_else(
                                            |e| matches!(e.kind(), ErrorKind::PermissionDenied),
                                            |_| false,
                                        )
                                })
                            })
                        })
                    })
                })
            );
        }
    }
    #[cfg(all(feature = "std", target_os = "openbsd"))]
    #[test]
    #[ignore = "interferes with other tests when root"]
    fn inet_chroot_priv_pledge() {
        if Uid::geteuid().is_root() {
            assert!(
                Promises::new_chroot_then_priv_drop(
                    c"nobody",
                    c"./",
                    [Promise::Inet, Promise::Rpath, Promise::Unveil],
                    false,
                    || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 382, 0, 0))
                )
                .is_ok_and(|(_, mut promises)| Permissions::READ
                    .unveil(README)
                    .is_ok_and(|()| fs::exists(README).is_ok_and(|exists| Permissions::NONE
                        .unveil(README)
                        .is_ok_and(|()| promises
                            .remove_promises_then_pledge([Promise::Rpath, Promise::Unveil])
                            .is_ok_and(|()| exists
                                && TcpListener::bind(SocketAddrV6::new(
                                    Ipv6Addr::LOCALHOST,
                                    588,
                                    0,
                                    0
                                ))
                                .map_or_else(
                                    |e| matches!(e.kind(), ErrorKind::PermissionDenied),
                                    |_| false
                                ))))))
            );
        }
    }
}
