//! # `priv_sep`
//!
//! `priv_sep` is a library for privilege separation.
//! It is currently designed around [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) and
//! [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) for OpenBSD, but
//! in the future may contain functionality for Linux's
//! [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html).
//!
//! ## Pledge
//!
//! Calls to `pledge(2)` are done via [`Promises::pledge`] and [`pledge_none`].
//! Note that since the use of `execpromises` is quite rare, `NULL` is always
//! used for it.
//!
//! ## Unveil
//!
//! Calls to `unveil(2)` are done via [`Permissions::unveil`] and [`unveil_no_more`].
//!
//! ## Errors
//!
//! Any error returned from the underlying system call is propagated via [`io::Error`].
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    unknown_lints,
    future_incompatible,
    let_underscore,
    missing_docs,
    nonstandard_style,
    refining_impl_trait,
    rust_2018_compatibility,
    rust_2018_idioms,
    rust_2021_compatibility,
    rust_2024_compatibility,
    unsafe_code,
    unused,
    warnings,
    clippy::all,
    clippy::cargo,
    clippy::complexity,
    clippy::correctness,
    clippy::nursery,
    clippy::pedantic,
    clippy::perf,
    clippy::restriction,
    clippy::style,
    clippy::suspicious
)]
#![expect(
    clippy::blanket_clippy_restriction_lints,
    clippy::doc_markdown,
    reason = "same reason as below"
)]
#![cfg_attr(docsrs, doc(cfg(feature = "openbsd")))]
#![cfg(feature = "openbsd")]
#![expect(
    clippy::exhaustive_enums,
    clippy::implicit_return,
    clippy::min_ident_chars,
    clippy::missing_trait_methods,
    clippy::ref_patterns,
    clippy::single_char_lifetime_names,
    clippy::unseparated_literal_suffix,
    reason = "noisy, opinionated, and likely doesn't prevent bugs or improve APIs"
)]
extern crate alloc;
use alloc::ffi::{CString, NulError};
use core::{
    convert::AsRef,
    error,
    ffi::{c_char, c_int},
    fmt::{self, Display, Formatter},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not},
    ptr,
};
use std::{io, os::unix::ffi::OsStrExt, path::Path};
use Promise::{
    Audio, Bpf, Chown, Cpath, Disklabel, Dns, Dpath, Drm, Error, Exec, Fattr, Flock, Getpw, Id,
    Inet, Mcast, Pf, Proc, ProtExec, Ps, Recvfd, Route, Rpath, Sendfd, Settime, Stdio, Tape,
    Tmppath, Tty, Unix, Unveil, Video, Vminfo, Vmm, Wpath, Wroute,
};
/// A `promise` to [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Promise {
    /// Consult `pledge(2)`.
    Audio,
    /// Consult `pledge(2)`.
    Bpf,
    /// Consult `pledge(2)`.
    Chown,
    /// Consult `pledge(2)`.
    Cpath,
    /// Consult `pledge(2)`.
    Disklabel,
    /// Consult `pledge(2)`.
    Dns,
    /// Consult `pledge(2)`.
    Dpath,
    /// Consult `pledge(2)`.
    Drm,
    /// Consult `pledge(2)`.
    Error,
    /// Consult `pledge(2)`.
    Exec,
    /// Consult `pledge(2)`.
    Fattr,
    /// Consult `pledge(2)`.
    Flock,
    /// Consult `pledge(2)`.
    Getpw,
    /// Consult `pledge(2)`.
    Id,
    /// Consult `pledge(2)`.
    Inet,
    /// Consult `pledge(2)`.
    Mcast,
    /// Consult `pledge(2)`.
    Pf,
    /// Consult `pledge(2)`.
    Proc,
    /// Consult `pledge(2)`.
    ProtExec,
    /// Consult `pledge(2)`.
    Ps,
    /// Consult `pledge(2)`.
    Recvfd,
    /// Consult `pledge(2)`.
    Route,
    /// Consult `pledge(2)`.
    Rpath,
    /// Consult `pledge(2)`.
    Sendfd,
    /// Consult `pledge(2)`.
    Settime,
    /// Consult `pledge(2)`.
    Stdio,
    /// Consult `pledge(2)`.
    Tape,
    /// Consult `pledge(2)`.
    Tmppath,
    /// Consult `pledge(2)`.
    Tty,
    /// Consult `pledge(2)`.
    Unix,
    /// Consult `pledge(2)`.
    Unveil,
    /// Consult `pledge(2)`.
    Video,
    /// Consult `pledge(2)`.
    Vminfo,
    /// Consult `pledge(2)`.
    Vmm,
    /// Consult `pledge(2)`.
    Wpath,
    /// Consult `pledge(2)`.
    Wroute,
}
impl Promise {
    /// Returns `self` as a `u64`.
    const fn to_u64(self) -> u64 {
        match self {
            Audio => 0x1,
            Bpf => 0x2,
            Chown => 0x4,
            Cpath => 0x8,
            Disklabel => 0x10,
            Dns => 0x20,
            Dpath => 0x40,
            Drm => 0x80,
            Error => 0x100,
            Exec => 0x200,
            Fattr => 0x400,
            Flock => 0x800,
            Getpw => 0x1000,
            Id => 0x2000,
            Inet => 0x4000,
            Mcast => 0x8000,
            Pf => 0x10000,
            Proc => 0x20000,
            ProtExec => 0x40000,
            Ps => 0x80000,
            Recvfd => 0x0010_0000,
            Route => 0x0020_0000,
            Rpath => 0x0040_0000,
            Sendfd => 0x0080_0000,
            Settime => 0x0100_0000,
            Stdio => 0x0200_0000,
            Tape => 0x0400_0000,
            Tmppath => 0x0800_0000,
            Tty => 0x1000_0000,
            Unix => 0x2000_0000,
            Unveil => 0x4000_0000,
            Video => 0x8000_0000,
            Vminfo => 0x0001_0000_0000,
            Vmm => 0x0002_0000_0000,
            Wpath => 0x0004_0000_0000,
            Wroute => 0x0008_0000_0000,
        }
    }
}
impl Display for Promise {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Audio => f.write_str("pledge(2) 'audio' promise"),
            Bpf => f.write_str("pledge(2) 'bpf' promise"),
            Chown => f.write_str("pledge(2) 'chown' promise"),
            Cpath => f.write_str("pledge(2) 'cpath' promise"),
            Disklabel => f.write_str("pledge(2) 'disklabel' promise"),
            Dns => f.write_str("pledge(2) 'dns' promise"),
            Dpath => f.write_str("pledge(2) 'dpath' promise"),
            Drm => f.write_str("pledge(2) 'drm' promise"),
            Error => f.write_str("pledge(2) 'error' promise"),
            Exec => f.write_str("pledge(2) 'exec' promise"),
            Fattr => f.write_str("pledge(2) 'fattr' promise"),
            Flock => f.write_str("pledge(2) 'flock' promise"),
            Getpw => f.write_str("pledge(2) 'getpw' promise"),
            Id => f.write_str("pledge(2) 'id' promise"),
            Inet => f.write_str("pledge(2) 'inet' promise"),
            Mcast => f.write_str("pledge(2) 'mcast' promise"),
            Pf => f.write_str("pledge(2) 'pf' promise"),
            Proc => f.write_str("pledge(2) 'proc' promise"),
            ProtExec => f.write_str("pledge(2) 'prot_exec' promise"),
            Ps => f.write_str("pledge(2) 'ps' promise"),
            Recvfd => f.write_str("pledge(2) 'recvfd' promise"),
            Route => f.write_str("pledge(2) 'route' promise"),
            Rpath => f.write_str("pledge(2) 'rpath' promise"),
            Sendfd => f.write_str("pledge(2) 'sendfd' promise"),
            Settime => f.write_str("pledge(2) 'settime' promise"),
            Stdio => f.write_str("pledge(2) 'stdio' promise"),
            Tape => f.write_str("pledge(2) 'tape' promise"),
            Tmppath => f.write_str("pledge(2) 'tmppath' promise"),
            Tty => f.write_str("pledge(2) 'tty' promise"),
            Unix => f.write_str("pledge(2) 'unix' promise"),
            Unveil => f.write_str("pledge(2) 'unveil' promise"),
            Video => f.write_str("pledge(2) 'video' promise"),
            Vminfo => f.write_str("pledge(2) 'vminfo' promise"),
            Vmm => f.write_str("pledge(2) 'vmm' promise"),
            Wpath => f.write_str("pledge(2) 'wpath' promise"),
            Wroute => f.write_str("pledge(2) 'wroute' promise"),
        }
    }
}
impl PartialEq<&Self> for Promise {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Promise> for &Promise {
    #[inline]
    fn eq(&self, other: &Promise) -> bool {
        **self == *other
    }
}
/// A set of [`Promise`]s that can only have `Promise`s removed after creation.
///
/// Once a set of `promises` has been [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2)d,
/// only a subset of those `promises` can be `pledge(2)`d again, so this type can be used
/// to ensure that `Promise`s are never added but only removed from an initial set.
#[derive(Debug, Eq, PartialEq)]
pub struct Promises(u64);
/// Invokes `pledge(2)` always passing `NULL` for `execpromises` and
/// `promises` for `promises`.
///
/// This function MUST only be called by `Promises::pledge` and
/// `pledge_none`.
#[expect(unsafe_code, reason = "FFI requires unsafe code")]
fn pledge(promises: *const c_char) -> Result<(), io::Error> {
    extern "C" {
        fn pledge(promises: *const c_char, execpromises: *const c_char) -> c_int;
    }
    // SAFETY:
    // `pledge` is an FFI binding; thus requires unsafe code.
    // `NULL` is always valid for `execpromises`, and `promises` meets the requirements of the `pledge(2)` call
    // as can be verified in the only two functions that call this function:
    // `Promises::pledge` and `pledge_none`.
    if unsafe { pledge(promises, ptr::null()) } == 0i32 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
impl Promises {
    /// Empty `Promises`.
    pub const NONE: Self = Self(0);
    /// `Promises` containing all [`Promise`]s.
    pub const ALL: Self = Self::NONE
        .add(Promise::Audio)
        .add(Promise::Bpf)
        .add(Promise::Chown)
        .add(Promise::Cpath)
        .add(Promise::Disklabel)
        .add(Promise::Dns)
        .add(Promise::Dpath)
        .add(Promise::Drm)
        .add(Promise::Error)
        .add(Promise::Exec)
        .add(Promise::Fattr)
        .add(Promise::Flock)
        .add(Promise::Getpw)
        .add(Promise::Id)
        .add(Promise::Inet)
        .add(Promise::Mcast)
        .add(Promise::Pf)
        .add(Promise::Proc)
        .add(Promise::ProtExec)
        .add(Promise::Ps)
        .add(Promise::Recvfd)
        .add(Promise::Route)
        .add(Promise::Rpath)
        .add(Promise::Sendfd)
        .add(Promise::Settime)
        .add(Promise::Stdio)
        .add(Promise::Tape)
        .add(Promise::Tmppath)
        .add(Promise::Tty)
        .add(Promise::Unix)
        .add(Promise::Unveil)
        .add(Promise::Video)
        .add(Promise::Vminfo)
        .add(Promise::Vmm)
        .add(Promise::Wpath)
        .add(Promise::Wroute);
    /// Returns a `Promises` containing all `Promise`s in `self` and `promise`.
    const fn add(self, promise: Promise) -> Self {
        Self(self.0 | promise.to_u64())
    }
    /// Returns a `Promises` containing the unique `Promise`s in `initial`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Promise, Promises};
    /// assert_eq!(Promises::new([Promise::Stdio]).len(), 1);
    /// ```
    #[inline]
    #[must_use]
    pub fn new<P: AsRef<[Promise]>>(initial: P) -> Self {
        initial
            .as_ref()
            .iter()
            .fold(Self::NONE, |val, promise| val.add(*promise))
    }
    /// Returns the number of [`Promise`]s.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Promise, Promises};
    /// assert_eq!(Promises::new([Promise::Stdio]).len(), 1);
    /// ```
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.0.count_ones()
    }
    /// Returns `true` iff there are no [`Promise`]s.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Promises;
    /// assert!(Promises::NONE.is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns `true` iff `self` contains `promise`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Promise, Promises};
    /// assert!(Promises::new([Promise::Stdio]).contains(Promise::Stdio));
    /// assert!(!Promises::new([Promise::Stdio]).contains(Promise::Rpath));
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains(&self, promise: Promise) -> bool {
        let val = promise.to_u64();
        self.0 & val == val
    }
    /// Removes all `Promise`s _not_ in `promises` from `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Promise, Promises};
    /// let mut proms = Promises::new([Promise::Rpath, Promise::Stdio]);
    /// proms.retain([Promise::Stdio]);
    /// assert!(proms.len() == 1 && proms.contains(Promise::Stdio));
    /// ```
    #[inline]
    pub fn retain<P: AsRef<[Promise]>>(&mut self, promises: P) {
        self.0 = promises
            .as_ref()
            .iter()
            .fold(Self::NONE, |val, promise| {
                if self.contains(*promise) {
                    val.add(*promise)
                } else {
                    val
                }
            })
            .0;
    }
    /// Same as [`Self::retain`] then [`Self::pledge`]; however this is "atomic" in that if an error occurs from `pledge`,
    /// `self` is left unchanged. This is useful when one wants to "recover" from an error since there is no
    /// way to add `Promise`s back forcing one to have to create a second `Promises`.
    ///
    /// Note that when `retain` doesn't change `self`, `pledge` is not called.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] iff `pledge` does.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use priv_sep::{Promise, Promises};
    /// assert!(Promises::new([Promise::Rpath, Promise::Stdio]).retain_then_pledge([Promise::Rpath]).is_ok());
    /// ```
    #[inline]
    pub fn retain_then_pledge<P: AsRef<[Promise]>>(
        &mut self,
        promises: P,
    ) -> Result<(), io::Error> {
        // We opt for the easy way by copying `self`. This should be the fastest for the
        // typical case since `self` likely has very few `Promise`s, and it makes for less code.
        let cur = Self(self.0);
        self.retain(promises);
        if *self == cur {
            Ok(())
        } else {
            self.pledge().inspect_err(|_| *self = cur)
        }
    }
    /// Removes all `Promise`s in `promises` from `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Promise, Promises};
    /// let mut proms = Promises::new([Promise::Rpath, Promise::Stdio]);
    /// proms.remove_promises([Promise::Stdio]);
    /// assert!(proms.len() == 1 && proms.contains(Promise::Rpath));
    /// ```
    #[inline]
    pub fn remove_promises<P: AsRef<[Promise]>>(&mut self, promises: P) {
        promises
            .as_ref()
            .iter()
            .fold((), |(), promise| self.remove(*promise));
    }
    /// Same as [`Self::remove_promises`] then [`Self::pledge`]; however this is "atomic" in that if an error occurs from
    /// `pledge`, `self` is left unchanged. This is useful when one wants to "recover" from an error since there
    /// is no way to add `Promise`s back forcing one to have to create a second `Promises`.
    ///
    /// Note that when `remove_promises` doesn't remove any, `pledge` is not called.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] iff `pledge` does.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use priv_sep::{Promise, Promises};
    /// assert!(Promises::new([Promise::Rpath, Promise::Stdio]).remove_promises_then_pledge([Promise::Rpath]).is_ok());
    /// ```
    #[inline]
    pub fn remove_promises_then_pledge<P: AsRef<[Promise]>>(
        &mut self,
        promises: P,
    ) -> Result<(), io::Error> {
        // We opt for the easy way by copying `self`. This should be the fastest for the
        // typical case since `self` likely has very few `Promise`s, and it makes for less code.
        let cur = Self(self.0);
        self.remove_promises(promises);
        if *self == cur {
            Ok(())
        } else {
            self.pledge().inspect_err(|_| *self = cur)
        }
    }
    /// Removes `promise` from `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Promise, Promises};
    /// let mut proms = Promises::new([Promise::Rpath, Promise::Stdio]);
    /// proms.remove(Promise::Stdio);
    /// assert!(proms.len() == 1 && proms.contains(Promise::Rpath));
    /// ```
    #[inline]
    pub fn remove(&mut self, promise: Promise) {
        self.0 &= !promise.to_u64();
    }
    /// Same as [`Self::remove`] then [`Self::pledge`]; however this is "atomic" in that if an error occurs from `pledge`,
    /// `self` is left unchanged. This is useful when one wants to "recover" from an error since there is no
    /// way to add `Promise`s back forcing one to have to create a second `Promises`.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] iff `pledge` does.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use priv_sep::{Promise, Promises};
    /// assert!(Promises::new([Promise::Rpath, Promise::Stdio]).remove_then_pledge(Promise::Rpath).is_ok());
    /// ```
    #[inline]
    pub fn remove_then_pledge(&mut self, promise: Promise) -> Result<(), io::Error> {
        // We opt for the easy way by copying `self`. This should be the fastest for the
        // typical case since `self` likely has very few `Promise`s, and it makes for less code.
        let cur = Self(self.0);
        self.remove(promise);
        if *self == cur {
            Ok(())
        } else {
            self.pledge().inspect_err(|_| *self = cur)
        }
    }
    /// Invokes [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) always passing in
    /// `NULL` for `execpromises` and its contained [`Promise`]s for `promises`.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] iff `pledge(2)` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use priv_sep::{Promise, Promises};
    /// assert!(Promises::new([Promise::Stdio]).pledge().is_ok());
    /// ```
    #[expect(
        unsafe_code,
        reason = "we manually construct a valid CString and ensure its safety"
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "we replace a trailing space with 0 to ensure CString is correctly constructed"
    )]
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "many if blocks to handle each Promise"
    )]
    #[inline]
    pub fn pledge(&self) -> Result<(), io::Error> {
        let mut p = Vec::new();
        if self.contains(Audio) {
            p.extend_from_slice(b"audio ");
        }
        if self.contains(Bpf) {
            p.extend_from_slice(b"bpf ");
        }
        if self.contains(Chown) {
            p.extend_from_slice(b"chown ");
        }
        if self.contains(Cpath) {
            p.extend_from_slice(b"cpath ");
        }
        if self.contains(Disklabel) {
            p.extend_from_slice(b"disklabel ");
        }
        if self.contains(Dns) {
            p.extend_from_slice(b"dns ");
        }
        if self.contains(Dpath) {
            p.extend_from_slice(b"dpath ");
        }
        if self.contains(Drm) {
            p.extend_from_slice(b"drm ");
        }
        if self.contains(Error) {
            p.extend_from_slice(b"error ");
        }
        if self.contains(Exec) {
            p.extend_from_slice(b"exec ");
        }
        if self.contains(Fattr) {
            p.extend_from_slice(b"fattr ");
        }
        if self.contains(Flock) {
            p.extend_from_slice(b"flock ");
        }
        if self.contains(Getpw) {
            p.extend_from_slice(b"getpw ");
        }
        if self.contains(Id) {
            p.extend_from_slice(b"id ");
        }
        if self.contains(Inet) {
            p.extend_from_slice(b"inet ");
        }
        if self.contains(Mcast) {
            p.extend_from_slice(b"mcast ");
        }
        if self.contains(Pf) {
            p.extend_from_slice(b"pf ");
        }
        if self.contains(Proc) {
            p.extend_from_slice(b"proc ");
        }
        if self.contains(ProtExec) {
            p.extend_from_slice(b"prot_exec ");
        }
        if self.contains(Ps) {
            p.extend_from_slice(b"ps ");
        }
        if self.contains(Recvfd) {
            p.extend_from_slice(b"recvfd ");
        }
        if self.contains(Route) {
            p.extend_from_slice(b"route ");
        }
        if self.contains(Rpath) {
            p.extend_from_slice(b"rpath ");
        }
        if self.contains(Sendfd) {
            p.extend_from_slice(b"sendfd ");
        }
        if self.contains(Settime) {
            p.extend_from_slice(b"settime ");
        }
        if self.contains(Stdio) {
            p.extend_from_slice(b"stdio ");
        }
        if self.contains(Tape) {
            p.extend_from_slice(b"tape ");
        }
        if self.contains(Tmppath) {
            p.extend_from_slice(b"tmppath ");
        }
        if self.contains(Tty) {
            p.extend_from_slice(b"tty ");
        }
        if self.contains(Unix) {
            p.extend_from_slice(b"unix ");
        }
        if self.contains(Unveil) {
            p.extend_from_slice(b"unveil ");
        }
        if self.contains(Video) {
            p.extend_from_slice(b"video ");
        }
        if self.contains(Vminfo) {
            p.extend_from_slice(b"vminfo ");
        }
        if self.contains(Vmm) {
            p.extend_from_slice(b"vmm ");
        }
        if self.contains(Wpath) {
            p.extend_from_slice(b"wpath ");
        }
        if self.contains(Wroute) {
            p.extend_from_slice(b"wroute ");
        }
        let idx = p.len();
        if idx == 0 {
            p.push(0);
        } else {
            // All promises have a space after them which means
            // we must replace the last promise's space with
            // 0/nul byte.
            // `idx` is at least 1 based on the above check.
            p[idx - 1] = 0;
        }
        // SAFETY:
        // `p` was populated above with correct ASCII-encoding of the literal
        // values all of which do not have 0 bytes.
        // `p` ends with a 0/nul byte.
        let arg = unsafe { CString::from_vec_with_nul_unchecked(p) };
        pledge(arg.as_ptr())
    }
}
impl PartialEq<&Self> for Promises {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Promises> for &Promises {
    #[inline]
    fn eq(&self, other: &Promises) -> bool {
        **self == *other
    }
}
/// Invokes [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) with `NULL` for
/// both `promises` and `execpromises`.
///
/// # Errors
///
/// Returns [`io::Error`] iff `pledge(2)` errors.
///
/// # Example
///
/// ```no_run
/// use priv_sep;
/// assert!(priv_sep::pledge_none().is_ok());
/// ```
#[inline]
pub fn pledge_none() -> Result<(), io::Error> {
    // `NULL` is always valid for `promises`.
    pledge(ptr::null())
}
/// Invokes `unveil(2)` passing `path` for `path` and `permissions` for `permissions`.
///
/// This function MUST only be called by the functions `Permissions::unveil` and
/// `unveil_no_more`.
#[expect(unsafe_code, reason = "FFI requires unsafe code")]
fn unveil(path: *const c_char, permissions: *const c_char) -> Result<(), io::Error> {
    extern "C" {
        fn unveil(path: *const c_char, permissions: *const c_char) -> c_int;
    }
    // SAFETY:
    // `unveil` is an FFI binding; thus requires unsafe code.
    // `path` and `permissions` meet the requirements of the `unveil(2)` call
    // as can be seen in the only functions that call this function:
    // `Permissions::unveil` and `unveil_no_more`.
    if unsafe { unveil(path, permissions) } == 0i32 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
/// A permission in [`Permissions`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Permission {
    /// [c](https://man.openbsd.org/amd64/unveil.2#c).
    Create,
    /// [x](https://man.openbsd.org/amd64/unveil.2#x).
    Execute,
    /// [r](https://man.openbsd.org/amd64/unveil.2#r).
    Read,
    /// [w](https://man.openbsd.org/amd64/unveil.2#w).
    Write,
}
impl Permission {
    /// Transforms `self` into a `u8`.
    const fn to_u8(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::Execute => 2,
            Self::Read => 4,
            Self::Write => 8,
        }
    }
}
impl PartialEq<&Self> for Permission {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Permission> for &Permission {
    #[inline]
    fn eq(&self, other: &Permission) -> bool {
        **self == *other
    }
}
/// `permissions` to [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Permissions(u8);
impl Permissions {
    /// A `Permissions` with no [`Permission`]s enabled.
    pub const NONE: Self = Self(0);
    /// A `Permissions` with all [`Permission`]s enabled.
    pub const ALL: Self = Self::NONE
        .enable_inner(Permission::Create)
        .enable_inner(Permission::Execute)
        .enable_inner(Permission::Read)
        .enable_inner(Permission::Write);
    /// A `Permissions` with only [`Permission::Create`] enabled.
    pub const CREATE: Self = Self::NONE.enable_inner(Permission::Create);
    /// A `Permissions` with only [`Permission::Execute`] enabled.
    pub const EXECUTE: Self = Self::NONE.enable_inner(Permission::Execute);
    /// A `Permissions` with only [`Permission::Read`] enabled.
    pub const READ: Self = Self::NONE.enable_inner(Permission::Read);
    /// A `Permissions` with only [`Permission::Write`] enabled.
    pub const WRITE: Self = Self::NONE.enable_inner(Permission::Write);
    /// Same as [`enable`] but returns a new instance instead of mutating `self`.
    const fn enable_inner(self, permission: Permission) -> Self {
        Self(self.0 | permission.to_u8())
    }
    /// Enables `permission` in `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Permission, Permissions};
    /// let mut perms = Permissions::NONE;
    /// perms.enable(Permission::Read);
    /// assert_eq!(perms, Permissions::READ);
    /// ```
    #[inline]
    pub fn enable(&mut self, permission: Permission) {
        self.0 |= permission.to_u8();
    }
    /// Disables `permission` in `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Permission, Permissions};
    /// let mut perms = Permissions::ALL;
    /// perms.disable(Permission::Execute);
    /// assert!(
    ///     perms.is_enabled(Permission::Create)
    ///         && perms.is_enabled(Permission::Read)
    ///         && perms.is_enabled(Permission::Write)
    ///         && !perms.is_enabled(Permission::Execute)
    /// );
    /// assert!(perms.is_enabled(Permission::Create) && perms.is_enabled(Permission::Read) && perms.is_enabled(Permission::Write) && !perms.is_enabled(Permission::Execute));
    /// ```
    #[inline]
    pub fn disable(&mut self, permission: Permission) {
        self.0 &= !permission.to_u8();
    }
    /// Returns `true` iff `self` has `permission` enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::{Permission, Permissions};
    /// let perms = Permissions::CREATE;
    /// assert!(perms.is_enabled(Permission::Create));
    /// assert!(!perms.is_enabled(Permission::Write));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_enabled(self, permission: Permission) -> bool {
        let val = permission.to_u8();
        self.0 & val == val
    }
    /// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2)
    /// passing `path` for `path` and the contained permissions for `permissions`.
    ///
    /// # Errors
    ///
    /// Returns [`NulError`] iff [`CString::new`] does.
    /// Returns [`io::Error`] iff `unveil(2)` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::io::ErrorKind;
    /// # use priv_sep::{Permissions, UnveilErr};
    /// assert!(Permissions::READ.unveil("/path/to/read").is_ok());
    /// assert!(Permissions::READ.unveil("/path/does/not/exist").map_or_else(
    ///     |err| match err {
    ///         UnveilErr::Io(e) => e.kind() == ErrorKind::NotFound,
    ///         UnveilErr::Nul(_) => false,
    ///     },
    ///     |()| false
    /// ));
    /// ```
    #[expect(
        unsafe_code,
        reason = "we manually construct a valid CString and ensure its safety"
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "we pre-allocate a Vec with the exact capacity which is capped at 5"
    )]
    #[inline]
    pub fn unveil<P: AsRef<Path>>(self, path: P) -> Result<(), UnveilErr> {
        CString::new(path.as_ref().as_os_str().as_bytes()).map_or_else(
            |e| Err(UnveilErr::Nul(e)),
            |path_c| {
                // The max sum is 5, so overflow is not possible.
                let mut vec = Vec::with_capacity(
                    usize::from(self.is_enabled(Permission::Create))
                        + usize::from(self.is_enabled(Permission::Execute))
                        + usize::from(self.is_enabled(Permission::Read))
                        + usize::from(self.is_enabled(Permission::Write))
                        + 1,
                );
                if self.is_enabled(Permission::Create) {
                    vec.push(b'c');
                }
                if self.is_enabled(Permission::Execute) {
                    vec.push(b'x');
                }
                if self.is_enabled(Permission::Read) {
                    vec.push(b'r');
                }
                if self.is_enabled(Permission::Write) {
                    vec.push(b'w');
                }
                vec.push(0);
                // SAFETY:
                // `vec` was populated above with correct ASCII-encoding of the literal
                // values all of which do not have 0 bytes.
                // `vec` ends with a 0/nul byte.
                let perm_c = unsafe { CString::from_vec_with_nul_unchecked(vec) };
                let path_ptr = path_c.as_ptr();
                let perm_ptr = perm_c.as_ptr();
                unveil(path_ptr, perm_ptr).map_err(UnveilErr::Io)
            },
        )
    }
}
impl Display for Permissions {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unveil(2) '{}{}{}{}' permissions",
            if self.is_enabled(Permission::Create) {
                "c"
            } else {
                ""
            },
            if self.is_enabled(Permission::Execute) {
                "x"
            } else {
                ""
            },
            if self.is_enabled(Permission::Read) {
                "r"
            } else {
                ""
            },
            if self.is_enabled(Permission::Write) {
                "w"
            } else {
                ""
            },
        )
    }
}
impl BitAnd for Permissions {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}
impl BitAnd<&Self> for Permissions {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: &Self) -> Self::Output {
        self & *rhs
    }
}
impl BitAnd<&Permissions> for &Permissions {
    type Output = Permissions;
    #[inline]
    fn bitand(self, rhs: &Permissions) -> Self::Output {
        *self & *rhs
    }
}
impl<'a> BitAnd<Permissions> for &'a Permissions {
    type Output = Permissions;
    #[inline]
    fn bitand(self, rhs: Permissions) -> Self::Output {
        *self & rhs
    }
}
impl BitAndAssign for Permissions {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl BitAndAssign<&Self> for Permissions {
    #[inline]
    fn bitand_assign(&mut self, rhs: &Self) {
        *self &= *rhs;
    }
}
impl BitOr for Permissions {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
impl BitOr<&Self> for Permissions {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: &Self) -> Self::Output {
        self | *rhs
    }
}
impl BitOr<&Permissions> for &Permissions {
    type Output = Permissions;
    #[inline]
    fn bitor(self, rhs: &Permissions) -> Self::Output {
        *self | *rhs
    }
}
impl<'a> BitOr<Permissions> for &'a Permissions {
    type Output = Permissions;
    #[inline]
    fn bitor(self, rhs: Permissions) -> Self::Output {
        *self | rhs
    }
}
impl BitOrAssign for Permissions {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl BitOrAssign<&Self> for Permissions {
    #[inline]
    fn bitor_assign(&mut self, rhs: &Self) {
        *self |= *rhs;
    }
}
impl BitXor for Permissions {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}
impl BitXor<&Self> for Permissions {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: &Self) -> Self::Output {
        self ^ *rhs
    }
}
impl BitXor<&Permissions> for &Permissions {
    type Output = Permissions;
    #[inline]
    fn bitxor(self, rhs: &Permissions) -> Self::Output {
        *self ^ *rhs
    }
}
impl<'a> BitXor<Permissions> for &'a Permissions {
    type Output = Permissions;
    #[inline]
    fn bitxor(self, rhs: Permissions) -> Self::Output {
        *self ^ rhs
    }
}
impl BitXorAssign for Permissions {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
impl BitXorAssign<&Self> for Permissions {
    #[inline]
    fn bitxor_assign(&mut self, rhs: &Self) {
        *self ^= *rhs;
    }
}
impl Not for Permissions {
    type Output = Self;
    #[inline]
    fn not(self) -> Self::Output {
        Self(Self::ALL.0 & !self.0)
    }
}
impl Not for &Permissions {
    type Output = Permissions;
    #[inline]
    fn not(self) -> Self::Output {
        !*self
    }
}
impl PartialEq<&Self> for Permissions {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Permissions> for &Permissions {
    #[inline]
    fn eq(&self, other: &Permissions) -> bool {
        **self == *other
    }
}
/// Error returned by [`Permissions::unveil`].
#[derive(Debug)]
pub enum UnveilErr {
    /// Error propagated from [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2).
    Io(io::Error),
    /// Error when a path cannot be converted into a
    /// [`CString`].
    Nul(NulError),
}
impl Display for UnveilErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Io(ref err) => err.fmt(f),
            Self::Nul(ref e) => write!(
                f,
                "The path passed to 'unveil(2)' was unable to be converted to a CString: {e}"
            ),
        }
    }
}
impl error::Error for UnveilErr {}
/// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) by passing `NULL` for both `path` and `permissions`.
///
/// # Errors
///
/// Returns [`io::Error`] when a problem occurs.
///
/// # Example
///
/// ```no_run
/// use priv_sep;
/// assert!(priv_sep::unveil_no_more().is_ok());
/// ```
#[inline]
pub fn unveil_no_more() -> Result<(), io::Error> {
    // `NULL` is valid for both `path` and `permissions`.
    unveil(ptr::null(), ptr::null())
}
#[cfg(all(test, target_os = "openbsd"))]
mod tests {
    use crate::{Permissions, Promise, Promises};
    use std::fs;
    // We only have one test since we must force the order of pledge/unveil calls.
    #[test]
    #[ignore]
    fn test() {
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
        assert!(crate::pledge_none().is_ok());
        print!("");
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
        assert!(crate::unveil_no_more().is_ok());
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
}
