//! # `priv_sep`
//!
//! `priv_sep` is a library for privilege separation.
//! It is currently designed around [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) and
//! [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) for OpenBSD-stable—that is correct, -stable not -current—but
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
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
#![deny(
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
#![allow(
    clippy::arithmetic_side_effects,
    clippy::blanket_clippy_restriction_lints,
    clippy::exhaustive_structs,
    clippy::implicit_return,
    clippy::into_iter_on_ref,
    clippy::min_ident_chars,
    clippy::missing_trait_methods,
    clippy::single_char_lifetime_names,
    clippy::unseparated_literal_suffix
)]
#![cfg(feature = "openbsd")]
extern crate alloc;
use alloc::ffi::{CString, NulError};
use core::convert::AsRef;
use core::ffi::{c_char, c_int};
use core::fmt::{self, Display, Formatter};
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, Not};
use core::ptr;
use core::slice::Iter;
use std::error;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
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
/// A set of [`Promise`]s that can only have `Promise`s removed after creation.
///
/// Once a set of `promises` has been [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2)d,
/// only a subset of those `promises` can be `pledge(2)`d again, so this type can be used
/// to ensure that `Promise`s are never added but only removed from an initial set.
#[derive(Clone, Copy, Debug)]
pub struct Promises<const CAP: usize> {
    /// The initial set of `Promise`s.
    proms: [Promise; CAP],
    /// The length of `vals`.
    len: usize,
}
/// Invokes `pledge(2)` always passing `NULL` for `execpromises` and
/// `promises` for `promises`.
///
/// This function MUST only be called by `Promises::pledge` and
/// `pledge_none`.
#[allow(unsafe_code)]
#[inline]
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
impl<const CAP: usize> Promises<CAP> {
    /// Returns a `Promises` containing the unique
    /// `Promise`s in `initial`.
    ///
    /// Note that the order of `initial` may
    /// not be retained.
    #[allow(clippy::indexing_slicing)]
    #[inline]
    #[must_use]
    pub fn new(mut initial: [Promise; CAP]) -> Self {
        let mut len = CAP;
        for i in 0..CAP {
            if len > i {
                let mut start = i + 1;
                loop {
                    if len > start {
                        if initial[i] == initial[start] {
                            len -= 1;
                            initial.swap(start, len);
                        } else {
                            start += 1;
                        }
                    } else {
                        break;
                    }
                }
            } else {
                break;
            }
        }
        Self {
            proms: initial,
            len,
        }
    }
    /// Returns the number of [`Promise`]s.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Returns `true` iff there are no [`Promise`]s.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Returns the set of `Promise`s.
    #[inline]
    #[must_use]
    pub fn vals(&self) -> &[Promise] {
        &self.proms[..self.len]
    }
    /// Returns `true` iff `self` contains `promise`.
    #[inline]
    #[must_use]
    pub fn contains(&self, promise: Promise) -> bool {
        self.vals().contains(&promise)
    }
    /// Removes all [`Promise`]s except `promises`.
    ///
    /// Note that the internal order of `Promise`s
    /// may no longer be the same.
    #[inline]
    pub fn retain<P: AsRef<[Promise]>>(&mut self, promises: P) {
        let other = promises.as_ref();
        for i in 0..self.len {
            loop {
                let Some(prom) = self.vals().get(i) else {
                    return;
                };
                if other.contains(prom) {
                    break;
                }
                self.len -= 1;
                self.proms.swap(i, self.len);
            }
        }
    }
    /// Removes `promises` from `self`.
    ///
    /// Note that the internal order of `Promise`s
    /// may no longer be the same.
    #[inline]
    pub fn remove_promises<P: AsRef<[Promise]>>(&mut self, promises: P) {
        promises.as_ref().into_iter().fold((), |(), prom| {
            for (idx, prom2) in self.vals().into_iter().enumerate() {
                if prom == prom2 {
                    self.len -= 1;
                    self.proms.swap(idx, self.len);
                    break;
                }
            }
        });
    }
    /// Removes `promise` from `self` returning `true` iff
    /// `promise` existed.
    ///
    /// Note that the internal order of `Promise`s
    /// may no longer be the same.
    #[inline]
    pub fn remove(&mut self, promise: Promise) -> bool {
        for (idx, prom) in self.vals().into_iter().enumerate() {
            if *prom == promise {
                self.len -= 1;
                self.proms.swap(idx, self.len);
                return true;
            }
        }
        false
    }
    /// Returns an [`Iterator`] without consuming `self`.
    #[inline]
    pub fn iter(&self) -> Iter<'_, Promise> {
        self.vals().into_iter()
    }
    /// Invokes [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) always passing in
    /// `NULL` for `execpromises` and its contained [`Promise`]s for `promises`.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] iff `pledge(2)` errors.
    #[inline]
    #[allow(unsafe_code, clippy::indexing_slicing)]
    pub fn pledge(&self) -> Result<(), io::Error> {
        let mut p = Vec::new();
        self.vals().into_iter().fold((), |(), promise| {
            p.extend_from_slice(match *promise {
                Audio => b"audio ",
                Bpf => b"bpf ",
                Chown => b"chown ",
                Cpath => b"cpath ",
                Disklabel => b"disklabel ",
                Dns => b"dns ",
                Dpath => b"dpath ",
                Drm => b"drm ",
                Error => b"error ",
                Exec => b"exec ",
                Fattr => b"fattr ",
                Flock => b"flock ",
                Getpw => b"getpw ",
                Id => b"id ",
                Inet => b"inet ",
                Mcast => b"mcast ",
                Pf => b"pf ",
                Proc => b"proc ",
                ProtExec => b"prot_exec ",
                Ps => b"ps ",
                Recvfd => b"recvfd ",
                Route => b"route ",
                Rpath => b"rpath ",
                Sendfd => b"sendfd ",
                Settime => b"settime ",
                Stdio => b"stdio ",
                Tape => b"tape ",
                Tmppath => b"tmppath ",
                Tty => b"tty ",
                Unix => b"unix ",
                Unveil => b"unveil ",
                Video => b"video ",
                Vminfo => b"vminfo ",
                Vmm => b"vmm ",
                Wpath => b"wpath ",
                Wroute => b"wroute ",
            });
        });
        let idx = p.len();
        if idx == 0 {
            p.push(0);
        } else {
            // All promises have a space after them which means
            // we must replace the last promise's space with
            // 0/nul byte.
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
impl<const CAP: usize> AsRef<[Promise]> for Promises<CAP> {
    #[inline]
    fn as_ref(&self) -> &[Promise] {
        self.vals()
    }
}
impl<const CAP: usize> Deref for Promises<CAP> {
    type Target = [Promise];
    #[inline]
    fn deref(&self) -> &[Promise] {
        self.vals()
    }
}
impl<const CAP: usize, const CAP2: usize> PartialEq<Promises<CAP2>> for Promises<CAP> {
    #[inline]
    fn eq(&self, other: &Promises<CAP2>) -> bool {
        self.len == other.len
            && self
                .iter()
                .try_fold((), |(), prom| {
                    if other.contains(*prom) {
                        Ok(())
                    } else {
                        Err(())
                    }
                })
                .map_or(false, |()| true)
    }
}
impl<const CAP: usize> Eq for Promises<CAP> {}
/// An [`Iterator`] of [`Promise`]s
pub struct PromIter<const CAP: usize> {
    /// Source of `Promise`s.
    prom: Promises<CAP>,
    /// Current index.
    idx: usize,
}
impl<const CAP: usize> Iterator for PromIter<CAP> {
    type Item = Promise;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.prom.vals().get(self.idx).map(|prom| {
            self.idx += 1;
            *prom
        })
    }
}
impl<const CAP: usize> ExactSizeIterator for PromIter<CAP> {
    #[inline]
    fn len(&self) -> usize {
        self.prom.len - self.idx
    }
}
impl<const CAP: usize> DoubleEndedIterator for PromIter<CAP> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.prom.proms[self.idx..self.prom.len].last().map(|prom| {
            self.prom.len -= 1;
            *prom
        })
    }
}
impl<const CAP: usize> IntoIterator for Promises<CAP> {
    type Item = Promise;
    type IntoIter = PromIter<CAP>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        PromIter { prom: self, idx: 0 }
    }
}
impl<'a, const CAP: usize> IntoIterator for &'a Promises<CAP> {
    type Item = &'a Promise;
    type IntoIter = Iter<'a, Promise>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<const CAP: usize> From<[Promise; CAP]> for Promises<CAP> {
    #[inline]
    fn from(value: [Promise; CAP]) -> Self {
        Self::new(value)
    }
}
/// Invokes [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) with `NULL` for
/// both `promises` and `execpromises`.
///
/// # Errors
///
/// Returns [`io::Error`] iff `pledge(2)` errors.
#[inline]
pub fn pledge_none() -> Result<(), io::Error> {
    // `NULL` is always valid for `promises`.
    pledge(ptr::null())
}
/// Invokes `unveil(2)` passing `path` for `path` and `permissions` for `permissions`.
///
/// This function MUST only be called by the functions `Permissions::unveil` and
/// `unveil_no_more`.
#[allow(unsafe_code)]
#[inline]
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
/// `permissions` to [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2).
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Permissions {
    /// Consult `unveil(2)`.
    pub create: bool,
    /// Consult `unveil(2)`.
    pub execute: bool,
    /// Consult `unveil(2)`.
    pub read: bool,
    /// Consult `unveil(2)`.
    pub write: bool,
}
impl Permissions {
    /// Contains all fields as `true`.
    pub const ALL: Self = Self {
        create: true,
        execute: true,
        read: true,
        write: true,
    };
    /// Contains all fields as `false`.
    pub const NONE: Self = Self {
        create: false,
        execute: false,
        read: false,
        write: false,
    };
    /// A `Permissions` with only [`Permissions::create`] set to `true`.
    pub const CREATE: Self = Self {
        create: true,
        execute: false,
        read: false,
        write: false,
    };
    /// A `Permissions` with only [`Permissions::execute`] set to `true`.
    pub const EXECUTE: Self = Self {
        create: false,
        execute: true,
        read: false,
        write: false,
    };
    /// A `Permissions` with only [`Permissions::read`] set to `true`.
    pub const READ: Self = Self {
        create: false,
        execute: false,
        read: true,
        write: false,
    };
    /// A `Permissions` with only [`Permissions::write`] set to `true`.
    pub const WRITE: Self = Self {
        create: false,
        execute: false,
        read: false,
        write: true,
    };
    /// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2)
    /// passing `path` for `path` and the contained permissions for `permissions`.
    ///
    /// # Errors
    ///
    /// Returns [`NulError`] iff [`CString::new`] does.
    /// Returns [`io::Error`] iff `unveil(2)` errors.
    #[inline]
    #[allow(unsafe_code)]
    pub fn unveil<P: AsRef<Path>>(self, path: P) -> Result<(), UnveilErr> {
        let mut vec = Vec::new();
        if self.create {
            vec.push(b'c');
        }
        if self.execute {
            vec.push(b'x');
        }
        if self.read {
            vec.push(b'r');
        }
        if self.write {
            vec.push(b'w');
        }
        vec.push(0);
        CString::new(path.as_ref().as_os_str().as_bytes()).map_or_else(
            |e| Err(UnveilErr::Nul(e)),
            |path_c| {
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
            if self.create { "c" } else { "" },
            if self.execute { "x" } else { "" },
            if self.read { "r" } else { "" },
            if self.write { "w" } else { "" },
        )
    }
}
impl BitAnd<Self> for Permissions {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            create: self.create & rhs.create,
            execute: self.execute & rhs.execute,
            read: self.read & rhs.read,
            write: self.write & rhs.write,
        }
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
impl BitAndAssign<Self> for Permissions {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.create &= rhs.create;
        self.execute &= rhs.execute;
        self.read &= rhs.read;
        self.write &= rhs.write;
    }
}
impl BitAndAssign<&Self> for Permissions {
    #[inline]
    fn bitand_assign(&mut self, rhs: &Self) {
        *self &= *rhs;
    }
}
impl BitOr<Self> for Permissions {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            create: self.create | rhs.create,
            execute: self.execute | rhs.execute,
            read: self.read | rhs.read,
            write: self.write | rhs.write,
        }
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
impl BitOrAssign<Self> for Permissions {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.create |= rhs.create;
        self.execute |= rhs.execute;
        self.read |= rhs.read;
        self.write |= rhs.write;
    }
}
impl BitOrAssign<&Self> for Permissions {
    #[inline]
    fn bitor_assign(&mut self, rhs: &Self) {
        *self |= *rhs;
    }
}
impl BitXor<Self> for Permissions {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self {
            create: self.create ^ rhs.create,
            execute: self.execute ^ rhs.execute,
            read: self.read ^ rhs.read,
            write: self.write ^ rhs.write,
        }
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
impl BitXorAssign<Self> for Permissions {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.create ^= rhs.create;
        self.execute ^= rhs.execute;
        self.read ^= rhs.read;
        self.write ^= rhs.write;
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
        Self {
            create: !self.create,
            execute: !self.execute,
            read: !self.read,
            write: !self.write,
        }
    }
}
impl Not for &Permissions {
    type Output = Permissions;
    #[inline]
    fn not(self) -> Self::Output {
        !*self
    }
}
/// Error returned by [`Permissions::unveil`].
#[allow(clippy::exhaustive_enums)]
#[derive(Debug)]
pub enum UnveilErr {
    /// Error propagated from [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2).
    Io(io::Error),
    /// Error when a path cannot be converted into a
    /// [`CString`].
    Nul(NulError),
}
impl Display for UnveilErr {
    #[allow(clippy::ref_patterns)]
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
        _ = fs::metadata(FILE_NOT_EXISTS)
            .expect_err(format!("{FILE_NOT_EXISTS} exists, so unit testing cannot occur").as_str());
        const DIR_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23/";
        _ = fs::metadata(DIR_NOT_EXISTS)
            .expect_err(format!("{DIR_NOT_EXISTS} exists, so unit testing cannot occur").as_str());
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
            vals.len() == 2
                && vals.contains(Promise::Chown)
                && vals.vals().contains(&Promise::Error)
        });
        // This tests iteration.
        // After "removal" of duplicates,
        // this should be [Stdio, Unveil, Error, Rpath] in
        // some order.
        let mut proms = Promises::new([
            Promise::Unveil,
            Promise::Unveil,
            Promise::Stdio,
            Promise::Unveil,
            Promise::Unveil,
            Promise::Rpath,
            Promise::Error,
            Promise::Stdio,
            Promise::Rpath,
            Promise::Error,
        ])
        .into_iter();
        assert!(proms.len() == 4);
        let mut unveil = false;
        let mut stdio = false;
        let mut rpath = false;
        let mut error = false;
        let mut closure = |prom: Promise| -> bool {
            match prom {
                Promise::Unveil => {
                    if unveil {
                        return false;
                    } else {
                        unveil = true;
                        true
                    }
                }
                Promise::Rpath => {
                    if rpath {
                        return false;
                    } else {
                        rpath = true;
                        true
                    }
                }
                Promise::Error => {
                    if error {
                        return false;
                    } else {
                        error = true;
                        true
                    }
                }
                Promise::Stdio => {
                    if stdio {
                        return false;
                    } else {
                        stdio = true;
                        true
                    }
                }
                _ => false,
            }
        };
        assert!(proms.next().map_or(false, &mut closure));
        assert!(proms.len() == 3);
        assert!(proms.next_back().map_or(false, &mut closure));
        assert!(proms.len() == 2);
        assert!(proms.next_back().map_or(false, &mut closure));
        assert!(proms.len() == 1);
        assert!(proms.next().map_or(false, &mut closure));
        assert!(proms.len() == 0);
        assert!(unveil && stdio && error && rpath);
        assert!(proms.next().is_none());
        assert!(proms.next_back().is_none());
        assert!(proms.next().is_none());
        assert!(proms.next_back().is_none());
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
        assert!(initial_promises.remove(Promise::Rpath));
        assert!(!initial_promises.remove(Promise::Rpath));
        assert!(initial_promises.pledge().is_ok());
        print!("");
        assert!(Promises::new([Promise::Rpath]).pledge().is_err());
        // If the below is uncommented, the program should crash since the above
        // call to pledge no longer allows access to the file system.
        //_ = fs::metadata(FILE_EXISTS);
    }
}
