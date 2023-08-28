//! # `priv_sep`  
//!  
//! `priv_sep` is a library for privilege separation.
//! It is currently designed around [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) and
//! [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) for OpenBSD-stable—that is correct, -stable not -current—
//! but in the future may contain functionality for Linux's
//! [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html).  
//!  
//! ## Pledge  
//!  
//! It is very rare to use the `execpromises` parameter, so [`pledge`] only relies on [`Promise`]s.  
//!  
//! ## Unveil  
//!  
//! Unlike `pledge(2)` which allows a large quantity of duplicate `promises` to be provided, `unveil(2)` allows a maximum
//! of four `permissions` to be passed. For this reason, there are dedicated functions for each quantity of
//! [`Permission`]s.  
//!  
//! ## Errors  
//!  
//! Any error returned from the underlying system call is propagated via
//! [`c_int`](https://doc.rust-lang.org/core/ffi/type.c_int.html). Note for both `pledge(2)` and `unveil(2)` duplicates
//! are ignored, so it is not an error to pass in duplicate values for their corresponding functions in this crate.  
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
    clippy::implicit_return,
    clippy::missing_trait_methods,
    clippy::min_ident_chars,
    clippy::unseparated_literal_suffix
)]
#![cfg(feature = "openbsd")]
extern crate alloc;
use alloc::ffi::{CString, NulError};
use core::ffi::{c_char, c_int};
use core::fmt::{self, Display, Formatter};
use core::ptr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use Promise::{
    Audio, Bpf, Chown, Cpath, Disklabel, Dns, Dpath, Drm, Error, Exec, Fattr, Flock, Getpw, Id,
    Inet, Mcast, Pf, Proc, ProtExec, Ps, Recvfd, Route, Rpath, Sendfd, Settime, Stdio, Tape,
    Tmppath, Tty, Unix, Unveil, Video, Vminfo, Vmm, Wpath, Wroute,
};
#[non_exhaustive]
#[derive(Clone, Copy)]
/// A `promise` to [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2).
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
/// Invokes [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) always passing in
/// `NULL` for `execpromises`. When `None` is passed, then `NULL` is passed for `promises`. When `Some([])`
/// is passed, then `""` is passed for `promises`. Like the system call it wraps, duplicates are ignored.
///
/// # Errors
///
/// Will return [`c_int`](https://doc.rust-lang.org/stable/core/ffi/type.c_int.html) iff
/// `pledge(2)` does.
#[inline]
#[allow(unsafe_code, clippy::indexing_slicing, clippy::option_if_let_else)]
pub fn pledge<const N: usize>(promises: Option<[Promise; N]>) -> Result<(), c_int> {
    extern "C" {
        fn pledge(promises: *const c_char, execpromises: *const c_char) -> c_int;
    }
    let arg: CString;
    let ptr = if let Some(prom) = promises {
        let mut p = Vec::new();
        prom.into_iter().fold((), |_, promise| {
            p.extend_from_slice(match promise {
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
        // p was populated above with correct ASCII-encoding of the literal
        // values all of which do not have 0 bytes.
        // p ends with a 0/nul byte.
        arg = unsafe { CString::from_vec_with_nul_unchecked(p) };
        arg.as_ptr()
    } else {
        ptr::null()
    };
    // SAFETY:
    // pledge is an FFI binding; thus requires unsafe code.
    // ptr meets the requirements of the pledge(2) call.
    match unsafe { pledge(ptr, ptr::null()) } {
        0i32 => Ok(()),
        c => Err(c),
    }
}
/// A `permission` to [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2).
#[allow(clippy::exhaustive_enums)]
#[derive(Clone, Copy)]
pub enum Permission {
    /// Consult `unveil(2)`.
    Create,
    /// Consult `unveil(2)`.
    Execute,
    /// Consult `unveil(2)`.
    Read,
    /// Consult `unveil(2)`.
    Write,
}
/// Error returned by the `unveil` functions.
#[allow(clippy::exhaustive_enums)]
#[derive(Debug)]
pub enum UnveilErr {
    /// Error propagated from [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2).
    CInt(c_int),
    /// Error when a path cannot be converted into a
    /// [`CString`](https://doc.rust-lang.org/alloc/ffi/struct.CString.html).
    NulError(NulError),
}
impl Display for UnveilErr {
    #[allow(clippy::ref_patterns)]
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::CInt(c) => write!(
                f,
                "The following error was returned when calling 'unveil(2)': {c}"
            ),
            Self::NulError(ref e) => write!(
                f,
                "The path passed to 'unveil(2)' was unable to be converted to a CString: {e}"
            ),
        }
    }
}
impl std::error::Error for UnveilErr {}
/// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2).
///
/// # Errors
///
/// Will return [`c_int`](https://doc.rust-lang.org/stable/core/ffi/type.c_int.html) iff
/// `unveil(2)` does. Returns [`NulError`](https://doc.rust-lang.org/alloc/ffi/struct.NulError.html)
/// iff [`CString::new`](https://doc.rust-lang.org/alloc/ffi/struct.CString.html#method.new) does.
/// This is a private function and uses `Option` for the path to indicate calling `unveil(2)` with
/// two `NULL` arguments.
#[inline]
#[allow(unsafe_code, clippy::indexing_slicing)]
fn unveil<P: AsRef<Path>, const N: usize>(
    path: Option<P>,
    permissions: [Permission; N],
) -> Result<(), UnveilErr> {
    extern "C" {
        fn unveil(path: *const c_char, permissions: *const c_char) -> c_int;
    }
    let path_c: CString;
    let perm_c: CString;
    let (fst, snd) = if let Some(p) = path {
        let mut v = Vec::new();
        permissions.into_iter().fold((), |_, perm| {
            v.push(match perm {
                Permission::Create => b'c',
                Permission::Execute => b'x',
                Permission::Read => b'r',
                Permission::Write => b'w',
            });
        });
        v.push(0);
        match CString::new(p.as_ref().as_os_str().as_bytes()) {
            Ok(s) => {
                path_c = s;
                // SAFETY:
                // v was populated above with correct ASCII-encoding of the literal
                // values all of which do not have 0 bytes.
                // v ends with a 0/nul byte.
                perm_c = unsafe { CString::from_vec_with_nul_unchecked(v) };
                (path_c.as_ptr(), perm_c.as_ptr())
            }
            Err(e) => return Err(UnveilErr::NulError(e)),
        }
    } else {
        (ptr::null(), ptr::null())
    };
    // SAFETY:
    // unveil is an FFI binding; thus requires unsafe code.
    // fst and snd meet the requirements of the unveil(2) call.
    match unsafe { unveil(fst, snd) } {
        0i32 => Ok(()),
        c => Err(UnveilErr::CInt(c)),
    }
}
/// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) by passing `NULL` for both `path` and `permissions`.
///
/// # Errors
///
/// Will return [`c_int`](https://doc.rust-lang.org/stable/core/ffi/type.c_int.html) iff
/// `unveil(2)` does.
#[allow(clippy::unreachable)]
#[inline]
pub fn unveil_no_more() -> Result<(), c_int> {
    unveil::<PathBuf, 0>(None, []).map_err(|e| match e {
        UnveilErr::CInt(c) => c,
        UnveilErr::NulError(_) => unreachable!("There is a bug in unveil."),
    })
}
/// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) by passing `path` for `path` and `""` for `permissions`.
///
/// # Errors
///
/// Returns [`UnveilErr`] when a problem occurs.
#[inline]
pub fn unveil_no_perms<P: AsRef<Path>>(path: P) -> Result<(), UnveilErr> {
    unveil(Some(path), [])
}
/// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) by passing `path` for `path` and `perm` for `permissions`.
///
/// # Errors
///
/// Returns [`UnveilErr`] when a problem occurs.
#[inline]
pub fn unveil_one_perm<P: AsRef<Path>>(path: P, perm: Permission) -> Result<(), UnveilErr> {
    unveil(Some(path), [perm])
}
/// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) by passing `path` for `path` and `perms` for `permissions`.
///
/// # Errors
///
/// Returns [`UnveilErr`] when a problem occurs.
#[inline]
pub fn unveil_two_perms<P: AsRef<Path>>(path: P, perms: [Permission; 2]) -> Result<(), UnveilErr> {
    unveil(Some(path), perms)
}
/// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) by passing `path` for `path` and `perms` for `permissions`.
///
/// # Errors
///
/// Returns [`UnveilErr`] when a problem occurs.
#[inline]
pub fn unveil_three_perms<P: AsRef<Path>>(
    path: P,
    perms: [Permission; 3],
) -> Result<(), UnveilErr> {
    unveil(Some(path), perms)
}
/// Invokes [`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) by passing `path` for `path` and `"cxrw"` for `permissions`.
///
/// # Errors
///
/// Returns [`UnveilErr`] when a problem occurs.
#[inline]
pub fn unveil_all_perms<P: AsRef<Path>>(path: P) -> Result<(), UnveilErr> {
    unveil(
        Some(path),
        [
            Permission::Create,
            Permission::Execute,
            Permission::Read,
            Permission::Write,
        ],
    )
}
#[cfg(all(test, target_os = "openbsd"))]
mod tests {
    use super::{Permission, Promise};
    // We only have one test since we must force the order of pledge/unveil calls.
    // The file /home/zack/foo.txt must exist before calling.
    // The file /home/zack/aadkjfasj3s23.2lk3h and the directory /home/zack/aadkjfasj3s23/2lk3h
    // must not exist before calling.
    #[test]
    fn test() {
        // This tests that a NULL pledge does nothing.
        assert!(super::pledge::<0>(None).is_ok());
        print!("");
        // This tests that duplicate pledges are ignored.
        assert!(super::pledge(Some([
            Promise::Stdio,
            Promise::Stdio,
            Promise::Unveil,
            Promise::Rpath
        ]))
        .is_ok());
        print!("");
        // This tests unveil with no permissions.
        assert!(super::unveil_no_perms("/home/zack/foo.txt").is_ok());
        assert!(std::fs::metadata("/home/zack/foo.txt").is_err());
        // This tests unveil with read permissions, duplicates are ignored,
        // and one can unveil more permissions (unlike pledge which can only remove promises).
        assert!(super::unveil_two_perms(
            "/home/zack/foo.txt",
            [Permission::Read, Permission::Read]
        )
        .is_ok());
        assert!(std::fs::metadata("/home/zack/foo.txt").is_ok());
        // This tests that calls to unveil on missing files don't error.
        assert!(super::unveil_no_perms("/home/zack/aadkjfasj3s23.2lk3h").is_ok());
        // This tests that calls to unveil on missing directories error.
        assert!(super::unveil_no_perms("/home/zack/aadkjfasj3s23/2lk3h").is_err());
        // This tests that unveil can no longer be called.
        assert!(super::unveil_no_more().is_ok());
        assert!(super::unveil_no_perms("/home/zack/foo.txt").is_err());
        assert!(std::fs::metadata("/home/zack/foo.txt").is_ok());
        // The below tests that Promises can only be removed and not added.
        assert!(super::pledge(Some([Promise::Stdio])).is_ok());
        assert!(super::pledge(Some([Promise::Rpath])).is_err());
        // If the below is uncommented, the program should crash since the above
        // call to pledge no longer allows access to the file system.
        //_ = std::fs::metadata("/home/zack/foo.txt");
    }
}
