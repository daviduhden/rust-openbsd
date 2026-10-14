//! [`chroot(2)`](https://man.openbsd.org/chroot.2): change the filesystem
//! root.
//!
//! `chroot(2)` changes the root directory used to resolve absolute pathnames.
//! It is **not** a complete sandbox:
//!
//! * it only changes filesystem pathname resolution;
//! * it requires superuser privileges ([`Errno::EPERM`] otherwise);
//! * it does not replace `pledge(2)`, `unveil(2)`, or privilege dropping;
//! * a process that still holds root may be able to escape the new root;
//! * already-open file descriptors keep access to resources outside the new
//!   root.
//!
//! Privilege dropping should normally follow `chroot(2)`, and `chroot(2)` is
//! not covered by any pledge promise: it must be performed *before* pledging.

use core::ffi::CStr;

use crate::{
    cstr::CStrHelper,
    error::Errno,
    ffi::{self, SUCCESS},
};

/// The raw [`chdir(2)`](https://man.openbsd.org/chdir.2) call on an already
/// converted path.
#[expect(unsafe_code, reason = "chdir(2) takes a raw pointer")]
fn chdir_raw(path: &CStr) -> Result<(), Errno> {
    // SAFETY:
    // `path` is a valid, NUL-terminated string borrowed for the duration of the call.
    // `chdir(2)` only reads it.
    if unsafe { ffi::chdir(path.as_ptr()) } == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Changes the current working directory, as
/// [`chdir(2)`](https://man.openbsd.org/chdir.2).
///
/// The path is accepted through [`CStrHelper`], so it may be a
/// [`Path`](std::path::Path), an [`OsStr`](std::ffi::OsStr), a [`str`], or a
/// raw byte slice, and need not be valid UTF-8. It must not contain an interior
/// NUL byte.
///
/// # Errors
///
/// Errors if `chdir(2)` does.
///
/// # Examples
///
/// ```no_run
/// # use openbsd_rust::chdir;
/// assert!(chdir("/").is_ok());
/// ```
pub fn chdir<P: CStrHelper>(path: P) -> Result<(), Errno> {
    path.convert_then_apply(chdir_raw)
}

/// The raw [`chroot(2)`](https://man.openbsd.org/chroot.2) call.
///
/// This does not change the current working directory, so an open `".."` can
/// leave the new root when the process was not already chrooted. Prefer
/// [`enter_chroot`] for the security-sensitive transition.
///
/// The path must not contain an interior NUL byte.
///
/// # Errors
///
/// Errors if `chroot(2)` does. [`Errno::EPERM`] without sufficient privileges.
///
/// # Examples
///
/// ```no_run
/// # use openbsd_rust::chroot;
/// assert!(chroot("/var/empty").is_ok());
/// ```
#[expect(unsafe_code, reason = "chroot(2) takes a raw pointer")]
pub fn chroot<P: CStrHelper>(path: P) -> Result<(), Errno> {
    path.convert_then_apply(|path| {
        // SAFETY:
        // `path` is a valid, NUL-terminated string borrowed for the duration of the call.
        // `chroot(2)` only reads it.
        if unsafe { ffi::chroot(path.as_ptr()) } == SUCCESS {
            Ok(())
        } else {
            Err(Errno::last())
        }
    })
}

/// Performs the security-sensitive chroot transition `chroot(path)` followed by
/// `chdir("/")`.
///
/// Changing the working directory to the new root closes the classic `".."`
/// escape that [`chroot`] alone leaves open.
///
/// The transition is irreversible and only partially protected on failure: if
/// `chroot(2)` succeeds but `chdir(2)` fails, the process is already inside the
/// new root and cannot simply be restored. Any error from this function must
/// therefore be treated as fatal for the current process.
///
/// # Errors
///
/// Errors if [`chroot`] or [`chdir`] does.
///
/// # Examples
///
/// ```no_run
/// # use openbsd_rust::enter_chroot;
/// assert!(enter_chroot("/var/empty").is_ok());
/// ```
pub fn enter_chroot<P: CStrHelper>(path: P) -> Result<(), Errno> {
    chroot(path).and_then(|()| chdir_raw(c"/"))
}
