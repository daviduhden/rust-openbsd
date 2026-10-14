//! Minimal native OpenBSD interfaces used by this crate.
//!
//! Everything here is a direct `extern "C"` declaration; the crate does not
//! depend on a platform-bindings crate. The `unsafe` surface is intentionally
//! tiny: functions that cannot dereference a pointer are declared `safe`, and
//! the rest are wrapped once, with documented safety invariants, in the
//! modules that use them.
//!
//! The [`Passwd`] layout matches OpenBSD's
//! [`<pwd.h>`](https://github.com/openbsd/src/blob/master/include/pwd.h).

use core::ffi::{c_char, c_int};

/// Return value of a successful libc call.
pub(crate) const SUCCESS: c_int = 0;

/// `struct passwd` as defined by OpenBSD's `<pwd.h>`.
///
/// Only the fields this crate reads are exposed; the layout must match the C
/// definition exactly because the structure is filled in by
/// [`getpwnam_r`](ffi::getpwnam_r) and [`getpwuid_r`](ffi::getpwuid_r).
#[repr(C)]
pub(crate) struct Passwd {
    /// Login name.
    pub(crate) name: *mut c_char,
    /// Encrypted password.
    pub(crate) passwd: *mut c_char,
    /// User ID.
    pub(crate) uid: u32,
    /// Primary group ID.
    pub(crate) gid: u32,
    /// Password change time.
    pub(crate) change: i64,
    /// Login class.
    pub(crate) class: *mut c_char,
    /// User information.
    pub(crate) gecos: *mut c_char,
    /// Home directory.
    pub(crate) dir: *mut c_char,
    /// Shell program.
    pub(crate) shell: *mut c_char,
    /// Account expiration.
    pub(crate) expire: i64,
}

#[expect(
    unsafe_code,
    reason = "the FFI declarations themselves require an `unsafe extern` block"
)]
unsafe extern "C" {
    /// [`getuid(2)`](https://man.openbsd.org/getuid.2).
    pub(crate) safe fn getuid() -> u32;

    /// [`geteuid(2)`](https://man.openbsd.org/geteuid.2).
    pub(crate) safe fn geteuid() -> u32;

    /// [`getgid(2)`](https://man.openbsd.org/getgid.2).
    pub(crate) safe fn getgid() -> u32;

    /// [`getegid(2)`](https://man.openbsd.org/getegid.2).
    pub(crate) safe fn getegid() -> u32;

    /// [`setresuid(2)`](https://man.openbsd.org/setresuid.2).
    pub(crate) safe fn setresuid(ruid: u32, euid: u32, suid: u32) -> c_int;

    /// [`setresgid(2)`](https://man.openbsd.org/setresgid.2).
    pub(crate) safe fn setresgid(rgid: u32, egid: u32, sgid: u32) -> c_int;

    /// [`getresuid(2)`](https://man.openbsd.org/getresuid.2).
    pub(crate) fn getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> c_int;

    /// [`getresgid(2)`](https://man.openbsd.org/getresgid.2).
    pub(crate) fn getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> c_int;

    /// [`setgroups(2)`](https://man.openbsd.org/setgroups.2).
    pub(crate) fn setgroups(size: c_int, gids: *const u32) -> c_int;

    /// [`getgroups(2)`](https://man.openbsd.org/getgroups.2).
    pub(crate) fn getgroups(size: c_int, gids: *mut u32) -> c_int;

    /// [`initgroups(3)`](https://man.openbsd.org/initgroups.3).
    pub(crate) fn initgroups(name: *const c_char, basegid: u32) -> c_int;

    /// [`chroot(2)`](https://man.openbsd.org/chroot.2).
    pub(crate) fn chroot(path: *const c_char) -> c_int;

    /// [`chdir(2)`](https://man.openbsd.org/chdir.2).
    pub(crate) fn chdir(path: *const c_char) -> c_int;

    /// [`getpwnam_r(3)`](https://man.openbsd.org/getpwnam_r.3).
    pub(crate) fn getpwnam_r(
        name: *const c_char,
        pwd: *mut Passwd,
        buf: *mut c_char,
        size: usize,
        result: *mut *mut Passwd,
    ) -> c_int;

    /// [`pledge(2)`](https://man.openbsd.org/pledge.2).
    pub(crate) fn pledge(promises: *const c_char, execpromises: *const c_char) -> c_int;

    /// [`unveil(2)`](https://man.openbsd.org/unveil.2).
    pub(crate) fn unveil(path: *const c_char, permissions: *const c_char) -> c_int;

    /// [`__errno`](https://github.com/openbsd/src/blob/master/include/errno.h).
    pub(crate) fn __errno() -> *mut c_int;
}
