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

use core::ffi::{c_char, c_int, c_void};

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

    /// [`issetugid(2)`](https://man.openbsd.org/issetugid.2).
    pub(crate) safe fn issetugid() -> c_int;

    /// [`getpeereid(3)`](https://man.openbsd.org/getpeereid.3).
    pub(crate) fn getpeereid(fd: c_int, euid: *mut u32, egid: *mut u32) -> c_int;

    /// [`arc4random(3)`](https://man.openbsd.org/arc4random.3).
    pub(crate) safe fn arc4random() -> u32;

    /// [`arc4random_buf(3)`](https://man.openbsd.org/arc4random.3).
    pub(crate) fn arc4random_buf(buf: *mut c_void, n: usize);

    /// [`arc4random_uniform(3)`](https://man.openbsd.org/arc4random.3).
    pub(crate) safe fn arc4random_uniform(upper_bound: u32) -> u32;

    /// [`getentropy(2)`](https://man.openbsd.org/getentropy.2).
    pub(crate) fn getentropy(buf: *mut c_void, n: usize) -> c_int;

    /// [`mimmutable(2)`](https://man.openbsd.org/mimmutable.2).
    pub(crate) fn mimmutable(addr: *mut c_void, len: usize) -> c_int;

    /// [`explicit_bzero(3)`](https://man.openbsd.org/explicit_bzero.3).
    pub(crate) fn explicit_bzero(buf: *mut c_void, len: usize);

    /// [`freezero(3)`](https://man.openbsd.org/freezero.3).
    pub(crate) fn freezero(buf: *mut c_void, len: usize);

    /// [`timingsafe_bcmp(3)`](https://man.openbsd.org/timingsafe_bcmp.3).
    pub(crate) fn timingsafe_bcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int;

    /// [`timingsafe_memcmp(3)`](https://man.openbsd.org/timingsafe_memcmp.3).
    pub(crate) fn timingsafe_memcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int;

    /// [`getrtable(2)`](https://man.openbsd.org/getrtable.2).
    pub(crate) safe fn getrtable() -> c_int;

    /// [`setrtable(2)`](https://man.openbsd.org/setrtable.2).
    pub(crate) safe fn setrtable(table: c_int) -> c_int;

    /// [`setproctitle(3)`](https://man.openbsd.org/setproctitle.3).
    ///
    /// Variadic, like the C function. Callers must always pass a fixed `"%s"`
    /// format and the title as the data argument, as
    /// [`set_proctitle`](crate::process::set_proctitle) does.
    pub(crate) fn setproctitle(fmt: *const c_char, ...);

    /// [`getprogname(3)`](https://man.openbsd.org/setprogname.3).
    pub(crate) safe fn getprogname() -> *const c_char;

    /// [`setprogname(3)`](https://man.openbsd.org/setprogname.3).
    ///
    /// The native implementation stores the pointer, so `name` must remain
    /// valid for the rest of the process lifetime.
    pub(crate) fn setprogname(name: *const c_char);

    /// [`closefrom(2)`](https://man.openbsd.org/closefrom.2).
    pub(crate) safe fn closefrom(lowfd: c_int);

    /// [`getdtablecount(2)`](https://man.openbsd.org/getdtablecount.2).
    pub(crate) safe fn getdtablecount() -> c_int;

    /// [`crypt_checkpass(3)`](https://man.openbsd.org/crypt_checkpass.3).
    pub(crate) fn crypt_checkpass(password: *const c_char, hash: *const c_char) -> c_int;

    /// [`crypt_newhash(3)`](https://man.openbsd.org/crypt_newhash.3).
    pub(crate) fn crypt_newhash(
        password: *const c_char,
        pref: *const c_char,
        buf: *mut c_char,
        buflen: usize,
    ) -> c_int;

    /// [`bcrypt_pbkdf(3)`](https://man.openbsd.org/bcrypt_pbkdf.3).
    pub(crate) fn bcrypt_pbkdf(
        pass: *const c_void,
        passlen: usize,
        salt: *const c_void,
        saltlen: usize,
        key: *mut c_void,
        keylen: usize,
        rounds: u32,
    ) -> c_int;

    /// [`fork(2)`](https://man.openbsd.org/fork.2).
    pub(crate) safe fn fork() -> c_int;

    /// [`setsid(2)`](https://man.openbsd.org/setsid.2).
    pub(crate) safe fn setsid() -> c_int;

    /// [`dup2(2)`](https://man.openbsd.org/dup2.2).
    pub(crate) safe fn dup2(from: c_int, to: c_int) -> c_int;

    /// [`close(2)`](https://man.openbsd.org/close.2).
    pub(crate) fn close(fd: c_int) -> c_int;

    /// [`open(2)`](https://man.openbsd.org/open.2).
    ///
    /// Variadic, like the C function; the two-argument form is used here.
    pub(crate) fn open(path: *const c_char, flags: c_int, ...) -> c_int;

    /// [`_exit(2)`](https://man.openbsd.org/_exit.2).
    pub(crate) safe fn _exit(status: c_int) -> !;
}
