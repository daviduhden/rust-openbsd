use super::{Gid, Uid, UserInfo};
use core::ffi::{c_char, c_int};
/// Error code when a libc call is successful.
pub(crate) const SUCCESS: c_int = 0;
/// `time_t`.
#[cfg(all(
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_vendor = "apple"
    ),
    target_arch = "aarch64",
    target_pointer_width = "32"
))]
type TimeT = i32;
/// `time_t`.
#[cfg(all(
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_vendor = "apple"
    ),
    not(all(target_arch = "aarch64", target_pointer_width = "32"))
))]
type TimeT = i64;
/// [`passwd`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/basedefs/pwd.h.html).
#[repr(C)]
pub(crate) struct Passwd {
    /// Username.
    name: *mut c_char,
    /// User password.
    pass: *mut c_char,
    /// User ID.
    uid: u32,
    /// Group ID.
    gid: u32,
    /// Password change time.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_vendor = "apple"
    ))]
    change: TimeT,
    /// User access class.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_vendor = "apple"
    ))]
    class: *mut c_char,
    /// User information.
    gecos: *mut c_char,
    /// Home directory.
    dir: *mut c_char,
    /// Shell program.
    shell: *mut c_char,
    /// Account expiration.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_vendor = "apple"
    ))]
    expire: TimeT,
    /// Internal fields.
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
    fields: c_int,
}
impl Passwd {
    /// Returns `UserInfo` based on the contained user and group IDs.
    pub(crate) const fn into_user_info(self) -> UserInfo {
        UserInfo {
            uid: Uid(self.uid),
            gid: Gid(self.gid),
        }
    }
}
#[expect(unsafe_code, reason = "FFI requires unsafe")]
unsafe extern "C" {
    /// [`getuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getuid.html).
    pub(crate) safe fn getuid() -> u32;
    /// [`geteuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/geteuid.html).
    pub(crate) safe fn geteuid() -> u32;
    /// [`getgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getgid.html).
    pub(crate) safe fn getgid() -> u32;
    /// [`getegid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getegid.html).
    pub(crate) safe fn getegid() -> u32;
    /// [`setresuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresuid.html).
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "openbsd"
    ))]
    pub(crate) safe fn setresuid(ruid: u32, euid: u32, suid: u32) -> c_int;
    /// [`setuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setuid.html#).
    #[cfg(any(target_os = "netbsd", target_vendor = "apple"))]
    pub(crate) safe fn setuid(uid: u32) -> c_int;
    /// [`setresgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresgid.html).
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "openbsd"
    ))]
    pub(crate) safe fn setresgid(rgid: u32, egid: u32, sgid: u32) -> c_int;
    /// [`setgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setgid.html#).
    #[cfg(any(target_os = "netbsd", target_vendor = "apple"))]
    pub(crate) safe fn setgid(gid: u32) -> c_int;
    /// [`chroot(2)`](https://manned.org/chroot.2).
    pub(crate) fn chroot(path: *const c_char) -> c_int;
    /// [`chdir`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/chdir.html).
    pub(crate) fn chdir(path: *const c_char) -> c_int;
    /// [`getpwnam_r`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getpwnam_r.html).
    pub(crate) fn getpwnam_r(
        name: *const c_char,
        pwd: *mut Passwd,
        buf: *mut c_char,
        size: usize,
        result: *mut *mut Passwd,
    ) -> c_int;
    /// [`getpwuid_r`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getpwuid_r.html).
    pub(crate) fn getpwuid_r(
        uid: u32,
        pwd: *mut Passwd,
        buf: *mut c_char,
        size: usize,
        result: *mut *mut Passwd,
    ) -> c_int;
    /// [`setgroups(2)`](https://man.openbsd.org/setgroups.2).
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    pub(crate) fn setgroups(size: c_int, gids: *const u32) -> c_int;
    /// [`setgroups(2)`](https://www.man7.org/linux/man-pages/man2/setgroups.2.html).
    #[cfg(target_os = "linux")]
    pub(crate) fn setgroups(size: usize, gids: *const u32) -> c_int;
    /// [`__errno`](https://github.com/openbsd/src/blob/master/include/errno.h#L54).
    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    pub(crate) fn __errno() -> *mut c_int;
    /// [`__error`](https://github.com/freebsd/freebsd-src/blob/main/sys/sys/errno.h#L43).
    #[cfg(any(target_os = "freebsd", target_vendor = "apple"))]
    pub(crate) fn __error() -> *mut c_int;
    /// [`__errno_location`](https://sourceware.org/git/?p=glibc.git;a=blob;f=include/errno.h;h=f0ccaa74dd8bebed83e4adfbf301339efeae3cdb;hb=HEAD#l37).
    #[cfg(any(target_os = "dragonfly", target_os = "linux"))]
    pub(crate) fn __errno_location() -> *mut c_int;
}
