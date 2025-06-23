use super::{Gid, Uid, UserInfo};
#[cfg(any(target_os = "espidf", target_os = "horizon", target_os = "vita"))]
use core::ffi::c_ushort;
use core::ffi::{c_char, c_int};
/// Error code when a libc call is successful.
pub(crate) const SUCCESS: c_int = 0;
/// `uid_t` and `gid_t`.
#[cfg(any(target_os = "espidf", target_os = "horizon", target_os = "vita"))]
pub type IdT = c_ushort;
/// `uid_t` and `gid_t`.
#[cfg(target_os = "nto")]
pub type IdT = i32;
/// `uid_t` and `gid_t`.
#[cfg(not(any(
    target_os = "espidf",
    target_os = "horizon",
    target_os = "nto",
    target_os = "vita"
)))]
pub(crate) type IdT = u32;
/// `time_t`.
#[cfg(all(
    any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
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
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
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
    uid: IdT,
    /// Group ID.
    gid: IdT,
    /// Password change time.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    change: TimeT,
    /// User access class.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
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
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    expire: TimeT,
    /// Internal fields.
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd", target_os = "macos"))]
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
    pub(crate) safe fn getuid() -> IdT;
    /// [`geteuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/geteuid.html).
    pub(crate) safe fn geteuid() -> IdT;
    /// [`getgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getgid.html).
    pub(crate) safe fn getgid() -> IdT;
    /// [`getegid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/getegid.html).
    pub(crate) safe fn getegid() -> IdT;
    /// [`setresuid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresuid.html).
    pub(crate) safe fn setresuid(ruid: IdT, euid: IdT, suid: IdT) -> c_int;
    /// [`setresgid`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/setresgid.html).
    pub(crate) safe fn setresgid(rgid: IdT, egid: IdT, sgid: IdT) -> c_int;
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
        uid: IdT,
        pwd: *mut Passwd,
        buf: *mut c_char,
        size: usize,
        result: *mut *mut Passwd,
    ) -> c_int;
}
