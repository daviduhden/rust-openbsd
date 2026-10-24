# FFI surface inventory

All declarations live in one `unsafe extern "C"` block in `src/ffi.rs`. There is
no `#[link]`, no `build.rs`, no C shim, and no dependency crate. Symbols resolve
from the OpenBSD libc linked by the Rust target. The only declaration gated by a
feature is `getexecpath` (`openbsd-8-0`).

`SUCCESS` is `0`. `c_int` is the native `int`; `u32` represents `uid_t`,
`gid_t`, and `uint32_t`; `usize` represents `size_t`; `i64` represents `time_t`.

## Safe declarations

These have no pointer argument and no memory-safety precondition.

| Symbol | Rust signature | Wrapper |
| --- | --- | --- |
| `getuid` | `fn() -> u32` | `Uid::getuid` |
| `geteuid` | `fn() -> u32` | `Uid::geteuid` |
| `getgid` | `fn() -> u32` | `Gid::getgid` |
| `getegid` | `fn() -> u32` | `Gid::getegid` |
| `setresuid` | `fn(u32, u32, u32) -> c_int` | `set_res_uid` |
| `setresgid` | `fn(u32, u32, u32) -> c_int` | `set_res_gid` |
| `issetugid` | `fn() -> c_int` | `is_setugid` |
| `arc4random` | `fn() -> u32` | `arc4_random` |
| `arc4random_uniform` | `fn(u32) -> u32` | `arc4_random_uniform` |
| `getrtable` | `fn() -> c_int` | `get_rtable` |
| `setrtable` | `fn(c_int) -> c_int` | `set_rtable` |
| `getprogname` | `fn() -> *const c_char` | `progname` (pointer checked before deref) |
| `closefrom` | `fn(c_int) -> c_int` | `close_from` |
| `getdtablecount` | `fn() -> c_int` | `dtable_count` |
| `setsid` | `fn() -> c_int` | `daemonize_with` |
| `dup2` | `fn(c_int, c_int) -> c_int` | `daemonize_with` |
| `_exit` | `fn(c_int) -> !` | `daemonize_with` |

`getprogname` returns a raw pointer but does not dereference it; the safe wrapper
checks for null and relies on libc keeping the name alive for the process.

## Unsafe declarations

These take a pointer, write through a pointer, or have a process-wide
precondition that the wrapper documents.

| Symbol | Rust signature | Wrapper |
| --- | --- | --- |
| `getresuid` | `fn(*mut u32, *mut u32, *mut u32) -> c_int` | `get_res_uid` |
| `getresgid` | `fn(*mut u32, *mut u32, *mut u32) -> c_int` | `get_res_gid` |
| `setgroups` | `fn(c_int, *const u32) -> c_int` | `set_groups` |
| `getgroups` | `fn(c_int, *mut u32) -> c_int` | `groups` |
| `getgrouplist` | `fn(*const c_char, u32, *mut u32, *mut c_int) -> c_int` | `group_membership` (verification) |
| `initgroups` | `fn(*const c_char, u32) -> c_int` | `init_groups` |
| `chroot` | `fn(*const c_char) -> c_int` | `chroot` |
| `chdir` | `fn(*const c_char) -> c_int` | `chdir`, `enter_chroot`, `daemonize_with` |
| `getpwnam_r` | `fn(*const c_char, *mut Passwd, *mut c_char, usize, *mut *mut Passwd) -> c_int` | `resolve` |
| `pledge` | `fn(*const c_char, *const c_char) -> c_int` | `pledge_parts`, `pledge_raw` |
| `unveil` | `fn(*const c_char, *const c_char) -> c_int` | `unveil`, `lock_unveil` |
| `__errno` | `fn() -> *mut c_int` | `Errno::get_raw_err_ptr` |
| `getpeereid` | `fn(c_int, *mut u32, *mut u32) -> c_int` | `get_peer_credentials` |
| `arc4random_buf` | `fn(*mut c_void, usize)` | `arc4_random_buf` |
| `getentropy` | `fn(*mut c_void, usize) -> c_int` | `get_entropy` |
| `mimmutable` | `fn(*mut c_void, usize) -> c_int` | `mimmutable` |
| `explicit_bzero` | `fn(*mut c_void, usize)` | `explicit_bzero` |
| `freezero` | `fn(*mut c_void, usize)` | `freezero` |
| `timingsafe_bcmp` | `fn(*const c_void, *const c_void, usize) -> c_int` | `timingsafe_bcmp` |
| `timingsafe_memcmp` | `fn(*const c_void, *const c_void, usize) -> c_int` | `timingsafe_memcmp` |
| `setproctitle` | `fn(*const c_char, ...)` | `set_proctitle`, `reset_proctitle` |
| `setprogname` | `fn(*const c_char)` | `set_progname` |
| `crypt_checkpass` | `fn(*const c_char, *const c_char) -> c_int` | `checkpass` |
| `crypt_newhash` | `fn(*const c_char, *const c_char, *mut c_char, usize) -> c_int` | `newhash` |
| `bcrypt_pbkdf` | `fn(*const c_void, usize, *const c_void, usize, *mut c_void, usize, u32) -> c_int` | `bcrypt_pbkdf_into` |
| `fork` | `fn() -> c_int` | `daemonize_with` |
| `close` | `fn(c_int) -> c_int` | `daemonize_with` |
| `open` | `fn(*const c_char, c_int, ...) -> c_int` | `daemonize_with` |
| `getexecpath` | `fn(*mut c_char, usize) -> c_int` | `get_execpath` (`openbsd-8-0`) |

## Return conventions

| Call | Success | Special case |
| --- | --- | --- |
| Most libc calls | `0` | failure returns `-1`, read `errno` |
| `getgroups` | count | `0` is a valid empty set |
| `getrtable` | table id | `0` is valid, so check `< 0` |
| `fork` | pid | `0` is the child |
| `getpwnam_r` | `0` | returns an error number directly; `*result == NULL` means no entry |
| `getdtablecount` | count | cannot fail |
| `closefrom` | `0` | propagated as `Result` |
| `_exit` | never returns | modeled as `-> !` |

## `Passwd` layout

```text
name: *mut c_char
passwd: *mut c_char
uid: u32
gid: u32
change: i64
class: *mut c_char
gecos: *mut c_char
dir: *mut c_char
shell: *mut c_char
expire: i64
```

The field order, `#[repr(C)]`, and all ten fields are required. Do not remove
unread fields. `uid`/`gid` are 32-bit; `change`/`expire` are 64-bit `time_t` on
supported targets. Pointers are 8 bytes on LP64. Add layout assertions before
changing the target set.
