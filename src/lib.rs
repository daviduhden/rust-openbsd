//! Idiomatic, OpenBSD-only Rust bindings for the security facilities that are
//! unique to [OpenBSD](https://www.openbsd.org/):
//!
//! * [`pledge(2)`](https://man.openbsd.org/pledge.2): restrict the system
//!   operations a process may perform ([`pledge()`]).
//! * [`unveil(2)`](https://man.openbsd.org/unveil.2): restrict the filesystem
//!   view of a process ([`unveil()`]).
//! * [`chroot(2)`](https://man.openbsd.org/chroot.2): change the filesystem
//!   root ([`chroot()`](crate::chroot())).
//! * Daemon-style privilege dropping: the
//!   [`setgroups(2)`](https://man.openbsd.org/setgroups.2) /
//!   [`setresgid(2)`](https://man.openbsd.org/setresgid.2) /
//!   [`setresuid(2)`](https://man.openbsd.org/setresuid.2) sequence used by
//!   OpenBSD base-system daemons ([`drop_privileges`]).
//! * [`issetugid(2)`](https://man.openbsd.org/issetugid.2) and
//!   [`getpeereid(3)`](https://man.openbsd.org/getpeereid.3) credential queries
//!   ([`is_setugid`], [`get_peer_credentials`]).
//! * [`setproctitle(3)`](https://man.openbsd.org/setproctitle.3),
//!   [`getprogname(3)`](https://man.openbsd.org/setprogname.3),
//!   [`closefrom(2)`](https://man.openbsd.org/closefrom.2), and
//!   [`getdtablecount(2)`](https://man.openbsd.org/getdtablecount.2), plus exec
//!   under a pledge ceiling and daemonization ([`set_proctitle`], [`progname`],
//!   [`close_from`], [`dtable_count`], [`exec_pledged`], [`daemonize`]).
//! * [`getexecpath(3)`](https://man.openbsd.org/getexecpath.3), the canonical
//!   pathname of the running executable, via `get_execpath` (gated behind the
//!   `openbsd-8-0` feature).
//! * The [`arc4random(3)`](https://man.openbsd.org/arc4random.3) family and
//!   [`getentropy(2)`](https://man.openbsd.org/getentropy.2) ([`arc4_random`],
//!   [`get_entropy`]).
//! * Routing domains, [`getrtable(2)`](https://man.openbsd.org/getrtable.2) and
//!   [`setrtable(2)`](https://man.openbsd.org/setrtable.2), via [`Rtable`].
//! * [`mimmutable(2)`](https://man.openbsd.org/mimmutable.2),
//!   [`explicit_bzero(3)`](https://man.openbsd.org/explicit_bzero.3),
//!   [`freezero(3)`](https://man.openbsd.org/freezero.3),
//!   [`timingsafe_bcmp(3)`](https://man.openbsd.org/timingsafe_bcmp.3), and
//!   [`timingsafe_memcmp(3)`](https://man.openbsd.org/timingsafe_memcmp.3)
//!   ([`mimmutable`], [`explicit_bzero`], [`freezero`], [`timingsafe_bcmp`]).
//! * [`crypt_checkpass(3)`](https://man.openbsd.org/crypt_checkpass.3),
//!   [`crypt_newhash(3)`](https://man.openbsd.org/crypt_newhash.3), and
//!   [`bcrypt_pbkdf(3)`](https://man.openbsd.org/bcrypt_pbkdf.3)
//!   ([`crypt_checkpass`], [`crypt_newhash`], [`bcrypt_pbkdf`]).
//!
//! These mechanisms restrict *different dimensions* of process authority and
//! are normally complementary: a typical OpenBSD daemon uses several of them.
//! They are not interchangeable.
//!
//! # OpenBSD only
//!
//! This crate is deliberately OpenBSD-only. Building it for any other
//! operating system fails with a clear compile-time error; there are no stub
//! implementations, no fallback behavior, and no portability abstractions.
//! Documentation builds (`cargo doc`, which sets `cfg(doc)`) are the only
//! exception, so that the API can be documented from any host.
//!
//! The crate targets **OpenBSD 7.9**, **OpenBSD 8.0**, and
//! **OpenBSD-current**. Interfaces that first appeared in OpenBSD 8.0 are
//! gated behind the [`openbsd-8-0`](#openbsd-8-0) Cargo feature so that the
//! default build still works on 7.9.
//!
//! # The pledge promise model
//!
//! [`pledge(2)`](https://man.openbsd.org/pledge.2) partitions the POSIX
//! feature set into subsystems called *promises*. After a successful
//! `pledge()` call, performing an operation that is not covered by a promise
//! aborts the process with an uncatchable `SIGABRT`.
//!
//! Promise changes are *monotonic*: a later call may only reduce the promise
//! set. An attempt to increase it fails with `EPERM`. Once a promise has been
//! removed it can never be regained. The [`Promises`] type models this by
//! exposing only removal operations.
//!
//! The second argument of `pledge(2)` restricts programs executed later via
//! [`execve(2)`](https://man.openbsd.org/execve.2). This crate exposes both
//! arguments independently; see [`pledge_parts`] for the exact `NULL` versus
//! empty-string distinction.
//!
//! ```no_run
//! use rust_openbsd::{pledge, Promise, Promises};
//!
//! // Allow only the standard I/O and read-only path promises.
//! let promises = Promises::new([Promise::Stdio, Promise::Rpath]);
//! pledge(&promises)?;
//! # Ok::<(), rust_openbsd::Errno>(())
//! ```
//!
//! # Execution promises
//!
//! `execpromises` restrict programs started later with
//! [`execve(2)`](https://man.openbsd.org/execve.2) and are inherited across
//! [`fork(2)`](https://man.openbsd.org/fork.2). Set them in the parent before
//! forking, so that the post-fork child only has to perform the `execve`
//! itself.
//!
//! ```no_run
//! use rust_openbsd::{pledge_both, Promise, Promises};
//!
//! // The current process keeps the ability to execute and read paths; any
//! // program it later execs starts with only "stdio".
//! pledge_both(
//!     &Promises::new([Promise::Stdio, Promise::Rpath, Promise::Proc, Promise::Exec]),
//!     &Promises::new([Promise::Stdio]),
//! )?;
//! # Ok::<(), rust_openbsd::Errno>(())
//! ```
//!
//! # The unveil model
//!
//! [`unveil(2)`](https://man.openbsd.org/unveil.2) restricts the filesystem
//! view of a process. The first call removes visibility of the entire
//! filesystem except for explicitly unveiled paths; additional calls add
//! rules. Once all rules have been installed the configuration should be
//! locked with [`lock_unveil`].
//!
//! ```no_run
//! use rust_openbsd::{unveil_and_lock, Permission, Permissions};
//!
//! let read = Permissions::READ;
//! let read_write_create = Permissions::READ
//!     .enable(Permission::Write)
//!     .enable(Permission::Create);
//!
//! unveil_and_lock([
//!     ("/", read),
//!     ("/var/www", read),
//!     ("/var/log/myapp", read_write_create),
//! ])?;
//! # Ok::<(), rust_openbsd::Errno>(())
//! ```
//!
//! # Privilege dropping
//!
//! The [`privileges`] module implements the sequence used by OpenBSD
//! base-system daemons:
//!
//! 1. resolve the destination account while still privileged;
//! 2. set the supplementary groups while still privileged;
//! 3. call [`setresgid(2)`](https://man.openbsd.org/setresgid.2) to set the
//!    real, effective, and saved GIDs;
//! 4. call [`setresuid(2)`](https://man.openbsd.org/setresuid.2) to set the
//!    real, effective, and saved UIDs;
//! 5. verify the resulting credentials.
//!
//! The ordering matters: [`setgroups(2)`](https://man.openbsd.org/setgroups.2)
//! requires privilege, and once root is gone the saved IDs must not allow the
//! process to regain it.
//!
//! ```no_run
//! use rust_openbsd::drop_privileges;
//!
//! // Privileged initialization happens first (binding sockets, opening logs,
//! // resolving the account, ...).
//! drop_privileges(c"_mydaemon")?;
//! // The process is irreversibly unprivileged from here on.
//! # Ok::<(), rust_openbsd::PrivDropError>(())
//! ```
//!
//! # Recommended ordering
//!
//! A daemon that combines all of the mechanisms should perform its privileged
//! initialization first and then transition, in this order:
//!
//! 1. privileged initialization (sockets, log files, configuration);
//! 2. [`chroot()`](crate::chroot()) / [`enter_chroot`] if a filesystem root is wanted;
//! 3. [`unveil()`] rules and [`lock_unveil`];
//! 4. an initial [`pledge()`] that still includes the promises the transition
//!    needs (`id`, and `getpw` for account resolution);
//! 5. [`drop_privileges`];
//! 6. a final [`pledge()`] without the identity-changing promises;
//! 7. optional [`pledge_child`] to restrict future
//!    [`execve(2)`](https://man.openbsd.org/execve.2) children;
//! 8. the unprivileged service loop.
//!
//! # Warning: process-wide state
//!
//! `pledge(2)`, `unveil(2)`, `chroot(2)`, and privilege dropping all change
//! process-wide security state and are not reversible. Apply them before
//! arbitrary concurrent work begins. In particular, applying pledge
//! restrictions to a process that has already started threads, an asynchronous
//! runtime, or libraries that need further system calls can abort the process
//! because the kernel unwinds sibling threads while cleaning up unveil state
//! and those threads then perform syscalls that the fresh restriction forbids.
//!
//! # Cargo "features"
//!
//! ### `alloc`
//!
//! Enables [`alloc`](https://doc.rust-lang.org/stable/alloc/) support. Without
//! it, the account database lookup uses a fixed-size stack buffer and reports
//! `ERANGE` for entries that do not fit.
//!
//! ### `std`
//!
//! Enables [`std`](https://doc.rust-lang.org/stable/std/) support, which adds
//! [`CStrHelper`] implementations for [`OsStr`](std::ffi::OsStr),
//! [`OsString`](std::ffi::OsString), [`Path`](std::path::Path), and
//! [`PathBuf`](std::path::PathBuf), as well as conversions between [`Errno`]
//! and [`std::io::Error`]. This is the default.
//!
//! ### `openbsd-8-0`
//!
//! Binds interfaces that first appeared in OpenBSD 8.0 (currently
//! [`getexecpath(3)`](https://man.openbsd.org/getexecpath.3), via
//! `get_execpath`). Those symbols do not exist in OpenBSD 7.9's libc, so
//! enabling this feature makes the crate require OpenBSD 8.0 or later. It is
//! off by default; the 7.9-compatible surface is always available.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg = false))]
#![no_std]
// Reject every non-OpenBSD target with a single, explicit diagnostic. The
// `doc` escape hatch exists only so that the API can be documented from a host
// that is not OpenBSD; it does not enable any portability behavior. Everything
// below is target-independent.
#[cfg(all(not(target_os = "openbsd"), not(doc)))]
compile_error!(
    "rust-openbsd only supports OpenBSD: pledge(2), unveil(2), chroot(2) and the \
     privilege-dropping interfaces are OpenBSD-specific. Build with an OpenBSD \
     target such as x86_64-unknown-openbsd."
);

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod cstr;
mod ffi;

pub mod authentication;
pub mod chroot;
pub mod credentials;
pub mod error;
pub mod memory;
pub mod pledge;
pub mod privileges;
pub mod process;
pub mod random;
pub mod rtable;
#[cfg(test)]
mod tests;
pub mod unveil;

pub use crate::{
    authentication::{PASSWORD_LEN, bcrypt_pbkdf_into, crypt_checkpass, crypt_newhash_into},
    chroot::{chdir, chroot, enter_chroot},
    credentials::{get_peer_credentials, is_setugid},
    cstr::CStrHelper,
    error::Errno,
    memory::{explicit_bzero, freezero, mimmutable, timingsafe_bcmp, timingsafe_memcmp},
    pledge::{Promise, Promises, pledge, pledge_both, pledge_child, pledge_parts, pledge_raw},
    privileges::{
        Account, Gid, GroupPolicy, Groups, NGROUPS_MAX, PrivDropError, PrivDropStep, Uid,
        account_by_name, drop_privileges, drop_privileges_to, drop_privileges_with, get_res_gid,
        get_res_uid, groups, init_groups, set_groups, set_res_gid, set_res_uid,
    },
    process::{
        DaemonOptions, PATH_MAX, PROCTITLE_MAX, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO,
        close_from, daemonize, daemonize_with, default_daemon_options, dtable_count, progname,
        reset_proctitle, set_proctitle, set_progname,
    },
    random::{MAX_ENTROPY, arc4_random, arc4_random_buf, arc4_random_uniform, get_entropy},
    rtable::{Rtable, get_rtable, set_rtable},
    unveil::{Permission, Permissions, lock_unveil, unveil, unveil_and_lock, unveil_paths},
};

/// Allocation-backed conveniences.
#[cfg(feature = "alloc")]
pub use crate::{
    authentication::{bcrypt_pbkdf, crypt_newhash},
    random::{arc4_random_bytes, get_entropy_bytes},
};

/// Process helpers that need [`std`].
#[cfg(feature = "std")]
pub use crate::process::{ForkExecError, exec_pledged, fork_exec, fork_exec_pledged};

/// Interfaces that first appeared in OpenBSD 8.0.
///
/// The `openbsd-8-0` feature makes these symbols part of the link, so enabling
/// it requires OpenBSD 8.0 or later.
#[cfg(feature = "openbsd-8-0")]
pub use crate::process::get_execpath;

/// The [`PathBuf`](std::path::PathBuf) convenience for [`get_execpath`].
#[cfg(all(feature = "openbsd-8-0", feature = "std"))]
pub use crate::process::execpath;
