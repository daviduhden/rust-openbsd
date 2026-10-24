// Copyright 2024-2026 Zack Newman and David Uhden Collado
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Process titles, descriptor hygiene, exec, and daemonization.
//!
//! * [`set_proctitle`] and [`reset_proctitle`] wrap
//!   [`setproctitle(3)`](https://man.openbsd.org/setproctitle.3) without ever
//!   letting a value become a format string.
//! * [`progname`] and [`set_progname`] wrap
//!   [`getprogname(3)`](https://man.openbsd.org/setprogname.3) and
//!   [`setprogname(3)`](https://man.openbsd.org/setprogname.3).
//! * [`close_from`] and [`dtable_count`] wrap
//!   [`closefrom(2)`](https://man.openbsd.org/closefrom.2) and
//!   [`getdtablecount(2)`](https://man.openbsd.org/getdtablecount.2).
//! * [`exec_pledged`], [`fork_exec`], and [`fork_exec_pledged`] combine
//!   [`pledge(2)`](https://man.openbsd.org/pledge.2) execution promises with
//!   [`execve(2)`](https://man.openbsd.org/execve.2).
//! * [`daemonize`] and [`daemonize_with`] detach the process from its
//!   controlling terminal.
//!
//! None of these performs any restriction by itself beyond a pledge policy
//! explicitly requested here; combine them with [`mod@crate::pledge`],
//! [`mod@crate::unveil`], [`mod@crate::chroot`], and [`crate::privileges`] as
//! required.
//!
//! # Forking, exec, and pledge
//!
//! The supported model for creating a more restricted child process is to
//! configure the *execution* promise ceiling in the parent and then exec:
//!
//! ```text
//! pledge_child(child_promises)   (exec ceiling, set in the parent)
//! fork + execve immediately      (the child does nothing else)
//! the new image starts under child_promises
//! ```
//!
//! OpenBSD copies the exec-promise state across
//! [`fork(2)`](https://man.openbsd.org/fork.2) and applies it when a descendant
//! executes a new image, so the child needs no pledge call of its own.
//! [`fork_exec_pledged`] implements exactly this. The
//! [`fork_exec`] and [`fork_exec_pledged`] helpers use a plain
//! [`std::process::Command`], which forks and execs without running any of your
//! code in the post-fork child.
//!
//! Setting exec promises in the parent is monotonic and affects every future
//! exec from that process and its descendants: use it when those descendants
//! share a common promise ceiling. Independent per-child policies require a
//! fresh-process boundary.

use core::{ffi::c_int, ptr};

use crate::{cstr::CStrHelper, error::Errno, ffi};

use core::ffi::CStr;

#[cfg(feature = "std")]
use crate::pledge::{Promises, pledge_child};

/// Maximum length of a process title in bytes.
///
/// This corresponds to the native `MAX_PROCTITLE`; the native
/// [`setproctitle(3)`](https://man.openbsd.org/setproctitle.3) truncates longer
/// titles. See [`set_proctitle`] for the difference in `no_alloc` builds.
pub const PROCTITLE_MAX: usize = 2048;

/// `PATH_MAX` from OpenBSD's `<sys/syslimits.h>`: the maximum length of a
/// pathname including its terminating NUL.
pub const PATH_MAX: usize = 1024;

/// Standard input descriptor.
pub const STDIN_FILENO: c_int = 0;
/// Standard output descriptor.
pub const STDOUT_FILENO: c_int = 1;
/// Standard error descriptor.
pub const STDERR_FILENO: c_int = 2;

/// Sets the process title shown by
/// [`ps(1)`](https://man.openbsd.org/ps.1), as `setproctitle("%s", title)`.
///
/// The title is passed purely as *data*: the fixed `"%s"` format string lives
/// here, so a title containing format characters (for example `"%s %n %x"`)
/// can never be interpreted as a format string. This is the secure idiom the
/// OpenBSD manual page requires.
///
/// Titles longer than [`PROCTITLE_MAX`] bytes are truncated by the native
/// implementation. With the `alloc` feature the title is converted through a
/// heap allocation, so `setproctitle(3)` always sees the full string and
/// performs the truncation. Without `alloc`, [`CStrHelper`] uses a 1024-byte
/// stack buffer and a title of 1024 bytes or more fails with
/// [`Errno::ERANGE`] before the native call; it is not truncated.
///
/// The title is accepted through [`CStrHelper`], so it may be a byte slice,
/// `str`, or `CStr`; an interior NUL byte is rejected with [`Errno::EINVAL`].
///
/// The operation is process-global. It works under the `stdio` pledge promise.
///
/// # Errors
///
/// Errors with [`Errno::EINVAL`] if the title contains an interior NUL byte,
/// and with [`Errno::ERANGE`] for an over-long title when `alloc` is disabled.
#[expect(
    unsafe_code,
    reason = "setproctitle(3) is variadic and takes a pointer"
)]
pub fn set_proctitle<P: CStrHelper>(title: P) -> Result<(), Errno> {
    title.convert_then_apply(|title| {
        // SAFETY:
        // The format argument is the fixed literal "%s" (never caller data),
        // and `title` is a valid, NUL-terminated string borrowed for the
        // duration of the call. The native call only reads the data argument.
        unsafe { ffi::setproctitle(c"%s".as_ptr(), title.as_ptr()) };
        Ok(())
    })
}

/// Resets the process title to just the program name, as
/// `setproctitle(NULL)`.
///
/// # Pledge
///
/// Works under the `stdio` promise.
#[expect(unsafe_code, reason = "setproctitle(3) is variadic")]
#[inline]
pub fn reset_proctitle() {
    // SAFETY:
    // A null format argument is the documented way to reset the title; no
    // varargs are read.
    unsafe { ffi::setproctitle(ptr::null()) };
}

/// Returns the stored program name, as
/// [`getprogname(3)`](https://man.openbsd.org/setprogname.3).
///
/// The returned reference is valid for the lifetime of the process: the native
/// program name is process-global and is only ever replaced by another
/// long-lived name.
///
/// The value is supplied by the invoking process (normally from `argv[0]`) and
/// must not be trusted by set-user-ID or set-group-ID programs; use
/// [`is_setugid`](crate::is_setugid) to detect that situation before relying
/// on the name for diagnostics.
#[expect(unsafe_code, reason = "getprogname(3) returns a raw pointer")]
#[must_use]
pub fn progname() -> &'static CStr {
    let name = ffi::getprogname();
    if name.is_null() {
        return c"";
    }
    // SAFETY:
    // `getprogname` returns either the process's `argv[0]` memory (live for the
    // whole process) or the pointer previously stored by `setprogname` (which
    // `set_progname` only accepts with a `'static` lifetime). It is therefore
    // non-null and NUL-terminated here, and valid for `'static`.
    unsafe { CStr::from_ptr(name) }
}

/// Sets the program name, as
/// [`setprogname(3)`](https://man.openbsd.org/setprogname.3).
///
/// The stored name is used by `setproctitle(NULL)` ([`reset_proctitle`]) and by
/// diagnostic messages; if the name contains a slash, the basename is used,
/// matching the native behaviour.
///
/// The name must be `'static` because the native implementation stores the
/// pointer rather than copying the string: passing a temporary would leave the
/// process with a dangling program name.
#[expect(unsafe_code, reason = "setprogname(3) takes a raw pointer")]
#[inline]
pub fn set_progname(name: &'static CStr) {
    // SAFETY:
    // `name` is a valid, NUL-terminated string that lives for the rest of the
    // process (enforced by the `'static` bound). The native call only reads it,
    // and stores the pointer in a process-global variable.
    unsafe { ffi::setprogname(name.as_ptr()) };
}

/// Closes all file descriptors greater than or equal to `lowfd`, as
/// [`closefrom(2)`](https://man.openbsd.org/closefrom.2).
///
/// This is the classic OpenBSD descriptor-leak prevention: daemons and
/// privilege-separated programs call it around spawn/exec time, with the
/// descriptors to keep reserved at the low numbers. The argument itself is
/// closed too, as are any runtime-managed descriptors above it.
///
/// The result is propagated instead of being discarded, so a caller that
/// depends on descriptor hygiene can observe a failure. OpenBSD reports
/// [`Errno::EINVAL`] for a negative `lowfd`; other failures are kernel-specific.
/// Closing descriptors that another thread is using remains the caller's
/// responsibility.
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] for a negative `lowfd`; other failures reported by
/// the native call are propagated.
///
/// # Pledge
///
/// Allowed under the `stdio` promise.
#[inline]
pub fn close_from(lowfd: c_int) -> Result<(), Errno> {
    if ffi::closefrom(lowfd) == ffi::SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Returns the number of file descriptors the process currently has open, as
/// [`getdtablecount(2)`](https://man.openbsd.org/getdtablecount.2).
///
/// The native call cannot fail. Useful for auditing and for descriptor-hygiene
/// checks around spawn and privilege-separation boundaries.
///
/// # Pledge
///
/// Allowed under the `stdio` promise.
#[inline]
#[must_use]
pub fn dtable_count() -> c_int {
    ffi::getdtablecount()
}

/// Replaces the current process image with the program described by `command`,
/// starting it under the given execution promise ceiling, as
/// [`execve(2)`](https://man.openbsd.org/execve.2).
///
/// This sets the *execution* promises with [`pledge_child`] and then calls
/// [`exec`](std::os::unix::process::CommandExt::exec); the current image is not
/// restricted by that call, and the new program starts with exactly `promises`.
/// A successful exec never returns; on failure the returned
/// [`std::io::Error`] carries the native error.
///
/// The usual way for a long-running process to finish by becoming a more
/// tightly restricted program. An empty promise set is valid OpenBSD (the
/// `_exit(2)`-only state) but no ordinary runtime can start under it.
///
/// # Side effects and errors
///
/// [`pledge_child`] reduces the caller's execution promises monotonically
/// *before* the exec is attempted. If the exec then fails, that reduction is
/// **not** rolled back and remains in effect for every future exec from this
/// process. Any returned [`std::io::Error`] therefore means both "the image was
/// not replaced" and "the execution ceiling may have been lowered".
#[cfg(feature = "std")]
#[must_use = "a returned error means the image was not replaced"]
pub fn exec_pledged(promises: &Promises, command: &mut std::process::Command) -> std::io::Error {
    if let Err(errno) = pledge_child(promises) {
        return std::io::Error::from_raw_os_error(errno.into_raw());
    }
    std::os::unix::process::CommandExt::exec(command)
}

/// Forks and execs the program described by `command`, returning the child
/// handle on success, as
/// [`fork(2)`](https://man.openbsd.org/fork.2) followed by
/// [`execve(2)`](https://man.openbsd.org/execve.2).
///
/// With `openbsd-8-0`, the removed execution promise cannot be requested.
/// Under kernels that require it for `execve`, the caller must remain
/// unpledged to spawn a program. Setting execution promises does not grant
/// execution permission to the caller or to the new image; a pledged new
/// image cannot subsequently execute other programs without that permission.
///
/// This changes no pledge policy: any execution promises already configured in
/// the parent apply to the child. If the calling process has pledged itself,
/// its current promises must still allow `fork` and `execve` (generally `proc`
/// and `exec`).
///
/// # Errors
///
/// Errors if spawning the child fails.
#[cfg(feature = "std")]
#[inline]
pub fn fork_exec(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    command.spawn()
}

/// Sets the execution promise ceiling and then forks and execs `command`,
/// returning the child handle on success.
///
/// The supported fork/exec architecture: the exec promises are configured in
/// the parent *before* forking, and the child does nothing but reach exec, so
/// the executed program begins pledged with exactly `promises`.
///
/// # Process-global side effect
///
/// This is *not* a per-child configuration. Setting the execution promises
/// through [`pledge_child`] reduces the *caller's* promises monotonically and
/// cannot be widened afterwards: every future exec from the calling process and
/// its descendants is then capped by `promises`, including children spawned by
/// [`fork_exec`] or by [`std::process::Command`] directly. Use it only when
/// those descendants share a common promise ceiling; independent per-child
/// policies require a separate process boundary. If spawning fails after the
/// promise has been set, the reduction is **not** rolled back and remains in
/// effect.
///
/// # Errors
///
/// Returns [`ForkExecError::Pledge`] if the execution promises cannot be set,
/// or [`ForkExecError::Spawn`] if spawning the child fails.
#[cfg(feature = "std")]
pub fn fork_exec_pledged(
    promises: &Promises,
    command: &mut std::process::Command,
) -> Result<std::process::Child, ForkExecError> {
    pledge_child(promises).map_err(ForkExecError::Pledge)?;
    command.spawn().map_err(ForkExecError::Spawn)
}

/// Error from [`fork_exec_pledged`].
#[cfg(feature = "std")]
#[derive(Debug)]
#[non_exhaustive]
pub enum ForkExecError {
    /// The execution promise ceiling could not be set.
    Pledge(Errno),
    /// The child process could not be spawned.
    Spawn(std::io::Error),
}

#[cfg(feature = "std")]
impl core::fmt::Display for ForkExecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pledge(errno) => write!(f, "failed to set execution promises: {errno}"),
            Self::Spawn(error) => write!(f, "failed to spawn the child process: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl core::error::Error for ForkExecError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Pledge(errno) => Some(errno),
            Self::Spawn(error) => Some(error),
        }
    }
}

/// Options controlling [`daemonize_with`]. The fields are named positively,
/// unlike the inverted `nochdir`/`noclose` arguments of
/// [`daemon(3)`](https://man.openbsd.org/daemon.3).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DaemonOptions {
    /// Whether to change the working directory to `/`.
    ///
    /// Leaving this `false` keeps the current directory, which can prevent an
    /// unmount of the filesystem it lives on.
    pub change_directory_to_root: bool,
    /// Whether to redirect standard input, output, and error to `/dev/null`.
    pub redirect_standard_streams: bool,
}

impl Default for DaemonOptions {
    /// Returns [`default_daemon_options`].
    #[inline]
    fn default() -> Self {
        default_daemon_options()
    }
}

/// The default daemonization behaviour:
/// [`DaemonOptions::change_directory_to_root`] and
/// [`DaemonOptions::redirect_standard_streams`] both `true`.
#[inline]
#[must_use]
pub const fn default_daemon_options() -> DaemonOptions {
    DaemonOptions {
        change_directory_to_root: true,
        redirect_standard_streams: true,
    }
}

/// Daemonizes `body` with the default [`DaemonOptions`].
///
/// See [`daemonize_with`] for the exact sequence and return contract.
///
/// # Return value
///
/// Returns `Err` only if `fork(2)` fails; on success it never returns (the
/// original process exits and `body` runs in the detached child).
///
/// # Errors
///
/// Returns the [`Errno`] set by a failed
/// [`fork(2)`](https://man.openbsd.org/fork.2).
#[inline]
pub fn daemonize<F: FnOnce()>(body: F) -> Result<(), Errno> {
    daemonize_with(default_daemon_options(), body)
}

/// Detaches from the controlling terminal and runs `body` in the background, as
/// [`daemon(3)`](https://man.openbsd.org/daemon.3).
///
/// The sequence is
///
/// ```text
/// fork; parent _exit(0)
/// child: setsid; chdir("/") if requested; redirect 0/1/2 to /dev/null if requested
/// child: body()
/// child: _exit(0)
/// ```
///
/// and the original process exits immediately, exactly like `daemon(3)`.
///
/// # Return value
///
/// On success this function does not return: the parent has exited and `body`
/// runs in the detached child, which exits with status 0 when `body` returns.
///
/// # Errors
///
/// The only return path is a failed
/// [`fork(2)`](https://man.openbsd.org/fork.2), which yields the [`Errno`] it
/// set and leaves the original (still attached) process running so the caller
/// can report the error and abort. If
/// [`setsid(2)`](https://man.openbsd.org/setsid.2) fails in the child, the child
/// exits with status 1 without running `body`, because it did not actually
/// detach; the already-exited parent cannot report that. The same fail-closed
/// status 1 is used if the requested `chdir("/")` or the standard-stream
/// redirection fails, so the child never continues with a partially applied
/// transition.
///
/// # Correctness (read this before using it)
///
/// This is the one function in this crate that runs arbitrary caller code after
/// a raw [`fork(2)`](https://man.openbsd.org/fork.2). In a multithreaded
/// process the child only inherits the calling thread, and only
/// async-signal-safe operations are reliable between `fork` and `exec`: locks
/// held by other threads (including the allocator's) stay held in the child, so
/// `body` may deadlock. Call this before spawning threads, or accept the
/// documented risk. The Haskell reference implementation has the same
/// restriction and documents it; Rust has no runtime-aware `fork` equivalent of
/// `forkProcess`. A panic that unwinds out of `body` runs the Rust panic
/// runtime in the forked child and may also deadlock; `body` should not panic.
///
/// The child-side work performed by this crate itself (`setsid`, optional
/// `chdir`, optional `open`/`dup2`/`close`, and `_exit`) allocates no memory,
/// takes no locks, and touches no Rust runtime state.
///
/// When standard streams are redirected, descriptors 0, 1, and 2 are assumed to
/// be the standard streams; if the caller closed them and repurposed the
/// numbers, the redirection clobbers whatever now occupies them (the same
/// caveat as `daemon(3)`). Programs that have already reused those descriptors
/// should pass [`DaemonOptions::redirect_standard_streams`] `false`.
///
/// Under pledge, this needs `proc` (fork, setsid), `rpath` (chdir), and
/// `rpath`/`wpath` (opening `/dev/null`); the recommended order is to daemonize
/// before pledging. Modern service supervision commonly expects foreground
/// operation, so only call this when detachment is actually required.
#[expect(unsafe_code, reason = "chdir(2) takes a raw pointer")]
pub fn daemonize_with<F: FnOnce()>(options: DaemonOptions, body: F) -> Result<(), Errno> {
    // SAFETY:
    // `fork(2)` has no memory preconditions of its own; the constraints of
    // running code in the child are documented on this function.
    let pid = unsafe { ffi::fork() };
    if pid < 0 {
        // The fork failed; report it rather than pretending to have detached.
        return Err(Errno::last());
    }
    if pid > 0 {
        // The original process exits without running the daemon body, exactly
        // like daemon(3).
        ffi::_exit(0);
    }

    // A process created by fork(2) is never a process-group leader, so
    // setsid(2) cannot normally fail here. If it somehow does, fail closed
    // rather than running the body while still attached to the terminal.
    if ffi::setsid() < 0 {
        ffi::_exit(1);
    }
    let chdir_ok = if options.change_directory_to_root {
        // SAFETY:
        // The path is a fixed, NUL-terminated literal; `chdir(2)` only reads
        // it.
        let code = unsafe { ffi::chdir(c"/".as_ptr()) };
        code == ffi::SUCCESS
    } else {
        true
    };
    let redirect_ok = if options.redirect_standard_streams {
        redirect_standard_streams_to_dev_null()
    } else {
        true
    };
    if !child_transition_permitted(options, chdir_ok, redirect_ok) {
        // A daemon that did not reach the requested directory or standard-stream
        // state must not run the body as if the transition had succeeded.
        ffi::_exit(1);
    }

    body();
    ffi::_exit(0);
}

/// Returns `true` only when every transition requested by `options` succeeded.
///
/// This is the fail-closed decision used after `fork(2)`: a transition that was
/// requested but failed must prevent `body` from running. It is separated from
/// the syscalls so the decision table can be tested without performing the
/// irreversible daemon transition.
pub(crate) const fn child_transition_permitted(
    options: DaemonOptions,
    chdir_ok: bool,
    redirect_ok: bool,
) -> bool {
    (chdir_ok || !options.change_directory_to_root)
        && (redirect_ok || !options.redirect_standard_streams)
}

/// Redirects the three standard descriptors to `/dev/null`.
///
/// Returns `false` if `/dev/null` cannot be opened or any `dup2(2)` fails. A
/// failure to close the extra descriptor after a successful redirection is
/// ignored: the streams already refer to `/dev/null`, and the lingering
/// descriptor is released by the subsequent `_exit(2)`.
#[expect(unsafe_code, reason = "open(2) takes a raw pointer")]
fn redirect_standard_streams_to_dev_null() -> bool {
    /// `O_RDWR` from OpenBSD's `<fcntl.h>`.
    const O_RDWR: c_int = 0x0002;

    // SAFETY:
    // The path is a fixed, NUL-terminated literal and the call uses the
    // two-argument form of `open(2)`, so no varargs are read.
    let null_fd = unsafe { ffi::open(c"/dev/null".as_ptr(), O_RDWR) };
    if null_fd < 0 {
        return false;
    }
    for target in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] {
        if ffi::dup2(null_fd, target) < 0 {
            if null_fd > STDERR_FILENO {
                // SAFETY:
                // `null_fd` was returned by `open(2)` above and is still owned
                // by this function. The redirection failed, so exit rather
                // than leak a descriptor into a daemon.
                let _ = unsafe { ffi::close(null_fd) };
            }
            return false;
        }
    }
    if null_fd > STDERR_FILENO {
        // SAFETY:
        // `null_fd` was returned by `open(2)` above and is still owned by this
        // function; closing it releases the duplicate that is no longer needed
        // once descriptors 0-2 refer to `/dev/null`.
        let _ = unsafe { ffi::close(null_fd) };
    }
    true
}

/// Returns the absolute pathname of the running ELF executable, as
/// [`getexecpath(3)`](https://man.openbsd.org/getexecpath.3).
///
/// The pathname is canonicalized in the same manner as
/// [`realpath(3)`](https://man.openbsd.org/realpath.3). `buf` should be
/// [`PATH_MAX`] bytes long; the returned length excludes the terminating NUL.
///
/// # Availability
///
/// `getexecpath(3)` first appeared in OpenBSD 8.0, so it is gated behind the
/// `openbsd-8-0` Cargo feature. Enabling that feature makes the crate require
/// OpenBSD 8.0 or later.
///
/// # Errors
///
/// Returns [`Errno::ENOENT`] when the executable pathname cannot be determined
/// (for example when the process was started in a directory that is no longer
/// linked to the filesystem), and [`Errno::ERANGE`] when `buf` is too small.
#[cfg(feature = "openbsd-8-0")]
#[expect(unsafe_code, reason = "getexecpath(3) writes through a pointer")]
pub fn get_execpath(buf: &mut [u8]) -> Result<usize, Errno> {
    let size = buf.len();
    // SAFETY:
    // `buf` is a live, writable slice and `size` is exactly its length, so the
    // native call may write at most `size` bytes into it.
    let code = unsafe { ffi::getexecpath(buf.as_mut_ptr().cast(), size) };
    if code != ffi::SUCCESS {
        return Err(Errno::last());
    }
    buf.iter().position(|&byte| byte == 0).ok_or(Errno::ERANGE)
}

/// Returns the absolute, canonicalized pathname of the running ELF executable
/// as a [`PathBuf`](std::path::PathBuf).
///
/// See [`get_execpath`].
///
/// # Errors
///
/// See [`get_execpath`].
#[cfg(all(feature = "openbsd-8-0", feature = "std"))]
pub fn execpath() -> Result<std::path::PathBuf, Errno> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut buf = [0_u8; PATH_MAX];
    let len = get_execpath(&mut buf)?;
    let bytes = buf.get(..len).unwrap_or_default();
    Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}
