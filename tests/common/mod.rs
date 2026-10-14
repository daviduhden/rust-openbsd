//! Shared helpers for the kernel-dependent integration tests.
//!
//! Every destructive or irreversible test runs in an isolated child process.
//! The child is the *same test binary* re-executed by libtest with `--exact`
//! and `--ignored`, so no test can restrict the main test runner, change its
//! root, or drop its privileges. Tests that require root skip cleanly when the
//! runner is not root.

#![allow(
    dead_code,
    reason = "the helpers are shared by several test binaries that do not use all of them"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers may panic to report failures"
)]

use std::{
    ffi::c_int,
    os::unix::process::ExitStatusExt,
    process::{Command, Output},
};

/// The `SIGABRT` signal number on OpenBSD.
pub(crate) const SIGABRT: c_int = 6;

/// Terminates the current process immediately, as `_exit(2)`.
///
/// This must be used instead of [`std::process::exit`] once the process has
/// been restricted to the `_exit`-only promise set, because `exit(3)` performs
/// further system calls that the restriction forbids.
#[expect(unsafe_code, reason = "the helper calls the raw `_exit(2)` syscall")]
pub(crate) fn exit_now(code: c_int) -> ! {
    // SAFETY:
    // `_exit(2)` never returns and does not dereference any memory.
    unsafe { _exit(code) }
}

#[expect(unsafe_code, reason = "the tests need the raw `_exit(2)` syscall")]
unsafe extern "C" {
    /// [`_exit(2)`](https://man.openbsd.org/_exit.2).
    fn _exit(code: c_int) -> !;
}

/// Returns `true` if the current effective user is root.
pub(crate) fn is_root() -> bool {
    rust_openbsd::Uid::geteuid().is_root()
}

/// Re-runs the current test binary for a single ignored child test.
pub(crate) fn run_child(name: &str) -> Output {
    let exe = std::env::current_exe().expect("test binary path");
    Command::new(exe)
        .args([
            "--exact",
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("spawn child test process")
}

/// Asserts that the child exited successfully.
pub(crate) fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "child failed with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Asserts that the child was killed by `signal`.
pub(crate) fn assert_signal(output: &Output, signal: c_int) {
    assert_eq!(
        output.status.signal(),
        Some(signal),
        "expected signal {signal}, got {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Asserts that the child was killed by `SIGABRT`.
pub(crate) fn assert_sigabrt(output: &Output) {
    assert_signal(output, SIGABRT);
}

/// Prints a skip notice and returns `true` when the test must be skipped.
pub(crate) fn skip_without_root(name: &str) -> bool {
    if is_root() {
        false
    } else {
        println!("SKIP {name}: requires root privileges");
        true
    }
}

/// Source of the small native probe used to verify exec promises.
///
/// The probe is compiled with the system C compiler, exactly as a C program
/// would be on OpenBSD. Without arguments it performs only `stdio`-class
/// operations and exits 0; with the argument `violate` it calls `open(2)`,
/// which requires the `rpath` promise.
const EXEC_PROBE_SOURCE: &str = r#"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (argc > 1 && argv[1][0] == 'v') {
		if (open("/etc/hostname", O_RDONLY) == -1)
			(void)fprintf(stderr, "open failed\n");
		return 1;
	}
	(void)getpid();
	(void)printf("exec-probe-ok\n");
	return 0;
}
"#;

/// Compiles the exec-promise probe and returns its path.
///
/// The probe is linked statically: a dynamically linked executable needs the
/// `rpath` promise at startup for `ld.so`, which the `stdio` exec-promise
/// ceiling forbids, so a dynamic probe could never run in the allowed case.
///
/// Returns `None` when the system C compiler is unavailable or cannot link
/// statically, so that the calling test can skip instead of failing.
pub(crate) fn compile_exec_probe() -> Option<std::path::PathBuf> {
    let dir = std::path::Path::new("/tmp");
    let source = dir.join("rust-openbsd-exec-probe.c");
    let binary = dir.join("rust-openbsd-exec-probe");
    std::fs::write(&source, EXEC_PROBE_SOURCE).expect("write probe source");
    let status = Command::new("cc")
        .args(["-std=c23", "-Wall", "-Wextra", "-Werror", "-static"])
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .status()
        .expect("run cc");
    if status.success() { Some(binary) } else { None }
}

/// Source of the single-threaded probe for the empty (`_exit`-only) promise set.
///
/// Reducing a *multithreaded* process to the empty promise set makes the kernel
/// unwind sibling threads while cleaning up unveil state; the resumed threads
/// then perform syscalls the fresh restriction forbids and abort the process.
/// That is an interaction with the runtime environment, not a property of
/// `pledge(2)`, so this state is exercised from a dedicated single-threaded
/// native program instead of from the multithreaded libtest child.
const EMPTY_PLEDGE_PROBE_SOURCE: &str = r#"
#include <fcntl.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (pledge("", nullptr) == -1)
		_exit(3);
	if (argc > 1 && argv[1][0] == 'v') {
		/* requires "rpath"; forbidden under the empty promise set */
		if (open("/", O_RDONLY) == -1)
			_exit(4);
		_exit(1);
	}
	_exit(0);
}
"#;

/// Compiles the empty-promise-set probe and returns its path.
///
/// Returns `None` when the system C compiler is unavailable, so that the
/// calling test can skip instead of failing.
pub(crate) fn compile_empty_pledge_probe() -> Option<std::path::PathBuf> {
    let dir = std::path::Path::new("/tmp");
    let source = dir.join("rust-openbsd-empty-pledge-probe.c");
    let binary = dir.join("rust-openbsd-empty-pledge-probe");
    std::fs::write(&source, EMPTY_PLEDGE_PROBE_SOURCE).expect("write probe source");
    let status = Command::new("cc")
        .args(["-std=c23", "-Wall", "-Wextra", "-Werror"])
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .status()
        .expect("run cc");
    if status.success() { Some(binary) } else { None }
}
