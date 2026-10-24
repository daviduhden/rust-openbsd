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

//! Kernel tests for process titles, descriptor hygiene, and exec helpers.
//!
//! Tests that change process-wide state (the process title, the program name,
//! the descriptor table, or the caller's execution promises) run in an isolated
//! child process.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    unsafe_code,
    reason = "integration tests may use panicking assertions and raw libc calls"
)]

mod common;

use common::{assert_sigabrt, assert_success, compile_exec_probe, exit_now, run_child};
use rust_openbsd::{
    DaemonOptions, Promise, Promises, close_from, daemonize_with, dtable_count, exec_pledged,
    fork_exec, fork_exec_pledged, progname, reset_proctitle, set_proctitle, set_progname,
};

// ---------------------------------------------------------------------------
// Child processes.
// ---------------------------------------------------------------------------

/// The title, program name, and descriptor table are process-global.
#[test]
#[ignore = "isolated child process"]
fn child_process_state() {
    assert!(dtable_count() > 0, "no open descriptors");

    assert!(set_proctitle("rust-openbsd-title").is_ok());
    reset_proctitle();

    set_progname(c"rust-openbsd-progname");
    assert_eq!(progname(), c"rust-openbsd-progname");

    // A high threshold closes nothing that the test harness uses.
    assert!(close_from(10_000).is_ok());
    assert!(dtable_count() > 0, "the standard descriptors were closed");

    exit_now(0);
}

/// `closefrom(2)` reports `EINVAL` for a negative threshold and accepts a
/// threshold above every open descriptor. CI runs this on OpenBSD 8.0 for amd64
/// and arm64; OpenBSD 7.9 is not in the CI matrix and must be checked manually.
#[test]
#[ignore = "isolated child process"]
fn child_close_from_error_contract() {
    assert_eq!(close_from(-1), Err(rust_openbsd::Errno::EINVAL));
    assert!(close_from(10_000).is_ok());
    exit_now(0);
}

#[test]
fn close_from_reports_documented_errors() {
    assert_success(&run_child("child_close_from_error_contract"));
}

/// On success `daemonize_with` never returns: the original process exits and
/// `body` runs in the detached child. Reaching the statement after the call
/// therefore means `fork(2)` failed, which the wrapper reports as `Err`.
#[test]
#[ignore = "isolated child process"]
fn child_daemonize_never_returns_on_success() {
    let options = DaemonOptions {
        change_directory_to_root: false,
        redirect_standard_streams: false,
    };
    let result = daemonize_with(options, || {});
    // Only a failed fork(2) returns here; that is a test failure.
    panic!("daemonize_with returned {result:?}");
}

/// `fork_exec_pledged` caps the caller's exec promises, so it must not run in
/// the shared test process.
#[test]
#[ignore = "isolated child process"]
fn child_fork_exec_pledged() {
    let probe = compile_exec_probe().expect("probe compiled by the parent");
    let mut command = std::process::Command::new(&probe);
    let status = fork_exec_pledged(&Promises::new([Promise::Stdio]), &mut command)
        .expect("fork_exec_pledged")
        .wait()
        .expect("wait");
    assert!(status.success(), "pledged child failed: {status:?}");
    exit_now(0);
}

/// `exec_pledged` replaces the image, so it must run in a child.
#[test]
#[ignore = "isolated child process"]
fn child_exec_pledged() {
    let probe = compile_exec_probe().expect("probe compiled by the parent");
    let mut command = std::process::Command::new(&probe);
    let error = exec_pledged(&Promises::new([Promise::Stdio]), &mut command);
    panic!("exec_pledged returned: {error}");
}

/// The static probe aborts when the execution promises forbid its `open(2)`.
#[test]
#[ignore = "isolated child process"]
fn child_exec_pledged_violation() {
    let probe = compile_exec_probe().expect("probe compiled by the parent");
    let mut command = std::process::Command::new(&probe);
    let _ = command.arg("violate");
    let error = exec_pledged(&Promises::new([Promise::Stdio]), &mut command);
    panic!("exec_pledged returned: {error}");
}

// ---------------------------------------------------------------------------
// Parent tests.
// ---------------------------------------------------------------------------

#[test]
fn process_state_is_queryable() {
    assert_success(&run_child("child_process_state"));
}

#[test]
fn daemonize_does_not_return_on_success() {
    assert_success(&run_child("child_daemonize_never_returns_on_success"));
}

#[test]
fn fork_exec_pledged_execs_under_the_ceiling() {
    if compile_exec_probe().is_none() {
        println!("SKIP fork_exec_pledged: system C compiler unavailable");
        return;
    }
    assert_success(&run_child("child_fork_exec_pledged"));
}

#[test]
fn exec_pledged_replaces_the_image() {
    if compile_exec_probe().is_none() {
        println!("SKIP exec_pledged: system C compiler unavailable");
        return;
    }
    assert_success(&run_child("child_exec_pledged"));
}

#[test]
fn exec_pledged_enforces_the_ceiling() {
    if compile_exec_probe().is_none() {
        println!("SKIP exec_pledged: system C compiler unavailable");
        return;
    }
    assert_sigabrt(&run_child("child_exec_pledged_violation"));
}

#[test]
fn fork_exec_runs_a_child() {
    let mut command = std::process::Command::new("/usr/bin/true");
    let status = fork_exec(&mut command)
        .expect("fork_exec")
        .wait()
        .expect("wait");
    assert!(status.success());
}

#[test]
fn dtable_count_reports_open_descriptors() {
    assert!(dtable_count() > 0);
}

#[test]
fn progname_is_available() {
    assert_ne!(progname().to_bytes().len(), 0);
}

/// `getexecpath(3)` is available from OpenBSD 8.0; run with
/// `cargo test --features openbsd-8-0` on 8.0 or later.
#[cfg(feature = "openbsd-8-0")]
#[test]
fn execpath_reports_the_running_executable() {
    let mut buf = [0_u8; rust_openbsd::PATH_MAX];
    let len = rust_openbsd::get_execpath(&mut buf).expect("getexecpath");
    assert!(len > 0, "empty executable path");

    let text = std::str::from_utf8(buf.get(..len).unwrap_or_default()).expect("UTF-8 path");
    assert!(text.starts_with('/'), "not an absolute path: {text}");
    assert_eq!(
        rust_openbsd::execpath().expect("execpath"),
        std::path::PathBuf::from(text)
    );
}
