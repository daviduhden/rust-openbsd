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

//! Kernel tests for [`pledge(2)`](https://man.openbsd.org/pledge.2).
//!
//! Every case that changes process-wide state runs in an isolated child process
//! and verifies the result against the running kernel. `SIGABRT` is the normal
//! outcome of a pledge violation and is inspected from the child's termination
//! status.

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

use std::{os::unix::process::ExitStatusExt as _, process::Command};

use common::{SIGABRT, assert_sigabrt, assert_signal, assert_success, exit_now, run_child};
use rust_openbsd::{
    Errno, Promise, Promises, pledge, pledge_both, pledge_child, pledge_parts, pledge_raw,
};

// ---------------------------------------------------------------------------
// Child processes (run only through `run_child`).
// ---------------------------------------------------------------------------

/// A valid promise set is accepted and the process keeps working.
#[test]
#[ignore = "isolated child process"]
fn child_valid_promises() {
    let promises = Promises::new([Promise::Stdio, Promise::Rpath]);
    assert_eq!(pledge(&promises), Ok(()));
    assert_eq!(pledge(&promises), Ok(()));
    exit_now(0);
}

/// The kernel accepts every promise name in the inventory: a single `pledge(2)`
/// with all of them fails with `EINVAL` if any name is obsolete or misspelled.
/// This complements the pure unit test, which only round-trips the Rust table.
#[test]
#[ignore = "isolated child process"]
fn child_all_promise_names_accepted() {
    assert_eq!(pledge(&Promises::ALL), Ok(()));
    exit_now(0);
}

/// `NULL` leaves a value unchanged; an increase is still rejected.
#[test]
#[ignore = "isolated child process"]
fn child_null_changes_nothing() {
    assert_eq!(pledge(&Promises::new([Promise::Stdio])), Ok(()));
    assert_eq!(pledge_parts(None, None), Ok(()));
    assert_eq!(
        pledge(&Promises::new([Promise::Stdio, Promise::Rpath])),
        Err(Errno::EPERM)
    );
    exit_now(0);
}

/// `NULL` promises with an empty exec-promise set restricts only children.
#[test]
#[ignore = "isolated child process"]
fn child_null_promises_empty_exec() {
    assert_eq!(pledge(&Promises::new([Promise::Stdio])), Ok(()));
    assert_eq!(pledge_parts(None, Some(&Promises::NONE)), Ok(()));
    // The current process is unrestricted beyond its existing promises and must
    // remain able to call `pledge(2)` again with the same set.
    assert_eq!(pledge(&Promises::new([Promise::Stdio])), Ok(()));
    exit_now(0);
}

/// Promise reductions are allowed and cannot be undone.
#[test]
#[ignore = "isolated child process"]
fn child_monotonic_reduction() {
    let mut promises = Promises::new([Promise::Stdio, Promise::Rpath]);
    assert_eq!(pledge(&promises), Ok(()));
    assert_eq!(
        pledge(&Promises::new([Promise::Stdio, Promise::Rpath])),
        Ok(())
    );
    assert_eq!(promises.remove_then_pledge(Promise::Rpath), Ok(()));
    assert!(!promises.contains(Promise::Rpath));
    // Removing an already-removed promise is a no-op and must not call pledge.
    assert_eq!(promises.remove_then_pledge(Promise::Rpath), Ok(()));
    // The removed promise cannot be restored.
    assert_eq!(
        pledge(&Promises::new([Promise::Stdio, Promise::Rpath])),
        Err(Errno::EPERM)
    );
    exit_now(0);
}

/// Exec promises cannot be widened once set.
#[test]
#[ignore = "isolated child process"]
fn child_exec_increase_is_eperm() {
    assert_eq!(
        pledge_both(
            &Promises::new([Promise::Stdio]),
            &Promises::new([Promise::Stdio])
        ),
        Ok(())
    );
    assert_eq!(
        pledge_child(&Promises::new([Promise::Stdio, Promise::Rpath])),
        Err(Errno::EPERM)
    );
    exit_now(0);
}

/// The `error` promise turns a violation into `ENOSYS` instead of `SIGABRT`.
#[test]
#[ignore = "isolated child process"]
#[cfg(not(feature = "openbsd-8-0"))]
fn child_error_promise_returns_enosys() {
    assert_eq!(
        pledge(&Promises::new([Promise::Stdio, Promise::Error])),
        Ok(())
    );
    let error = std::fs::metadata("/").expect_err("stat(2) must be denied");
    assert_eq!(error.raw_os_error(), Some(Errno::ENOSYS.into_raw()));
    exit_now(0);
}

/// The `error` promise also makes promise increases silently succeed.
#[test]
#[ignore = "isolated child process"]
#[cfg(not(feature = "openbsd-8-0"))]
fn child_error_promise_ignores_increase() {
    assert_eq!(
        pledge(&Promises::new([Promise::Stdio, Promise::Error])),
        Ok(())
    );
    assert_eq!(
        pledge(&Promises::new([
            Promise::Stdio,
            Promise::Error,
            Promise::Rpath,
            Promise::Inet,
        ])),
        Ok(())
    );
    exit_now(0);
}

/// `pledge_raw` preserves the native `NULL` / empty-string distinction and
/// reports unknown promises with `EINVAL`.
#[test]
#[ignore = "isolated child process"]
fn child_pledge_raw() {
    assert_eq!(pledge_raw(Some(c"stdio rpath"), None), Ok(()));
    assert_eq!(pledge_raw(None, None), Ok(()));
    assert_eq!(pledge_raw(Some(c"tmppath"), None), Err(Errno::EINVAL));
    assert_eq!(
        pledge_raw(Some(c"stdio rpath inet"), None),
        Err(Errno::EPERM)
    );
    exit_now(0);
}

/// `pledge_raw` with an empty string requests an empty promise set for the
/// argument it is applied to.
///
/// Only the *exec* promise set is exercised here: it does not restrict the
/// current process. The empty *current* promise set is exercised by the
/// single-threaded `new_empty_promise_set_probe` tests below, because reducing
/// a multithreaded process to the `_exit`-only state makes the kernel unwind
/// sibling threads.
#[test]
#[ignore = "isolated child process"]
fn child_pledge_raw_empty_exec() {
    assert_eq!(pledge_raw(None, Some(c"")), Ok(()));
    // The current process keeps its (unrestricted) promises.
    drop(std::fs::metadata("/"));
    exit_now(0);
}

/// Exec promises set in a parent apply to a program started with `execve(2)`.
#[test]
#[ignore = "isolated child process"]
fn child_exec_promises_apply() {
    let probe = common::compile_exec_probe().expect("probe compiled by the parent");
    assert_eq!(pledge_child(&Promises::new([Promise::Stdio])), Ok(()));

    let allowed = Command::new(&probe).output().expect("run probe");
    assert!(
        allowed.status.success(),
        "allowed probe failed: {allowed:?}\nstderr:\n{}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    let forbidden = Command::new(&probe)
        .arg("violate")
        .output()
        .expect("run probe");
    assert_signal(&forbidden, SIGABRT);
    exit_now(0);
}

/// Exec promises set to the empty set prevent a child from initializing.
#[test]
#[ignore = "isolated child process"]
fn child_empty_exec_promises_abort_child() {
    assert_eq!(pledge_child(&Promises::NONE), Ok(()));
    let status = Command::new("/usr/bin/true").status().expect("run true");
    assert_eq!(status.signal(), Some(SIGABRT));
    exit_now(0);
}

// ---------------------------------------------------------------------------
// Parent tests that spawn the child processes and inspect their status.
// ---------------------------------------------------------------------------

#[test]
fn valid_promises_are_accepted() {
    assert_success(&run_child("child_valid_promises"));
}

#[test]
fn all_promise_names_are_accepted_by_the_kernel() {
    assert_success(&run_child("child_all_promise_names_accepted"));
}

#[test]
fn null_arguments_change_nothing() {
    assert_success(&run_child("child_null_changes_nothing"));
}

#[test]
fn null_promises_with_empty_exec_promises() {
    assert_success(&run_child("child_null_promises_empty_exec"));
}

#[test]
fn promise_reduction_is_monotonic() {
    assert_success(&run_child("child_monotonic_reduction"));
}

#[test]
fn exec_promise_increase_is_eperm() {
    assert_success(&run_child("child_exec_increase_is_eperm"));
}

#[test]
fn empty_promise_set_allows_exit() {
    let Some(probe) = common::compile_empty_pledge_probe() else {
        println!("SKIP empty-promises: system C compiler unavailable");
        return;
    };
    let output = Command::new(&probe).output().expect("run probe");
    assert!(
        output.status.success(),
        "empty promise set probe failed: {output:?}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(std::fs::remove_file(&probe));
}

#[test]
fn empty_promise_set_aborts_on_activity() {
    let Some(probe) = common::compile_empty_pledge_probe() else {
        println!("SKIP empty-promises: system C compiler unavailable");
        return;
    };
    let output = Command::new(&probe)
        .arg("violate")
        .output()
        .expect("run probe");
    assert_sigabrt(&output);
    drop(std::fs::remove_file(&probe));
}

#[test]
#[cfg(not(feature = "openbsd-8-0"))]
fn error_promise_returns_enosys() {
    assert_success(&run_child("child_error_promise_returns_enosys"));
}

#[test]
#[cfg(not(feature = "openbsd-8-0"))]
fn error_promise_ignores_promise_increase() {
    assert_success(&run_child("child_error_promise_ignores_increase"));
}

#[test]
fn raw_pledge_semantics() {
    assert_success(&run_child("child_pledge_raw"));
}

#[test]
fn raw_pledge_empty_exec_promises() {
    assert_success(&run_child("child_pledge_raw_empty_exec"));
}

#[test]
fn exec_promises_apply_to_executed_programs() {
    if common::compile_exec_probe().is_none() {
        println!("SKIP exec-promises: system C compiler unavailable");
        return;
    }
    assert_success(&run_child("child_exec_promises_apply"));
}

#[test]
fn empty_exec_promises_abort_executed_programs() {
    assert_success(&run_child("child_empty_exec_promises_abort_child"));
}
