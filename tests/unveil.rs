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

//! Kernel tests for [`unveil(2)`](https://man.openbsd.org/unveil.2).

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

use common::{assert_sigabrt, assert_success, exit_now, run_child};
use rust_openbsd::{
    Errno, Permission, Permissions, Promise, Promises, lock_unveil, pledge, unveil, unveil_and_lock,
};

// ---------------------------------------------------------------------------
// Child processes.
// ---------------------------------------------------------------------------

/// A read-only rule permits reads and denies writes.
#[test]
#[ignore = "isolated child process"]
fn child_read_only_enforcement() {
    assert_eq!(unveil("/", Permissions::READ), Ok(()));
    assert_eq!(lock_unveil(), Ok(()));
    assert!(std::fs::read("/dev/null").is_ok(), "read should succeed");
    assert!(
        std::fs::write("/tmp/rust-openbsd-forbidden", "x").is_err(),
        "write should be denied"
    );
    exit_now(0);
}

/// The empty permission set unveils a path but grants nothing on it.
#[test]
#[ignore = "isolated child process"]
fn child_empty_permissions() {
    assert_eq!(unveil("/tmp", Permissions::NONE), Ok(()));
    assert_eq!(lock_unveil(), Ok(()));
    assert!(
        std::fs::read("/dev/null").is_err(),
        "empty permission set granted access"
    );
    exit_now(0);
}

/// Locking is irreversible.
#[test]
#[ignore = "isolated child process"]
fn child_lock_is_irreversible() {
    assert_eq!(unveil("/", Permissions::READ), Ok(()));
    assert_eq!(lock_unveil(), Ok(()));
    assert_eq!(unveil("/etc", Permissions::READ), Err(Errno::EPERM));
    exit_now(0);
}

/// A later rule for the same path replaces its permissions instead of adding
/// to them: the kernel stores exactly the flags of the most recent call.
#[test]
#[ignore = "isolated child process"]
fn child_repeated_rule_replaces_permissions() {
    assert_eq!(unveil("/", Permissions::READ), Ok(()));
    // Re-unveiling "/" with no permissions must replace the read rule, not
    // union with it.
    assert_eq!(unveil("/", Permissions::NONE), Ok(()));
    assert_eq!(lock_unveil(), Ok(()));
    assert!(
        std::fs::read("/dev/null").is_err(),
        "the replaced rule still granted read access"
    );
    exit_now(0);
}

/// A later rule may *widen* a path's permissions before locking: unveil
/// permissions are not monotonic. This is the opposite direction from
/// `child_repeated_rule_replaces_permissions`.
#[test]
#[ignore = "isolated child process"]
fn child_rule_can_be_widened_before_locking() {
    assert_eq!(unveil("/tmp", Permissions::READ), Ok(()));
    let read_write_create = Permissions::READ
        .enable(Permission::Write)
        .enable(Permission::Create);
    assert_eq!(unveil("/tmp", read_write_create), Ok(()));
    assert_eq!(lock_unveil(), Ok(()));
    let file = "/tmp/rust-openbsd-widen";
    std::fs::write(file, b"x").expect("write under widened /tmp");
    drop(std::fs::remove_file(file));
    exit_now(0);
}

/// A nonexistent directory component fails with `ENOENT`.
#[test]
#[ignore = "isolated child process"]
fn child_missing_directory() {
    assert_eq!(
        unveil("/rust-openbsd-no-such-dir/file", Permissions::READ),
        Err(Errno::ENOENT)
    );
    exit_now(0);
}

/// A path with an invalid UTF-8 byte sequence is accepted and usable.
#[test]
#[ignore = "isolated child process"]
fn child_non_utf8_path() {
    use std::os::unix::ffi::OsStrExt as _;

    let path =
        std::path::Path::new("/tmp").join(std::ffi::OsStr::from_bytes(b"rust-openbsd-\xff-name"));
    std::fs::write(&path, b"data").expect("create non-UTF-8 file");
    assert_eq!(unveil("/", Permissions::READ), Ok(()));
    assert_eq!(unveil(&path, Permissions::READ), Ok(()));
    assert_eq!(lock_unveil(), Ok(()));
    assert_eq!(std::fs::read(&path).expect("read unveiled file"), b"data");
    drop(std::fs::remove_file(&path));
    exit_now(0);
}

/// `unveil_and_lock` installs rules and locks in one transition.
#[test]
#[ignore = "isolated child process"]
fn child_unveil_and_lock() {
    let read_write_create = Permissions::READ
        .enable(Permission::Write)
        .enable(Permission::Create);
    assert_eq!(
        unveil_and_lock([("/", Permissions::READ), ("/tmp", read_write_create)]),
        Ok(())
    );
    assert_eq!(unveil("/etc", Permissions::READ), Err(Errno::EPERM));
    let file = "/tmp/rust-openbsd-unveil-write";
    std::fs::write(file, b"ok").expect("write under unveiled /tmp");
    std::fs::remove_file(file).expect("remove under unveiled /tmp");
    exit_now(0);
}

/// Calling `unveil(2)` without the `unveil` promise aborts the process.
#[test]
#[ignore = "isolated child process"]
fn child_pledge_requires_unveil_promise() {
    assert_eq!(pledge(&Promises::new([Promise::Stdio])), Ok(()));
    // This call violates the pledge and must abort before returning.
    let result = unveil("/", Permissions::READ);
    panic!("unveil without the unveil promise returned {result:?}");
}

// ---------------------------------------------------------------------------
// Parent tests.
// ---------------------------------------------------------------------------

#[test]
fn read_only_rules_are_enforced() {
    assert_success(&run_child("child_read_only_enforcement"));
}

#[test]
fn empty_permissions_grant_nothing() {
    assert_success(&run_child("child_empty_permissions"));
}

#[test]
fn locking_is_irreversible() {
    assert_success(&run_child("child_lock_is_irreversible"));
}

#[test]
fn repeated_rule_replaces_permissions() {
    assert_success(&run_child("child_repeated_rule_replaces_permissions"));
}

#[test]
fn rule_can_be_widened_before_locking() {
    assert_success(&run_child("child_rule_can_be_widened_before_locking"));
}

#[test]
fn missing_directory_is_enoent() {
    assert_success(&run_child("child_missing_directory"));
}

#[test]
fn non_utf8_paths_are_supported() {
    assert_success(&run_child("child_non_utf8_path"));
}

#[test]
fn unveil_and_lock_installs_and_locks() {
    assert_success(&run_child("child_unveil_and_lock"));
}

#[test]
fn unveil_requires_the_unveil_promise() {
    assert_sigabrt(&run_child("child_pledge_requires_unveil_promise"));
}
