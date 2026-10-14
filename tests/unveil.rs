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
