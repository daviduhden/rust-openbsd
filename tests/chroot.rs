//! Kernel tests for [`chroot(2)`](https://man.openbsd.org/chroot.2).

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

use common::{assert_success, exit_now, is_root, run_child, skip_without_root};
use openbsd_rust::{Errno, account_by_name, chroot, enter_chroot, set_res_uid};

/// Path to the temporary root used by the `enter_chroot` test.
const CHROOT_DIR: &str = "/tmp/openbsd-rust-chroot-test";

/// `chroot(2)` requires root; an unprivileged process gets `EPERM`.
#[test]
#[ignore = "isolated child process"]
fn child_chroot_needs_privilege() {
    if is_root() {
        let account = account_by_name("nobody")
            .expect("lookup")
            .expect("nobody exists");
        let uid = account.uid();
        assert_eq!(set_res_uid(Some(uid), Some(uid), Some(uid)), Ok(()));
    }
    assert_eq!(chroot("/"), Err(Errno::EPERM));
    exit_now(0);
}

/// `enter_chroot` changes the root and cannot be escaped through `..`.
#[test]
#[ignore = "isolated child process"]
fn child_enter_chroot() {
    assert_eq!(enter_chroot(CHROOT_DIR), Ok(()));
    assert_eq!(
        std::env::current_dir().expect("current dir"),
        std::path::Path::new("/")
    );
    assert!(
        std::path::Path::new("/marker").exists(),
        "marker not visible"
    );
    assert!(
        !std::path::Path::new("/etc").exists(),
        "/etc visible inside the new root"
    );
    std::env::set_current_dir("..").expect("chdir ..");
    assert_eq!(
        std::env::current_dir().expect("current dir"),
        std::path::Path::new("/")
    );
    exit_now(0);
}

#[test]
fn chroot_without_privilege_is_eperm() {
    assert_success(&run_child("child_chroot_needs_privilege"));
}

#[test]
fn enter_chroot_confines_the_process() {
    if skip_without_root("enter_chroot_confines_the_process") {
        return;
    }
    std::fs::create_dir_all(CHROOT_DIR).expect("create chroot dir");
    std::fs::write(format!("{CHROOT_DIR}/marker"), b"inside").expect("write marker");

    let result = std::panic::catch_unwind(|| assert_success(&run_child("child_enter_chroot")));

    drop(std::fs::remove_file(format!("{CHROOT_DIR}/marker")));
    drop(std::fs::remove_dir(CHROOT_DIR));

    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}
