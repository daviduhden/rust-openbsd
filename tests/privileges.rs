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

//! Kernel tests for the privilege-dropping sequence.
//!
//! Tests that change credentials run in an isolated child process. Tests that
//! require root skip cleanly when the runner is not root; they are executed
//! separately in a privileged CI stage.

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
use rust_openbsd::{
    Errno, Gid, GroupPolicy, PrivDropError, Promise, Promises, Uid, account_by_name,
    drop_privileges, drop_privileges_to, drop_privileges_with, get_res_gid, get_res_uid, groups,
    pledge, set_res_gid, set_res_uid,
};

// ---------------------------------------------------------------------------
// Child processes.
// ---------------------------------------------------------------------------

/// Dropping to `nobody` installs every credential flavor and cannot be undone.
#[test]
#[ignore = "isolated child process"]
fn child_drop_privileges_fully() {
    let account = account_by_name("nobody")
        .expect("lookup")
        .expect("nobody exists");
    let uid = account.uid();
    let gid = account.gid();

    assert_eq!(drop_privileges("nobody"), Ok(()));

    let (ruid, euid, suid) = get_res_uid().expect("getresuid");
    assert_eq!((ruid, euid, suid), (uid, uid, uid));
    let (rgid, egid, sgid) = get_res_gid().expect("getresgid");
    assert_eq!((rgid, egid, sgid), (gid, gid, gid));
    assert_eq!(groups().expect("getgroups").as_slice(), &[gid]);

    // Root must not be regainingable through the saved IDs.
    assert_eq!(
        set_res_uid(Some(Uid::ROOT), Some(Uid::ROOT), Some(Uid::ROOT)),
        Err(Errno::EPERM)
    );
    assert_eq!(
        set_res_gid(Some(Gid::ROOT), Some(Gid::ROOT), Some(Gid::ROOT)),
        Err(Errno::EPERM)
    );
    exit_now(0);
}

/// The `Initgroups` policy adopts the account's group memberships.
#[test]
#[ignore = "isolated child process"]
fn child_drop_privileges_initgroups() {
    let account = account_by_name("nobody")
        .expect("lookup")
        .expect("nobody exists");
    let gid = account.gid();

    assert_eq!(
        drop_privileges_with(GroupPolicy::Initgroups, "nobody"),
        Ok(())
    );

    let (rgid, egid, sgid) = get_res_gid().expect("getresgid");
    assert_eq!((rgid, egid, sgid), (gid, gid, gid));
    assert!(
        groups().expect("getgroups").as_slice().contains(&gid),
        "primary gid missing from supplementary groups"
    );
    exit_now(0);
}

/// Dropping to a previously resolved account works.
#[test]
#[ignore = "isolated child process"]
fn child_drop_privileges_to() {
    let account = account_by_name("nobody")
        .expect("lookup")
        .expect("nobody exists");
    let uid = account.uid();
    assert_eq!(
        drop_privileges_to(GroupPolicy::PrimaryGroupOnly, account),
        Ok(())
    );
    let (ruid, euid, suid) = get_res_uid().expect("getresuid");
    assert_eq!((ruid, euid, suid), (uid, uid, uid));
    exit_now(0);
}

/// An unknown account is reported instead of silently succeeding.
#[test]
#[ignore = "isolated child process"]
fn child_drop_unknown_account() {
    assert_eq!(
        drop_privileges("rust-openbsd-no-such-user"),
        Err(PrivDropError::NoSuchAccount)
    );
    exit_now(0);
}

/// Dropping without sufficient privilege fails with `EPERM`.
#[test]
#[ignore = "isolated child process"]
fn child_drop_without_privilege() {
    match drop_privileges("nobody") {
        Err(PrivDropError::SetSupplementaryGroups(Errno::EPERM)) => {}
        other => panic!("expected EPERM from setgroups(2), got {other:?}"),
    }
    exit_now(0);
}

/// The native `-1` passthrough leaves the IDs unchanged.
#[test]
#[ignore = "isolated child process"]
fn child_set_res_passthrough() {
    let before_uid = get_res_uid().expect("getresuid");
    assert_eq!(set_res_uid(None, None, None), Ok(()));
    assert_eq!(get_res_uid().expect("getresuid"), before_uid);
    let before_gid = get_res_gid().expect("getresgid");
    assert_eq!(set_res_gid(None, None, None), Ok(()));
    assert_eq!(get_res_gid().expect("getresgid"), before_gid);
    exit_now(0);
}

/// The `id` promise can be removed after the drop is complete.
#[test]
#[ignore = "isolated child process"]
fn child_pledge_id_lifecycle() {
    let account = account_by_name("nobody")
        .expect("lookup")
        .expect("nobody exists");
    let uid = account.uid();

    assert_eq!(
        pledge(&Promises::new([
            Promise::Stdio,
            Promise::Getpw,
            Promise::Id
        ])),
        Ok(())
    );
    assert_eq!(drop_privileges("nobody"), Ok(()));
    assert_eq!(pledge(&Promises::new([Promise::Stdio])), Ok(()));

    let (ruid, euid, suid) = get_res_uid().expect("getresuid");
    assert_eq!((ruid, euid, suid), (uid, uid, uid));
    exit_now(0);
}

// ---------------------------------------------------------------------------
// Parent tests.
// ---------------------------------------------------------------------------

#[test]
fn account_resolution() {
    let root = account_by_name("root")
        .expect("lookup root")
        .expect("root exists");
    assert_eq!(root.uid(), Uid::ROOT);
    assert_eq!(root.name(), c"root");
    assert!(
        account_by_name("rust-openbsd-no-such-user")
            .expect("lookup unknown")
            .is_none()
    );
}

#[test]
fn drop_privileges_fully_drops_identity() {
    if skip_without_root("drop_privileges_fully_drops_identity") {
        return;
    }
    assert_success(&run_child("child_drop_privileges_fully"));
}

#[test]
fn drop_privileges_initgroups_policy() {
    if skip_without_root("drop_privileges_initgroups_policy") {
        return;
    }
    assert_success(&run_child("child_drop_privileges_initgroups"));
}

#[test]
fn drop_privileges_to_resolved_account() {
    if skip_without_root("drop_privileges_to_resolved_account") {
        return;
    }
    assert_success(&run_child("child_drop_privileges_to"));
}

#[test]
fn unknown_account_is_reported() {
    assert_success(&run_child("child_drop_unknown_account"));
}

#[test]
fn drop_without_privilege_is_eperm() {
    if is_root() {
        println!("SKIP drop_without_privilege_is_eperm: running as root");
        return;
    }
    assert_success(&run_child("child_drop_without_privilege"));
}

#[test]
fn set_res_passthrough_leaves_ids_unchanged() {
    assert_success(&run_child("child_set_res_passthrough"));
}

#[test]
fn id_promise_can_be_removed_after_dropping() {
    if skip_without_root("id_promise_can_be_removed_after_dropping") {
        return;
    }
    assert_success(&run_child("child_pledge_id_lifecycle"));
}
