// Copyright (c) 2026, David Uhden Collado <david@uhden.dev>
// Copyright (c) 2024-2026, Zack Newman <zack@philomathiclife.com>
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

//! Kernel tests for the credential queries.

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

use std::os::fd::AsRawFd;

use rust_openbsd::{Errno, Gid, Promise, Promises, Uid, get_peer_credentials, is_setugid, pledge};

mod common;

use common::{assert_sigabrt, assert_success, exit_now, run_child};

#[test]
fn the_test_binary_is_not_set_id_tainted() {
    // A sanity check, not a proof: the test runner is an ordinary binary, so
    // `issetugid(2)` must report an untainted image.
    assert!(!is_setugid());
}

#[test]
fn peer_credentials_match_the_process_credentials() {
    let (local, _remote) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let (uid, gid) = get_peer_credentials(local.as_raw_fd()).expect("getpeereid");
    // Both ends are this process, so the peer credentials are our own.
    assert_eq!(uid, Uid::geteuid());
    assert_eq!(gid, Gid::getegid());
}

#[test]
fn invalid_descriptors_are_reported() {
    assert!(matches!(get_peer_credentials(-1), Err(Errno::EBADF)));
}

/// `getpeereid(3)` is a `getsockopt(2)` call; `stdio` plus `unix` must allow it.
#[test]
#[ignore = "isolated child process"]
fn child_peer_credentials_with_unix_promise() {
    let (local, _remote) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    if pledge(&Promises::new([Promise::Stdio, Promise::Unix])).is_err() {
        exit_now(1);
    }
    match get_peer_credentials(local.as_raw_fd()) {
        Ok((uid, gid)) if uid == Uid::geteuid() && gid == Gid::getegid() => exit_now(0),
        Ok(_) => exit_now(2),
        Err(_) => exit_now(3),
    }
}

/// With only `stdio`, the `getsockopt(2)` path must be a pledge violation.
#[test]
#[ignore = "isolated child process"]
fn child_peer_credentials_without_socket_promise_aborts() {
    let (local, _remote) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    if pledge(&Promises::new([Promise::Stdio])).is_err() {
        exit_now(1);
    }
    let _ = get_peer_credentials(local.as_raw_fd());
    // The kernel should have aborted before this point. Exit with a normal
    // status so the parent can distinguish the missing violation from SIGABRT.
    exit_now(2);
}

#[test]
fn peer_credentials_work_with_unix_promise() {
    assert_success(&run_child("child_peer_credentials_with_unix_promise"));
}

#[test]
fn peer_credentials_require_a_socket_promise() {
    assert_sigabrt(&run_child(
        "child_peer_credentials_without_socket_promise_aborts",
    ));
}
