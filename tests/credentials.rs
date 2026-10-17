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

use rust_openbsd::{Errno, Gid, Uid, get_peer_credentials, is_setugid};

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
