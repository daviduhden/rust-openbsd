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

//! Kernel tests for routing domains.

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

use rust_openbsd::{Rtable, Uid, get_rtable, set_rtable};

#[test]
fn the_default_domain_is_queryable_and_settable() {
    let current = get_rtable().expect("getrtable");
    // Changing the domain to its current (default) value is permitted without
    // privileges; it is a no-op rather than a restriction.
    if current == Rtable::DEFAULT {
        assert_eq!(set_rtable(Rtable::DEFAULT), Ok(()));
    }
    assert_eq!(get_rtable().expect("getrtable"), current);
}

#[test]
fn an_unknown_domain_is_rejected() {
    if Uid::geteuid().is_root() {
        // As root, setting an existing domain would succeed and change this
        // process's routing state for the rest of the test binary.
        println!("SKIP an_unknown_domain_is_rejected: running as root");
        return;
    }
    // Only domain 0 exists by default; anything else fails (EPERM without
    // privileges, or EINVAL for a missing domain).
    assert!(set_rtable(Rtable::new(1)).is_err());
}
