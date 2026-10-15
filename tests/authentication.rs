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

//! Kernel tests for password hashing and key derivation.

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

use rust_openbsd::{Errno, bcrypt_pbkdf, crypt_checkpass, crypt_newhash};

#[test]
fn password_hash_round_trip() {
    let hash =
        crypt_newhash(&b"correct horse battery staple"[..], "bcrypt,4").expect("crypt_newhash");
    assert_eq!(&hash[..1], b"$", "unexpected hash format: {hash:?}");

    assert_eq!(
        crypt_checkpass(&b"correct horse battery staple"[..], hash.as_slice()),
        Ok(true)
    );
    assert_eq!(
        crypt_checkpass(&b"wrong password"[..], hash.as_slice()),
        Ok(false)
    );
}

#[test]
fn invalid_preference_is_rejected() {
    assert!(matches!(
        crypt_newhash(&b"x"[..], "no-such-algorithm"),
        Err(Errno::EINVAL)
    ));
}

#[test]
fn interior_nul_bytes_are_rejected() {
    assert_eq!(
        crypt_checkpass(
            &b"secret\0hidden"[..],
            &b"$2b$04$abcdefghijklmnopqrstuv"[..]
        ),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        crypt_newhash(&b"secret\0hidden"[..], "bcrypt,4"),
        Err(Errno::EINVAL)
    );
}

#[test]
fn key_derivation_is_deterministic_and_salt_sensitive() {
    let first = bcrypt_pbkdf(&b"password"[..], &b"salt"[..], 4, 32).expect("bcrypt_pbkdf");
    let again = bcrypt_pbkdf(&b"password"[..], &b"salt"[..], 4, 32).expect("bcrypt_pbkdf");
    let other = bcrypt_pbkdf(&b"password"[..], &b"other-salt"[..], 4, 32).expect("bcrypt_pbkdf");

    assert_eq!(first.len(), 32);
    assert_ne!(first, [0_u8; 32]);
    assert_eq!(first, again);
    assert_ne!(first, other);
}

#[test]
fn key_derivation_supports_in_place_buffers() {
    let mut key = [0_u8; 16];
    assert_eq!(
        rust_openbsd::bcrypt_pbkdf_into(&b"pw"[..], &b"s"[..], 4, &mut key),
        Ok(())
    );
    assert_ne!(key, [0_u8; 16]);
}
