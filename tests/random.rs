//! Kernel tests for the random facilities.

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

use rust_openbsd::{
    Errno, MAX_ENTROPY, arc4_random, arc4_random_buf, arc4_random_uniform, get_entropy,
};

#[test]
fn arc4_random_returns() {
    let _ = arc4_random();
}

#[test]
fn arc4_random_buf_fills_distinct_buffers() {
    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    arc4_random_buf(&mut first);
    arc4_random_buf(&mut second);
    assert_ne!(first, [0_u8; 32], "the generator produced all zeroes");
    assert_ne!(first, second, "two 32-byte draws collided");
}

#[test]
fn arc4_random_uniform_respects_its_bound() {
    assert_eq!(arc4_random_uniform(0), 0);
    assert_eq!(arc4_random_uniform(1), 0);
    for _ in 0..64 {
        assert!(arc4_random_uniform(6) < 6);
    }
}

#[test]
fn get_entropy_enforces_the_native_limit() {
    let mut full = [0_u8; MAX_ENTROPY];
    assert_eq!(get_entropy(&mut full), Ok(()));

    let mut empty: [u8; 0] = [];
    assert_eq!(get_entropy(&mut empty), Ok(()));

    let mut too_big = [0_u8; MAX_ENTROPY + 1];
    assert_eq!(get_entropy(&mut too_big), Err(Errno::EINVAL));
}

#[cfg(feature = "alloc")]
#[test]
fn allocating_conveniences() {
    assert_eq!(rust_openbsd::arc4_random_bytes(16).len(), 16);
    assert_eq!(
        rust_openbsd::get_entropy_bytes(32).expect("entropy").len(),
        32
    );
    assert!(rust_openbsd::get_entropy_bytes(MAX_ENTROPY + 1).is_err());
}
