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

//! Kernel tests for the memory-protection facilities.

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

use core::{cmp::Ordering, ffi::c_void, ptr, slice};

use rust_openbsd::{explicit_bzero, freezero, mimmutable, timingsafe_bcmp, timingsafe_memcmp};

/// `PROT_READ | PROT_WRITE` from OpenBSD's `<sys/mman.h>`.
const PROT_READ_WRITE: i32 = 0x1 | 0x2;
/// `MAP_ANON` from OpenBSD's `<sys/mman.h>`.
const MAP_ANON: i32 = 0x1000;
/// `MAP_PRIVATE` from OpenBSD's `<sys/mman.h>`.
const MAP_PRIVATE: i32 = 0x0002;

unsafe extern "C" {
    /// `malloc(3)`, only so `freezero(3)` can be exercised on real native memory.
    fn malloc(size: usize) -> *mut c_void;
    /// `mmap(2)` with a 64-bit `off_t`, as on OpenBSD/amd64 and OpenBSD/arm64.
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
}

#[test]
fn constant_time_equality() {
    assert!(timingsafe_bcmp(b"secret", b"secret"));
    assert!(!timingsafe_bcmp(b"secret", b"secreT"));
    assert!(!timingsafe_bcmp(b"", b"secret"));
    assert!(!timingsafe_bcmp(b"secret", b""));
    assert!(timingsafe_bcmp(b"", b""));
}

#[test]
fn constant_time_order() {
    assert_eq!(timingsafe_memcmp(b"abc", b"abc"), Ordering::Equal);
    assert_eq!(timingsafe_memcmp(b"abc", b"abd"), Ordering::Less);
    assert_eq!(timingsafe_memcmp(b"abd", b"abc"), Ordering::Greater);
    assert_eq!(timingsafe_memcmp(b"ab", b"abc"), Ordering::Less);
    assert_eq!(timingsafe_memcmp(b"abc", b"ab"), Ordering::Greater);
    assert_eq!(timingsafe_memcmp(b"", b""), Ordering::Equal);
}

#[test]
fn explicit_bzero_clears_the_buffer() {
    let mut secret = [1_u8; 32];
    explicit_bzero(&mut secret);
    assert_eq!(secret, [0_u8; 32]);
}

#[test]
fn freezero_releases_native_memory() {
    // SAFETY: `malloc(3)` has no preconditions and returns a live allocation or
    // null.
    let region = unsafe { malloc(64) };
    assert!(!region.is_null(), "malloc(3) failed");
    // SAFETY: `region` is a live `malloc(3)` allocation of 64 bytes and
    // ownership transfers to `freezero`.
    unsafe { freezero(region.cast::<u8>(), 64) };
}

#[test]
fn mimmutable_freezes_a_mapping() {
    // A page-aligned anonymous mapping, as `mimmutable(2)` requires a valid
    // mapped range rather than a slice of the allocator's heap.
    //
    // SAFETY: `mmap(2)` with these arguments is always safe to call; the result
    // is checked for `MAP_FAILED` before use.
    let page = unsafe {
        mmap(
            ptr::null_mut(),
            4096,
            PROT_READ_WRITE,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0,
        )
    };
    assert_ne!(page as isize, -1, "mmap(2) failed");
    // SAFETY: `page` is a live mapping of 4096 readable bytes that is never
    // freed (it is immutable, so it cannot be).
    let region = unsafe { slice::from_raw_parts(page.cast::<u8>(), 4096) };
    // SAFETY: `region` is exactly one page of a dedicated anonymous mapping
    // that is deliberately never unmapped and never returned to the allocator,
    // so rounding the range outward to page boundaries only touches this
    // mapping.
    assert_eq!(unsafe { mimmutable(region) }, Ok(()));
}
