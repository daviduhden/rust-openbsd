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

/// `PROT_READ` from OpenBSD's `<sys/mman.h>`.
const PROT_READ: i32 = 0x1;
/// `PROT_READ | PROT_WRITE` from OpenBSD's `<sys/mman.h>`.
const PROT_READ_WRITE: i32 = 0x1 | 0x2;
/// `MAP_ANON` from OpenBSD's `<sys/mman.h>`.
const MAP_ANON: i32 = 0x1000;
/// `MAP_PRIVATE` from OpenBSD's `<sys/mman.h>`.
const MAP_PRIVATE: i32 = 0x0002;
/// `MAP_FIXED` from OpenBSD's `<sys/mman.h>`.
const MAP_FIXED: i32 = 0x0010;

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
    /// `mprotect(2)`.
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    /// `munmap(2)`.
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    /// The raw `mimmutable(2)` call, used to describe a range that contains an
    /// unmapped hole. The safe wrapper takes `&[u8]`, which cannot represent a
    /// hole without creating a slice over invalid memory.
    #[link_name = "mimmutable"]
    fn mimmutable_raw(addr: *mut c_void, len: usize) -> i32;
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
fn mimmutable_empty_slice_is_a_noop() {
    let empty: [u8; 0] = [];
    // SAFETY: the wrapper returns before entering the kernel for an empty
    // slice, so no mapping is frozen.
    assert_eq!(unsafe { mimmutable(&empty) }, Ok(()));
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

#[test]
fn mimmutable_skips_unmapped_holes() {
    let page_size = 4096_usize;
    let length = 3 * page_size;
    // SAFETY: `mmap(2)` with these arguments is always safe to call; the result
    // is checked for `MAP_FAILED` before use.
    let base = unsafe {
        mmap(
            ptr::null_mut(),
            length,
            PROT_READ_WRITE,
            MAP_ANON | MAP_PRIVATE,
            -1,
            0,
        )
    };
    assert_ne!(base as isize, -1, "mmap(2) failed");

    // Punch a one-page hole in the middle of the mapping.
    // SAFETY: `base + page_size` is the second page of the live mapping.
    let middle = unsafe { base.cast::<u8>().add(page_size) };
    // SAFETY: `middle` is the second page of the three-page live mapping.
    assert_eq!(unsafe { munmap(middle.cast(), page_size) }, 0, "munmap(2)");

    // Freeze the range covering both remaining pages and the hole. This uses
    // the raw syscall because the safe wrapper takes `&[u8]`, and a slice
    // cannot span an unmapped hole without being invalid.
    // SAFETY: the range starts at a dedicated anonymous mapping; the middle
    // page is unmapped, so freezing the outer pages does not affect allocator
    // metadata.
    let code = unsafe { mimmutable_raw(base, length) };
    assert_eq!(code, 0, "mimmutable(2) with a hole");

    // Map a fresh page into the hole. The kernel did not mark unmapped pages
    // immutable, so this mapping must remain mutable.
    // SAFETY: `MAP_FIXED` at the address of the hole is valid; the result is
    // checked for `MAP_FAILED`.
    let replacement = unsafe {
        mmap(
            middle.cast(),
            page_size,
            PROT_READ_WRITE,
            MAP_ANON | MAP_PRIVATE | MAP_FIXED,
            -1,
            0,
        )
    };
    assert_ne!(replacement as isize, -1, "mmap(2) into the hole failed");
    // SAFETY: `replacement` is a live page mapped into the former hole.
    let code = unsafe { mprotect(replacement, page_size, PROT_READ) };
    assert_eq!(
        code, 0,
        "a page mapped into an unmapped hole must not be immutable"
    );
}

#[test]
fn mimmutable_blocks_later_protection_changes() {
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
    // SAFETY: `page` is a live mapping of 4096 bytes that is deliberately never
    // freed.
    let region = unsafe { slice::from_raw_parts(page.cast::<u8>(), 4096) };
    // SAFETY: `region` is a dedicated page-aligned anonymous mapping, never
    // returned to a memory manager.
    assert_eq!(unsafe { mimmutable(region) }, Ok(()));
    // Removing write permission is a real protection change and must now fail.
    // SAFETY: `page` is a live mapping; `mprotect(2)` only changes protection.
    let rc = unsafe { mprotect(page, 4096, PROT_READ) };
    assert_eq!(
        rc, -1,
        "mprotect(2) unexpectedly succeeded on immutable memory"
    );
    assert_eq!(
        rust_openbsd::Errno::last(),
        rust_openbsd::Errno::EPERM,
        "unexpected errno from mprotect(2)"
    );
}
