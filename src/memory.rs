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

//! OpenBSD memory-protection and secure-memory helpers.
//!
//! * [`mimmutable`] wraps [`mimmutable(2)`](https://man.openbsd.org/mimmutable.2),
//!   which permanently forbids future changes to the protection or mapping of a
//!   memory region.
//! * [`explicit_bzero`] and [`freezero`] wrap
//!   [`explicit_bzero(3)`](https://man.openbsd.org/explicit_bzero.3) and
//!   [`freezero(3)`](https://man.openbsd.org/freezero.3) for secure erasure of
//!   native memory.
//! * [`timingsafe_bcmp`] and [`timingsafe_memcmp`] wrap
//!   [`timingsafe_bcmp(3)`](https://man.openbsd.org/timingsafe_bcmp.3) and
//!   [`timingsafe_memcmp(3)`](https://man.openbsd.org/timingsafe_memcmp.3) for
//!   constant-time byte-string comparison.
//!
//! Rust values are moved freely and may be copied, so the erasure functions
//! only make promises about the memory region they are given; they cannot
//! erase arbitrary values that the compiler may have copied elsewhere. The
//! constant-time comparisons are the recommended way to compare secrets such
//! as hashes and MACs; do not reimplement them with an early-exiting
//! comparison.

use core::{cmp::Ordering, ffi::c_void};

use crate::{
    error::Errno,
    ffi::{self, SUCCESS},
};

/// Permanently forbids future changes to the protection or mapping of the
/// memory containing `bytes`, as
/// [`mimmutable(2)`](https://man.openbsd.org/mimmutable.2).
///
/// The kernel aligns the range *outward* to whole pages, rounding the address
/// down and the length up, so the immutable region can extend beyond `bytes` on
/// either side. Most subsequent
/// [`mprotect(2)`](https://man.openbsd.org/mprotect.2),
/// [`munmap(2)`](https://man.openbsd.org/munmap.2),
/// [`madvise(2)`](https://man.openbsd.org/madvise.2),
/// [`msync(2)`](https://man.openbsd.org/msync.2),
/// [`mmap(2)`](https://man.openbsd.org/mmap.2), and
/// [`minherit(2)`](https://man.openbsd.org/minherit.2) operations on those
/// pages fail with [`Errno::EPERM`]. Reads and writes to the memory itself
/// remain allowed; the mechanism protects the *mapping*, not the contents. The
/// change is permanent.
///
/// # Safety
///
/// Because the range is rounded outward, every page that overlaps `bytes` is
/// marked immutable, including any bytes outside the slice. The caller must
/// ensure that all of those pages belong to a dedicated mapping that will not
/// be handed back to a memory manager: passing a slice into an ordinary Rust
/// allocation can freeze the allocator's own metadata, after which its
/// `mprotect(2)`/`munmap(2)` calls fail. Freeze only standalone mappings
/// created for the purpose (for example with
/// [`mmap(2)`](https://man.openbsd.org/mmap.2)), never heap memory.
///
/// # Errors
///
/// Errors if `mimmutable(2)` does: [`Errno::EINVAL`] for an invalid range, or
/// [`Errno::EPERM`] if a page inherits `MAP_INHERIT_ZERO`.
///
/// # Pledge
///
/// Allowed under the `stdio` promise.
#[expect(unsafe_code, reason = "mimmutable(2) takes a raw pointer")]
pub unsafe fn mimmutable(bytes: &[u8]) -> Result<(), Errno> {
    // SAFETY:
    // The caller guarantees that the page-rounded region overlapping `bytes`
    // is a dedicated mapping. `bytes` is a live slice and `len` is exactly its
    // length, so the pointer and length describe a valid region for the
    // duration of the call. `mimmutable(2)` only changes page metadata, never
    // the contents.
    let code = unsafe { ffi::mimmutable(bytes.as_ptr().cast::<c_void>().cast_mut(), bytes.len()) };
    if code == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Securely overwrites `buf` with zeroes, as
/// [`explicit_bzero(3)`](https://man.openbsd.org/explicit_bzero.3).
///
/// Unlike an ordinary zeroing loop, the write is not optimized away, so the
/// region cannot be recovered from memory afterward. An empty buffer is a
/// harmless no-op.
///
/// The function makes no claim about values the compiler may have copied to
/// other locations.
#[expect(unsafe_code, reason = "explicit_bzero(3) takes a raw pointer")]
#[inline]
pub fn explicit_bzero(buf: &mut [u8]) {
    // SAFETY:
    // `buf` is a live, writable slice and `len` is exactly its length, so the
    // native call may overwrite `len` bytes through the pointer.
    unsafe { ffi::explicit_bzero(buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
}

/// Zeroes and releases a `malloc(3)`-allocated region, as
/// [`freezero(3)`](https://man.openbsd.org/freezero.3).
///
/// The region of the given length (which must match the allocation) is
/// overwritten with zeroes and then freed.
///
/// # Safety
///
/// Ownership of `ptr` transfers to this function: the pointer must have been
/// returned by `malloc(3)` (or a compatible allocator) with at least `len`
/// bytes, and must not be used or freed again afterwards. `len` must match the
/// allocation size.
#[expect(unsafe_code, reason = "freezero(3) takes a raw pointer")]
#[inline]
pub unsafe fn freezero(ptr: *mut u8, len: usize) {
    // SAFETY:
    // The caller guarantees that `ptr` is a live `malloc(3)` allocation of at
    // least `len` bytes and that ownership transfers to this call.
    unsafe { ffi::freezero(ptr.cast::<c_void>(), len) };
}

/// Constant-time equality of two byte buffers, as
/// [`timingsafe_bcmp(3)`](https://man.openbsd.org/timingsafe_bcmp.3).
///
/// The comparison time depends only on the length of the shorter input, never
/// on where the first difference occurs, so it is suitable for comparing
/// secrets (hashes, MACs, keys). Buffers of different lengths are simply
/// unequal (a length is not secret material).
#[expect(unsafe_code, reason = "timingsafe_bcmp(3) takes raw pointers")]
#[must_use]
pub fn timingsafe_bcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // SAFETY:
    // Both slices are live, `a.len()` bytes long (`b` has the same length,
    // checked above), and readable. The native call only reads them. The
    // pointers are never dereferenced when the length is zero.
    unsafe {
        ffi::timingsafe_bcmp(
            a.as_ptr().cast::<c_void>(),
            b.as_ptr().cast::<c_void>(),
            a.len(),
        ) == 0
    }
}

/// Constant-time lexicographic comparison of two byte buffers, as
/// [`timingsafe_memcmp(3)`](https://man.openbsd.org/timingsafe_memcmp.3).
///
/// The common prefix is compared in constant time; ties are broken by length
/// (the shorter buffer sorts first), matching the native comparison semantics.
/// Suitable for ordering secret material without leaking where the first
/// difference occurs.
#[expect(unsafe_code, reason = "timingsafe_memcmp(3) takes raw pointers")]
#[must_use]
pub fn timingsafe_memcmp(a: &[u8], b: &[u8]) -> Ordering {
    let common = a.len().min(b.len());
    // SAFETY:
    // Both slices are live and at least `common` bytes long, and readable. The
    // native call only reads them. The pointers are never dereferenced when
    // `common` is zero.
    let result = unsafe {
        ffi::timingsafe_memcmp(
            a.as_ptr().cast::<c_void>(),
            b.as_ptr().cast::<c_void>(),
            common,
        )
    };
    match result.cmp(&0) {
        Ordering::Equal => a.len().cmp(&b.len()),
        other => other,
    }
}
