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

//! The OpenBSD [`arc4random(3)`](https://man.openbsd.org/arc4random.3) family
//! and [`getentropy(2)`](https://man.openbsd.org/getentropy.2).
//!
//! The API name is historical: the underlying generator is ChaCha20-based,
//! re-seeded from the kernel with `getentropy(2)` (and on
//! [`fork(2)`](https://man.openbsd.org/fork.2)), and may be replaced again in
//! the future. These functions can be used in almost all coding environments,
//! including within [`chroot(2)`](https://man.openbsd.org/chroot.2); under
//! [`pledge(2)`](https://man.openbsd.org/pledge.2) the `stdio` promise is
//! sufficient.

use core::ffi::c_void;

use crate::{
    error::Errno,
    ffi::{self, SUCCESS},
};

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// The largest buffer [`get_entropy`] accepts, as documented by
/// [`getentropy(2)`](https://man.openbsd.org/getentropy.2).
pub const MAX_ENTROPY: usize = 256;

/// Returns a single uniformly distributed 32-bit value, as `arc4random()`.
#[inline]
#[must_use]
pub fn arc4_random() -> u32 {
    ffi::arc4random()
}

/// Returns a uniformly distributed 32-bit value strictly less than
/// `upper_bound`, as `arc4random_uniform()`.
///
/// This is preferred over computing `arc4_random() % upper_bound`: the native
/// function avoids modulo bias when the bound is not a power of two. The bound
/// is passed through unchanged, so `arc4_random_uniform(0)` and
/// `arc4_random_uniform(1)` both return `0`, matching the native semantics.
#[inline]
#[must_use]
pub fn arc4_random_uniform(upper_bound: u32) -> u32 {
    ffi::arc4random_uniform(upper_bound)
}

/// Fills `buf` with random bytes, as `arc4random_buf()`.
///
/// An empty buffer is a harmless no-op.
#[expect(unsafe_code, reason = "arc4random_buf(3) takes a raw pointer")]
#[inline]
pub fn arc4_random_buf(buf: &mut [u8]) {
    // SAFETY:
    // `buf` is a live, writable slice and `len` is exactly its length, so the
    // native call may write `len` bytes through the pointer. The pointer is
    // never dereferenced when the slice is empty.
    unsafe { ffi::arc4random_buf(buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
}

/// Fills a fresh [`Vec`] of `len` bytes with random bytes.
///
/// See [`arc4_random_buf`]. The buffer is allocated before it is filled, so an
/// allocation failure aborts the process through the global allocator error
/// handler; this infallible convenience cannot report it.
#[cfg(feature = "alloc")]
#[must_use]
pub fn arc4_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0_u8; len];
    arc4_random_buf(&mut buf);
    buf
}

/// Fills `buf` with `buf.len()` bytes of kernel entropy, as
/// [`getentropy(2)`](https://man.openbsd.org/getentropy.2).
///
/// A low-level primitive for specialized use (for example reseeding a custom
/// generator); ordinary random-number needs are better served by the
/// [`arc4_random`] family, which the OpenBSD manual recommends.
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] when `buf.len()` exceeds [`MAX_ENTROPY`], which
/// the native maximum request size rejects. An empty buffer is a harmless
/// no-op. Other errors come from `getentropy(2)`.
///
/// # Pledge
///
/// Allowed under the `stdio` promise.
#[expect(unsafe_code, reason = "getentropy(2) takes a raw pointer")]
pub fn get_entropy(buf: &mut [u8]) -> Result<(), Errno> {
    if buf.len() > MAX_ENTROPY {
        return Err(Errno::EINVAL);
    }
    // SAFETY:
    // `buf` is a live, writable slice and `len` is exactly its length, so the
    // native call may write `len` bytes through the pointer. The pointer is
    // never dereferenced when the slice is empty.
    let code = unsafe { ffi::getentropy(buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
    if code == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Returns a fresh [`Vec`] of `len` bytes of kernel entropy.
///
/// See [`get_entropy`]. The length is validated before the buffer is
/// allocated, so an oversized request fails with [`Errno::EINVAL`] instead of
/// attempting a huge allocation first.
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] when `len` exceeds [`MAX_ENTROPY`]; other errors
/// come from `get_entropy(2)`.
#[cfg(feature = "alloc")]
pub fn get_entropy_bytes(len: usize) -> Result<Vec<u8>, Errno> {
    if len > MAX_ENTROPY {
        return Err(Errno::EINVAL);
    }
    let mut buf = vec![0_u8; len];
    get_entropy(&mut buf)?;
    Ok(buf)
}
