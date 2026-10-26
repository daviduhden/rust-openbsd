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

//! Conversions from Rust string and path types to `CStr`.
//!
//! This module deliberately has no dependencies beyond `core` (and `alloc` /
//! `std` when enabled). It exists so that the OpenBSD interfaces can accept
//! anything that can be viewed as a NUL-terminated byte string, including
//! paths that are not valid UTF-8.

#[cfg(feature = "alloc")]
use alloc::{ffi::CString, string::String};
use core::{ffi::CStr, mem::MaybeUninit, ptr, slice};
#[cfg(feature = "std")]
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    path::{Component, Components, Iter, Path, PathBuf},
};

use crate::error::Errno;

/// Anything that can be viewed as a NUL-terminated byte string.
///
/// The trait is the single entry point through which every OpenBSD interface in
/// this crate accepts paths and names. It is implemented for [`CStr`],
/// [`str`], `[u8]`, `&C`/`&mut C` where `C: CStrHelper`, and, with `alloc`, for
/// `CString` and `String`; the `std` feature adds [`OsStr`], [`OsString`],
/// `Cow<'_, OsStr>`, [`Path`], [`PathBuf`], `Component`, `Components`, and
/// `std::path::Iter`. No interface forces callers to produce valid UTF-8.
///
/// Implementors convert `self` to a [`CStr`] and then hand it to the provided
/// closure. The closure is used (rather than returning a borrowed `CStr`)
/// because some inputs need a temporary stack buffer for the terminating NUL.
/// The reference is valid only for the duration of the closure; never store it
/// or pass it to an API that retains the pointer.
///
/// The stack buffer is not zeroized. Callers that treat the input as secret
/// should prefer the length-delimited APIs (such as `bcrypt_pbkdf`) or erase
/// their own buffers with `explicit_bzero`.
pub trait CStrHelper {
    /// Converts `self` into a [`CStr`] before passing it into `f`.
    ///
    /// # Errors
    ///
    /// If an error occurs because the value contains an interior NUL byte,
    /// [`Errno::EINVAL`] is returned. If the value does not fit in the
    /// available buffer ([`alloc`](crate#alloc) disabled and the input longer
    /// than 1023 bytes), [`Errno::ERANGE`] is returned.
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(&self, f: F)
    -> Result<T, Errno>;
}

impl CStrHelper for CStr {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&Self) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        f(self)
    }
}

#[cfg(feature = "alloc")]
impl CStrHelper for CString {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_c_str().convert_then_apply(f)
    }
}

/// Converts `bytes` into a [`CStr`] via heap allocation before applying `f`.
#[cold]
#[inline(never)]
#[cfg(feature = "alloc")]
fn c_str_allocating<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
    bytes: &[u8],
    f: F,
) -> Result<T, Errno> {
    CString::new(bytes)
        .map_err(|_| Errno::EINVAL)
        .and_then(|c| f(&c))
}

impl CStrHelper for [u8] {
    #[expect(unsafe_code, reason = "a validated, initialized stack buffer is built")]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "`len + 1` cannot overflow because `len < C_STR_MAX_STACK_ALLOCATION`"
    )]
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        /// Maximum stack allocation for the `CStr` conversion.
        const C_STR_MAX_STACK_ALLOCATION: usize = 0x400;
        let len = self.len();
        if len < C_STR_MAX_STACK_ALLOCATION {
            let mut buf = MaybeUninit::<[u8; C_STR_MAX_STACK_ALLOCATION]>::uninit();
            let buf_ptr = buf.as_mut_ptr().cast();
            let slice_ptr = self.as_ptr();
            // SAFETY:
            // `slice_ptr` was created from `self`, which has length `len`, so it is valid for
            // `len` bytes. `buf_ptr` was created from `buf`, which has length
            // `C_STR_MAX_STACK_ALLOCATION > len`, so it is valid for `len` bytes as well.
            // `buf`, while uninitialized, is only written to before ever being read. Both
            // pointers are properly aligned and point to distinct allocations.
            unsafe { ptr::copy_nonoverlapping(slice_ptr, buf_ptr, len) };
            // SAFETY: `len` bytes were just written into `buf`, so `buf_ptr.add(len)` is in
            // bounds of the allocation and points at an uninitialized byte.
            let nul_pos = unsafe { buf_ptr.add(len) };
            // SAFETY: `nul_pos` is in bounds and writable.
            unsafe { nul_pos.write(0) };
            let final_len = len + 1;
            // SAFETY: the first `final_len` bytes of `buf` are initialized, aligned, valid, and
            // not null. `CStr::from_bytes_with_nul` does not mutate the slice.
            let raw_slice = unsafe { slice::from_raw_parts(buf_ptr, final_len) };
            CStr::from_bytes_with_nul(raw_slice)
                .map_err(|_| Errno::EINVAL)
                .and_then(f)
        } else {
            #[cfg(not(feature = "alloc"))]
            let res = Err(Errno::ERANGE);
            #[cfg(feature = "alloc")]
            let res = c_str_allocating(self, f);
            res
        }
    }
}

impl CStrHelper for str {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_bytes().convert_then_apply(f)
    }
}

#[cfg(feature = "alloc")]
impl CStrHelper for String {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_str().convert_then_apply(f)
    }
}

#[cfg(feature = "std")]
impl CStrHelper for OsStr {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_encoded_bytes().convert_then_apply(f)
    }
}

#[cfg(feature = "std")]
impl CStrHelper for OsString {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_os_str().convert_then_apply(f)
    }
}

#[cfg(feature = "std")]
impl CStrHelper for Cow<'_, OsStr> {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        (**self).convert_then_apply(f)
    }
}

#[cfg(feature = "std")]
impl CStrHelper for Path {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_os_str().convert_then_apply(f)
    }
}

#[cfg(feature = "std")]
impl CStrHelper for PathBuf {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_os_str().convert_then_apply(f)
    }
}

#[cfg(feature = "std")]
impl CStrHelper for Component<'_> {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_os_str().convert_then_apply(f)
    }
}

#[cfg(feature = "std")]
impl CStrHelper for Components<'_> {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_path().convert_then_apply(f)
    }
}

#[cfg(feature = "std")]
impl CStrHelper for Iter<'_> {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        self.as_path().convert_then_apply(f)
    }
}

impl<C: CStrHelper + ?Sized> CStrHelper for &C {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        (**self).convert_then_apply(f)
    }
}

impl<C: CStrHelper + ?Sized> CStrHelper for &mut C {
    #[inline]
    fn convert_then_apply<T, F: FnOnce(&CStr) -> Result<T, Errno>>(
        &self,
        f: F,
    ) -> Result<T, Errno> {
        (**self).convert_then_apply(f)
    }
}
