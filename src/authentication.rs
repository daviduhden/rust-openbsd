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

//! OpenBSD password hashing and key derivation.
//!
//! * [`crypt_checkpass`] wraps
//!   [`crypt_checkpass(3)`](https://man.openbsd.org/crypt_checkpass.3), which
//!   verifies a password against a hash.
//! * [`crypt_newhash`] wraps
//!   [`crypt_newhash(3)`](https://man.openbsd.org/crypt_newhash.3), which
//!   creates a new salted password hash.
//! * [`bcrypt_pbkdf`] wraps
//!   [`bcrypt_pbkdf(3)`](https://man.openbsd.org/bcrypt_pbkdf.3), bcrypt-based
//!   password key derivation.
//!
//! These call OpenBSD's implementations directly; no cryptographic code lives
//! in this crate. The `crypt_*` functions convert their arguments through
//! [`CStrHelper`], so inputs containing an interior NUL byte are rejected with
//! [`Errno::EINVAL`] rather than being silently truncated. [`bcrypt_pbkdf`] and
//! [`bcrypt_pbkdf_into`] take length-delimited byte slices and therefore accept
//! NUL bytes.
//!
//! Passwords are never logged or embedded in error values, but this crate
//! cannot guarantee that every transient copy is erased: [`CStrHelper`] may
//! place the password in a 1024-byte stack buffer or a heap `CString`, and the
//! compiler may copy values. Use [`explicit_bzero`](crate::explicit_bzero) on
//! native buffers you own when in-place erasure is required.

use core::ffi::CStr;

use crate::{
    cstr::CStrHelper,
    error::Errno,
    ffi::{self, SUCCESS},
};

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// `_PASSWORD_LEN`, the buffer size required by
/// [`crypt_newhash(3)`](https://man.openbsd.org/crypt_newhash.3).
pub const PASSWORD_LEN: usize = 128;

/// Verifies a password against a hash, as
/// [`crypt_checkpass(3)`](https://man.openbsd.org/crypt_checkpass.3).
///
/// Returns `Ok(true)` when the password matches. An invalid hash or a
/// non-matching password yields `Ok(false)` (the native `EACCES` case); other
/// failures are reported as [`Errno`]. The native function documents the empty
/// password matching the empty hash.
///
/// Both arguments are accepted through [`CStrHelper`], so they may be byte
/// slices, `str`, or `CStr`. An interior NUL byte is rejected with
/// [`Errno::EINVAL`].
///
/// # Errors
///
/// Errors if `crypt_checkpass(3)` fails with an error other than `EACCES`, or
/// if an input contains an interior NUL byte.
pub fn crypt_checkpass<P: CStrHelper, H: CStrHelper>(password: P, hash: H) -> Result<bool, Errno> {
    password
        .convert_then_apply(|password| hash.convert_then_apply(|hash| checkpass(password, hash)))
}

/// Verifies a password against a hash given the already converted C strings.
#[expect(unsafe_code, reason = "crypt_checkpass(3) takes raw pointers")]
fn checkpass(password: &CStr, hash: &CStr) -> Result<bool, Errno> {
    // SAFETY:
    // Both strings are valid, NUL-terminated, and borrowed for the duration of
    // the call. The native call only reads them.
    let code = unsafe { ffi::crypt_checkpass(password.as_ptr(), hash.as_ptr()) };
    if code == SUCCESS {
        return Ok(true);
    }
    let errno = Errno::last();
    if errno == Errno::EACCES {
        Ok(false)
    } else {
        Err(errno)
    }
}

/// Creates a new salted password hash into `out`, as
/// [`crypt_newhash(3)`](https://man.openbsd.org/crypt_newhash.3).
///
/// `pref` selects the algorithm and parameters, for example `"bcrypt,4"`
/// (rounds between 4 and 31) or `"bcrypt,a"` (automatically chosen rounds). An
/// unsupported preference fails with [`Errno::EINVAL`].
///
/// Returns the number of bytes of the hash written at the start of `out` (the
/// native result is a NUL-terminated string).
///
/// # Errors
///
/// Errors if `crypt_newhash(3)` does, or if an input contains an interior NUL
/// byte.
pub fn crypt_newhash_into<P: CStrHelper, F: CStrHelper>(
    password: P,
    pref: F,
    out: &mut [u8; PASSWORD_LEN],
) -> Result<usize, Errno> {
    password
        .convert_then_apply(|password| pref.convert_then_apply(|pref| newhash(password, pref, out)))
}

/// Creates a new salted password hash given the already converted C strings.
#[expect(unsafe_code, reason = "crypt_newhash(3) takes raw pointers")]
fn newhash(password: &CStr, pref: &CStr, out: &mut [u8; PASSWORD_LEN]) -> Result<usize, Errno> {
    // SAFETY:
    // Both strings are valid, NUL-terminated, and borrowed for the duration of
    // the call; `out` is a live, writable buffer of exactly `PASSWORD_LEN`
    // bytes, which is the size the native call requires. The native call writes
    // at most `PASSWORD_LEN` bytes, including the terminating NUL.
    let code = unsafe {
        ffi::crypt_newhash(
            password.as_ptr(),
            pref.as_ptr(),
            out.as_mut_ptr().cast(),
            PASSWORD_LEN,
        )
    };
    if code != SUCCESS {
        return Err(Errno::last());
    }
    out.iter().position(|&byte| byte == 0).ok_or(Errno::EINVAL)
}

/// Creates a new salted password hash, as
/// [`crypt_newhash(3)`](https://man.openbsd.org/crypt_newhash.3).
///
/// See [`crypt_newhash_into`] for the preference string and error semantics.
///
/// # Errors
///
/// Errors if `crypt_newhash(3)` does, or if an input contains an interior NUL
/// byte.
#[cfg(feature = "alloc")]
pub fn crypt_newhash<P: CStrHelper, F: CStrHelper>(password: P, pref: F) -> Result<Vec<u8>, Errno> {
    let mut buffer = [0_u8; PASSWORD_LEN];
    let len = crypt_newhash_into(password, pref, &mut buffer)?;
    Ok(buffer.get(..len).unwrap_or_default().to_vec())
}

/// Derives a key from a password and salt into `key`, as
/// [`bcrypt_pbkdf(3)`](https://man.openbsd.org/bcrypt_pbkdf.3).
///
/// The salt should be random material such as the output of
/// [`arc4_random_bytes`](crate::random::arc4_random_bytes). Higher `rounds`
/// values make each attempt slower. The derivation is deterministic for
/// identical inputs. An empty `key` is a harmless no-op that skips native
/// validation entirely.
///
/// Unlike [`crypt_checkpass`], the password and salt are raw byte strings: they
/// may contain NUL bytes. The derived key is left in `key`; the caller owns it
/// and is responsible for erasing it when it is no longer needed.
///
/// # Errors
///
/// Errors with [`Errno::EINVAL`] when `bcrypt_pbkdf(3)` rejects the arguments;
/// the native call does not report a documented `errno`.
#[expect(unsafe_code, reason = "bcrypt_pbkdf(3) takes raw pointers")]
pub fn bcrypt_pbkdf_into(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    key: &mut [u8],
) -> Result<(), Errno> {
    if key.is_empty() {
        return Ok(());
    }
    // SAFETY:
    // `password`, `salt`, and `key` are live slices whose accompanying lengths
    // are exactly their sizes, so the native call may read the first two and
    // write `key.len()` bytes into the third.
    let code = unsafe {
        ffi::bcrypt_pbkdf(
            password.as_ptr().cast(),
            password.len(),
            salt.as_ptr().cast(),
            salt.len(),
            key.as_mut_ptr().cast(),
            key.len(),
            rounds,
        )
    };
    if code == SUCCESS {
        Ok(())
    } else {
        Err(Errno::EINVAL)
    }
}

/// Derives a key of `key_len` bytes from a password and salt, as
/// [`bcrypt_pbkdf(3)`](https://man.openbsd.org/bcrypt_pbkdf.3).
///
/// See [`bcrypt_pbkdf_into`]. The returned buffer contains the derived key and
/// is not zeroized on drop; erase it with
/// [`explicit_bzero`](crate::explicit_bzero) if it must not remain in memory.
///
/// # Errors
///
/// See [`bcrypt_pbkdf_into`].
#[cfg(feature = "alloc")]
pub fn bcrypt_pbkdf(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    key_len: usize,
) -> Result<Vec<u8>, Errno> {
    let mut key = vec![0_u8; key_len];
    bcrypt_pbkdf_into(password, salt, rounds, &mut key)?;
    Ok(key)
}
