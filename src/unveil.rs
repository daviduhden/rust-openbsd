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

//! [`unveil(2)`](https://man.openbsd.org/unveil.2): restrict the filesystem
//! view of a process.
//!
//! The first call to `unveil(2)` removes visibility of the entire filesystem
//! except for explicitly unveiled paths; additional calls add rules. A call
//! that targets a path which is already unveiled *replaces* that path's
//! permissions with the set supplied to the most recent call; it does not
//! accumulate or union them. Once all rules have been installed the
//! configuration should be locked with [`lock_unveil`] (or
//! [`unveil_and_lock`]). Locking is irreversible.
//!
//! If the process is pledged, calling `unveil(2)` itself requires the
//! [`Promise::Unveil`](crate::Promise::Unveil) promise. Conversely, a
//! `pledge(2)` call that removes all path-accessing promises destroys the
//! unveil state.
//!
//! Denied filesystem access surfaces later as `EACCES`/`ENOENT` errors at the
//! point of the filesystem call, not as errors from this module. These
//! operations change process-wide security state and should normally be
//! performed before arbitrary concurrent application work begins.

use core::{
    ffi::c_char,
    fmt::{self, Display, Formatter},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not},
    ptr,
};

use crate::{
    cstr::CStrHelper,
    error::Errno,
    ffi::{self, SUCCESS},
};

/// A permission in an [`unveil(2)`](https://man.openbsd.org/unveil.2) rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Permission {
    /// `c`: create and remove operations (corresponds to the `cpath` and
    /// `dpath` promises, and permits `connect(2)` on `AF_UNIX` sockets).
    Create,
    /// `x`: execute operations (corresponds to the `exec` promise on kernels
    /// that still provide it).
    Execute,
    /// `r`: read operations (corresponds to the `rpath` promise).
    Read,
    /// `w`: write operations (corresponds to the `wpath`, `chown`, and `fattr`
    /// promises, and permits `connect(2)` on `AF_UNIX` sockets).
    Write,
}

impl Permission {
    /// Returns the single-character native permission for `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Permission;
    /// assert_eq!(Permission::Read.as_char(), 'r');
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_char(self) -> char {
        match self {
            Self::Create => 'c',
            Self::Execute => 'x',
            Self::Read => 'r',
            Self::Write => 'w',
        }
    }

    /// Returns the internal bit flag for `self`.
    const fn flag(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::Execute => 2,
            Self::Read => 4,
            Self::Write => 8,
        }
    }
}

impl Display for Permission {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Create => "create",
            Self::Execute => "execute",
            Self::Read => "read",
            Self::Write => "write",
        })
    }
}

/// A set of [`Permission`]s for an [`unveil(2)`](https://man.openbsd.org/unveil.2)
/// rule.
///
/// The empty set is valid: the path is unveiled but no operation on it is
/// permitted. Unlike pledge promises, unveil permissions are *not* monotonic:
/// a later `unveil(2)` call for the same path replaces its permission set, so
/// it can both widen and narrow the operations allowed on that path.
///
/// # Examples
///
/// ```
/// # use rust_openbsd::{Permission, Permissions};
/// let permissions = Permissions::READ
///     .enable(Permission::Write)
///     .enable(Permission::Create);
/// assert!(permissions.is_enabled(Permission::Write));
/// assert!(!permissions.is_enabled(Permission::Execute));
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Permissions(u8);

impl Permissions {
    /// The empty permission set.
    pub const NONE: Self = Self(0);

    /// A set with every permission enabled (`rwxc`).
    pub const ALL: Self = Self::NONE
        .enable(Permission::Create)
        .enable(Permission::Execute)
        .enable(Permission::Read)
        .enable(Permission::Write);

    /// A set with only [`Permission::Create`] enabled (`c`).
    pub const CREATE: Self = Self::NONE.enable(Permission::Create);

    /// A set with only [`Permission::Execute`] enabled (`x`).
    pub const EXECUTE: Self = Self::NONE.enable(Permission::Execute);

    /// A set with only [`Permission::Read`] enabled (`r`).
    pub const READ: Self = Self::NONE.enable(Permission::Read);

    /// A set with only [`Permission::Write`] enabled (`w`).
    pub const WRITE: Self = Self::NONE.enable(Permission::Write);

    /// Returns `self` with `permission` enabled.
    #[inline]
    #[must_use]
    pub const fn enable(self, permission: Permission) -> Self {
        Self(self.0 | permission.flag())
    }

    /// Returns `true` if `self` has `permission` enabled.
    #[inline]
    #[must_use]
    pub const fn is_enabled(self, permission: Permission) -> bool {
        let flag = permission.flag();
        self.0 & flag == flag
    }

    /// Returns `true` if `self` has no permissions enabled.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Encodes `self` as the NUL-terminated permission string accepted by
    /// `unveil(2)`, in canonical `rwxc` order.
    ///
    /// The empty set encodes as the empty string, which is valid: the path is
    /// unveiled but no operation on it is permitted.
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::indexing_slicing,
        reason = "there are at most four permissions; the buffer holds five bytes"
    )]
    pub(crate) fn encode(self) -> [u8; 5] {
        let mut buf = [0_u8; 5];
        let mut len = 0;
        // Emit permissions in the native canonical `rwxc` order regardless
        // of the order in which callers enabled the flag bits.
        for permission in [
            Permission::Read,
            Permission::Write,
            Permission::Execute,
            Permission::Create,
        ] {
            if self.is_enabled(permission) {
                buf[len] = permission.as_char() as u8;
                len += 1;
            }
        }
        buf
    }
}

impl Display for Permissions {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for permission in [
            Permission::Read,
            Permission::Write,
            Permission::Execute,
            Permission::Create,
        ] {
            if self.is_enabled(permission) {
                write!(f, "{}", permission.as_char())?;
            }
        }
        Ok(())
    }
}

impl BitOr<Permission> for Permissions {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Permission) -> Self::Output {
        self.enable(rhs)
    }
}

impl BitOrAssign<Permission> for Permissions {
    #[inline]
    fn bitor_assign(&mut self, rhs: Permission) {
        self.0 |= rhs.flag();
    }
}

impl BitAnd<Permission> for Permissions {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Permission) -> Self::Output {
        Self(self.0 & rhs.flag())
    }
}

impl BitAndAssign<Permission> for Permissions {
    #[inline]
    fn bitand_assign(&mut self, rhs: Permission) {
        self.0 &= rhs.flag();
    }
}

impl BitXor<Permission> for Permissions {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Permission) -> Self::Output {
        Self(self.0 ^ rhs.flag())
    }
}

impl BitXorAssign<Permission> for Permissions {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Permission) {
        self.0 ^= rhs.flag();
    }
}

impl Not for Permissions {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(Self::ALL.0 & !self.0)
    }
}

/// Calls `unveil(2)` for a single path and permission set.
///
/// The path is accepted through [`CStrHelper`], so it may be a
/// [`Path`](std::path::Path), an [`OsStr`](std::ffi::OsStr), a [`str`], or a
/// raw byte slice. Paths are subject to native OpenBSD semantics: they need not
/// be valid UTF-8, but they must not contain an interior NUL byte.
///
/// A rule may be added repeatedly; a later call for the same path *replaces*
/// the earlier permission set rather than adding to it (see [`Permissions`]).
/// The final component of a path may legitimately not exist yet (it is
/// remembered by name), but a nonexistent *directory* component fails with
/// [`Errno::ENOENT`].
///
/// # Errors
///
/// Errors if `unveil(2)` does: [`Errno::EPERM`] if the configuration is already
/// locked with [`lock_unveil`], [`Errno::ENOENT`] for a missing directory
/// component, [`Errno::E2BIG`] when the per-process unveiled-path or name limit
/// is exhausted, or [`Errno::EINVAL`] for an invalid permission string or an
/// interior NUL byte in the path. A call is not rejected merely for widening
/// the permissions of a path.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{unveil, Permissions};
/// assert!(unveil("/etc/resolv.conf", Permissions::READ).is_ok());
/// ```
#[expect(unsafe_code, reason = "unveil(2) takes raw pointers")]
pub fn unveil<P: CStrHelper>(path: P, permissions: Permissions) -> Result<(), Errno> {
    let permissions = permissions.encode();
    path.convert_then_apply(|path| {
        // SAFETY:
        // `path` is a valid, NUL-terminated string borrowed for the duration of the call.
        // `permissions` is a live five-byte buffer whose first NUL terminates it. `unveil(2)`
        // only reads both buffers.
        if unsafe { ffi::unveil(path.as_ptr(), permissions.as_ptr().cast::<c_char>()) } == SUCCESS {
            Ok(())
        } else {
            Err(Errno::last())
        }
    })
}

/// Calls `unveil(2)` for each `(path, permissions)` rule in order.
///
/// # Errors
///
/// Stops at the first failing rule; rules installed before the failure remain
/// in effect and cannot be removed. See [`unveil`].
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{unveil_paths, Permissions};
/// assert!(unveil_paths([("/", Permissions::READ), ("/tmp", Permissions::READ)]).is_ok());
/// ```
pub fn unveil_paths<P: CStrHelper>(
    rules: impl IntoIterator<Item = (P, Permissions)>,
) -> Result<(), Errno> {
    for (path, permissions) in rules {
        unveil(path, permissions)?;
    }
    Ok(())
}

/// Permanently locks the unveil configuration, equivalent to
/// `unveil(NULL, NULL)`.
///
/// After locking, no further rules can be added: subsequent calls to [`unveil`]
/// fail with [`Errno::EPERM`]. The lock cannot be undone. OpenBSD strongly
/// recommends locking once all rules are installed.
///
/// # Errors
///
/// Errors if `unveil(2)` does.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::lock_unveil;
/// assert!(lock_unveil().is_ok());
/// ```
#[expect(unsafe_code, reason = "unveil(2) takes raw pointers")]
pub fn lock_unveil() -> Result<(), Errno> {
    // SAFETY:
    // `unveil(NULL, NULL)` is the documented way to lock the configuration and does not
    // dereference either argument.
    if unsafe { ffi::unveil(ptr::null(), ptr::null()) } == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Installs every rule in `rules` and then locks the configuration.
///
/// This is equivalent to [`unveil_paths`] followed by [`lock_unveil`], but
/// expresses the intended "set up and close" transition in one call. The
/// transition is not atomic: if a rule fails, the rules installed before it
/// remain and the configuration is **not** locked (leaving the caller to decide
/// whether to retry, lock, or exit).
///
/// # Errors
///
/// Errors if [`unveil_paths`] or [`lock_unveil`] does.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{unveil_and_lock, Permissions};
/// assert!(unveil_and_lock([("/", Permissions::ALL)]).is_ok());
/// ```
pub fn unveil_and_lock<P: CStrHelper>(
    rules: impl IntoIterator<Item = (P, Permissions)>,
) -> Result<(), Errno> {
    unveil_paths(rules)?;
    lock_unveil()
}

/// Parses a native permission string (`r`, `w`, `x`, `c`) into a
/// [`Permissions`] set.
///
/// Unknown characters yield [`Errno::EINVAL`]. The empty string yields
/// [`Permissions::NONE`].
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] for an unknown character.
pub fn permissions_from_str(permissions: &str) -> Result<Permissions, Errno> {
    permissions
        .chars()
        .try_fold(Permissions::NONE, |set, c| match c {
            'r' => Ok(set.enable(Permission::Read)),
            'w' => Ok(set.enable(Permission::Write)),
            'x' => Ok(set.enable(Permission::Execute)),
            'c' => Ok(set.enable(Permission::Create)),
            _ => Err(Errno::EINVAL),
        })
}

/// Converts a raw byte string into a [`Permissions`] set.
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] for invalid UTF-8 or an unknown character.
pub fn permissions_from_os<C: CStrHelper>(permissions: C) -> Result<Permissions, Errno> {
    permissions.convert_then_apply(|cstr| {
        cstr.to_str()
            .map_err(|_| Errno::EINVAL)
            .and_then(permissions_from_str)
    })
}
