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

//! Account resolution, UID/GID handling, and daemon-style privilege dropping.
//!
//! This module implements the privilege-dropping sequence used by OpenBSD
//! base-system daemons such as
//! [`httpd(8)`](https://man.openbsd.org/httpd.8),
//! [`unwind(8)`](https://man.openbsd.org/unwind.8), and
//! [`smtpd(8)`](https://man.openbsd.org/smtpd.8):
//!
//! 1. resolve the target account while still privileged;
//! 2. set the supplementary groups while still privileged;
//! 3. drop the real, effective, and saved GIDs
//!    ([`setresgid(2)`](https://man.openbsd.org/setresgid.2));
//! 4. drop the real, effective, and saved UIDs last
//!    ([`setresuid(2)`](https://man.openbsd.org/setresuid.2));
//! 5. verify the resulting credentials.
//!
//! The ordering matters: [`setgroups(2)`](https://man.openbsd.org/setgroups.2)
//! requires privilege, and once root is gone the saved IDs must not allow the
//! process to regain it.
//!
//! # Partial failure
//!
//! Credential changes are not generally reversible. If a step fails partway
//! through, the process may already have reduced privileges and **must not**
//! continue normal service execution: treat any [`PrivDropError`] as fatal for
//! the current process. The error identifies the failing step and preserves the
//! underlying [`Errno`].
//!
//! # Why not `setusercontext(3)`?
//!
//! `setusercontext(3)` applies a full login class from
//! [`login.conf(5)`](https://man.openbsd.org/login.conf.5) (resource limits,
//! umask, priority, environment, `initgroups(3)`, ...). OpenBSD uses it in login
//! programs such as [`login(1)`](https://man.openbsd.org/login.1) and
//! [`su(1)`](https://man.openbsd.org/su.1); native daemons deliberately do not,
//! because daemon privilege separation is not a login session. This crate binds
//! the explicit daemon sequence and leaves login-session management to
//! `setusercontext(3)` users.
//!
//! # Interaction with pledge
//!
//! The [`Promise::Id`](crate::Promise::Id) promise covers the identity-changing
//! calls and [`Promise::Getpw`](crate::Promise::Getpw) is needed to resolve
//! account names. A process that pledges before dropping privileges must keep
//! both until the drop is complete, then pledge again without them.

use core::{
    error::Error,
    ffi::{CStr, c_char, c_int},
    fmt::{self, Display, Formatter},
    mem::MaybeUninit,
    ops::Deref,
    ptr,
};

#[cfg(feature = "alloc")]
use alloc::vec;

use crate::{
    cstr::CStrHelper,
    error::Errno,
    ffi::{self, SUCCESS},
};

/// Maximum length of a login name including the terminating NUL, from
/// OpenBSD's [`LOGIN_NAME_MAX`](https://github.com/openbsd/src/blob/master/sys/sys/syslimits.h).
pub const LOGIN_NAME_MAX: usize = 32;

/// Maximum number of supplementary group IDs, from OpenBSD's `NGROUPS_MAX`.
pub const NGROUPS_MAX: usize = 16;

/// A user ID (`uid_t`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Uid(pub u32);

impl Uid {
    /// The root user ID.
    pub const ROOT: Self = Self(0);

    /// Returns `true` if `self` is [`Uid::ROOT`].
    #[inline]
    #[must_use]
    pub const fn is_root(self) -> bool {
        self.0 == Self::ROOT.0
    }

    /// [`getuid(2)`](https://man.openbsd.org/getuid.2).
    #[inline]
    #[must_use]
    pub fn getuid() -> Self {
        Self(ffi::getuid())
    }

    /// [`geteuid(2)`](https://man.openbsd.org/geteuid.2).
    #[inline]
    #[must_use]
    pub fn geteuid() -> Self {
        Self(ffi::geteuid())
    }

    /// Returns the raw `uid_t`.
    #[inline]
    #[must_use]
    pub const fn into_raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for Uid {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Uid> for u32 {
    #[inline]
    fn from(value: Uid) -> Self {
        value.0
    }
}

impl Display for Uid {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A group ID (`gid_t`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Gid(pub u32);

impl Gid {
    /// The root group ID.
    pub const ROOT: Self = Self(0);

    /// Returns `true` if `self` is [`Gid::ROOT`].
    #[inline]
    #[must_use]
    pub const fn is_root(self) -> bool {
        self.0 == Self::ROOT.0
    }

    /// [`getgid(2)`](https://man.openbsd.org/getgid.2).
    #[inline]
    #[must_use]
    pub fn getgid() -> Self {
        Self(ffi::getgid())
    }

    /// [`getegid(2)`](https://man.openbsd.org/getegid.2).
    #[inline]
    #[must_use]
    pub fn getegid() -> Self {
        Self(ffi::getegid())
    }

    /// Returns the raw `gid_t`.
    #[inline]
    #[must_use]
    pub const fn into_raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for Gid {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Gid> for u32 {
    #[inline]
    fn from(value: Gid) -> Self {
        value.0
    }
}

impl Display for Gid {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A fixed-capacity list of supplementary group IDs.
///
/// OpenBSD limits a process to [`NGROUPS_MAX`] supplementary groups, so the
/// list can be stored inline and this type works without [`alloc`](crate#alloc).
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Groups {
    /// The group IDs.
    gids: [Gid; NGROUPS_MAX],
    /// The number of valid entries at the start of `gids`.
    len: u8,
}

impl Groups {
    /// Returns the supplementary groups as a slice.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[Gid] {
        #[expect(
            clippy::indexing_slicing,
            reason = "`len` is always in `0..=NGROUPS_MAX`"
        )]
        &self.gids[..usize::from(self.len)]
    }
}

impl Deref for Groups {
    type Target = [Gid];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[Gid]> for Groups {
    #[inline]
    fn as_ref(&self) -> &[Gid] {
        self.as_slice()
    }
}

impl fmt::Debug for Groups {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl Display for Groups {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for gid in self.as_slice() {
            if first {
                first = false;
            } else {
                f.write_str(", ")?;
            }
            write!(f, "{gid}")?;
        }
        Ok(())
    }
}

/// A resolved user account: the identity a process will be dropped to.
///
/// The login name is stored inline as a NUL-terminated string because OpenBSD
/// limits login names to [`LOGIN_NAME_MAX`] bytes; the type therefore works
/// without allocation. The kernel still enforces that identity-changing calls
/// are honored only from a sufficiently privileged process.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Account {
    /// The NUL-terminated login name.
    name: [u8; LOGIN_NAME_MAX],
    /// Length of the name excluding the NUL terminator.
    name_len: u8,
    /// The user ID.
    uid: Uid,
    /// The primary group ID.
    gid: Gid,
}

impl Account {
    /// Creates an account from a login name and its resolved IDs.
    ///
    /// This is useful when a daemon is configured from known numeric values
    /// instead of by name. The name is still required for the
    /// [`GroupPolicy::Initgroups`] policy.
    ///
    /// # Errors
    ///
    /// Returns [`PrivDropError::NameTooLong`] if `name` does not fit in
    /// [`LOGIN_NAME_MAX`] bytes.
    pub fn new(name: &CStr, uid: Uid, gid: Gid) -> Result<Self, PrivDropError> {
        let bytes = name.to_bytes();
        let name_len = u8::try_from(bytes.len())
            .ok()
            .filter(|len| usize::from(*len) < LOGIN_NAME_MAX)
            .ok_or(PrivDropError::NameTooLong)?;
        let mut buf = [0_u8; LOGIN_NAME_MAX];
        #[expect(
            clippy::indexing_slicing,
            reason = "`name_len < LOGIN_NAME_MAX` and the source has that length"
        )]
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            name: buf,
            name_len,
            uid,
            gid,
        })
    }

    /// Returns the login name.
    #[expect(
        unsafe_code,
        reason = "the buffer is NUL-terminated and has no interior NUL by construction"
    )]
    #[must_use]
    pub fn name(&self) -> &CStr {
        let end = usize::from(self.name_len);
        // SAFETY:
        // `name_len < LOGIN_NAME_MAX`, so `end` is in bounds of the fixed-size array.
        let bytes = unsafe { self.name.get_unchecked(..=end) };
        // SAFETY:
        // The byte at `name[name_len]` is the NUL written by `Account::new`, and the source was a
        // `CStr`, so there is no interior NUL. The slice therefore has exactly one NUL, at the
        // end.
        unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
    }

    /// Returns the user ID.
    #[inline]
    #[must_use]
    pub const fn uid(&self) -> Uid {
        self.uid
    }

    /// Returns the primary group ID.
    #[inline]
    #[must_use]
    pub const fn gid(&self) -> Gid {
        self.gid
    }

    /// Returns `true` if the account is root.
    #[inline]
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.uid.is_root()
    }
}

impl fmt::Debug for Account {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("name", &account_name_str(self))
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .finish_non_exhaustive()
    }
}

impl Display for Account {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (uid {}, gid {})",
            account_name_str(self),
            self.uid,
            self.gid
        )
    }
}

/// Returns the account's login name as a string, or a placeholder if it is not
/// valid UTF-8. Used only for diagnostics; the login name is a byte string.
fn account_name_str(account: &Account) -> &str {
    account.name().to_str().unwrap_or("<non-UTF-8 login name>")
}

/// How supplementary groups are set when dropping privileges.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum GroupPolicy {
    /// Replace the supplementary group list with only the target account's
    /// primary GID, the equivalent of `setgroups(1, &gid)`.
    ///
    /// This is the restrictive, daemon-style behavior and can never
    /// accidentally retain root's supplementary groups. It is the default.
    #[default]
    PrimaryGroupOnly,
    /// Adopt all supplementary groups associated with the account through
    /// [`initgroups(3)`](https://man.openbsd.org/initgroups.3).
    ///
    /// This is login-style behavior; use it only when the process genuinely
    /// needs the account's group memberships.
    Initgroups,
}

/// The step of the privilege-dropping sequence that failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrivDropStep {
    /// Resolving the account.
    Lookup,
    /// Setting the supplementary groups.
    SetSupplementaryGroups,
    /// Calling [`initgroups(3)`](https://man.openbsd.org/initgroups.3).
    InitGroups,
    /// Calling [`setresgid(2)`](https://man.openbsd.org/setresgid.2).
    SetResGid,
    /// Calling [`setresuid(2)`](https://man.openbsd.org/setresuid.2).
    SetResUid,
    /// Verifying the resulting credentials.
    Verify,
}

/// Details of a failed credential verification.
///
/// A verification failure means the kernel accepted the identity-changing calls
/// but the observed credentials do not match the account. The process must be
/// treated as fatally compromised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Verification {
    /// The expected real/effective/saved user IDs.
    pub expected_uid: (Uid, Uid, Uid),
    /// The observed real/effective/saved user IDs.
    pub actual_uid: (Uid, Uid, Uid),
    /// The expected real/effective/saved group IDs.
    pub expected_gid: (Gid, Gid, Gid),
    /// The observed real/effective/saved group IDs.
    pub actual_gid: (Gid, Gid, Gid),
    /// The supplementary-group policy that was requested.
    pub policy: GroupPolicy,
    /// The observed supplementary groups.
    pub actual_groups: Groups,
}

impl Display for Verification {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "credential verification failed: uid {}/{}/{}, gid {}/{}/{}, groups [{}]",
            self.actual_uid.0,
            self.actual_uid.1,
            self.actual_uid.2,
            self.actual_gid.0,
            self.actual_gid.1,
            self.actual_gid.2,
            self.actual_groups,
        )
    }
}

/// An error from the privilege-dropping sequence.
///
/// Every variant identifies the failing operation and, where one exists,
/// preserves the underlying [`Errno`] so that callers can react to `EPERM` and
/// friends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivDropError {
    /// The account database lookup failed.
    Lookup(Errno),
    /// No `passwd(5)` entry has the given name.
    NoSuchAccount,
    /// The login name does not fit in [`LOGIN_NAME_MAX`] bytes.
    NameTooLong,
    /// The resolved account is root; refusing to "drop" to root.
    RootAccount,
    /// [`setgroups(2)`](https://man.openbsd.org/setgroups.2) failed.
    SetSupplementaryGroups(Errno),
    /// [`initgroups(3)`](https://man.openbsd.org/initgroups.3) failed.
    InitGroups(Errno),
    /// [`setresgid(2)`](https://man.openbsd.org/setresgid.2) failed.
    SetResGid(Errno),
    /// [`setresuid(2)`](https://man.openbsd.org/setresuid.2) failed.
    SetResUid(Errno),
    /// [`getresuid(2)`](https://man.openbsd.org/getresuid.2) failed during
    /// verification.
    GetResUid(Errno),
    /// [`getresgid(2)`](https://man.openbsd.org/getresgid.2) failed during
    /// verification.
    GetResGid(Errno),
    /// [`getgroups(2)`](https://man.openbsd.org/getgroups.2) failed during
    /// verification.
    GetGroups(Errno),
    /// The resulting credentials did not match the account.
    Verification(Verification),
}

impl PrivDropError {
    /// Returns the step of the sequence that failed.
    #[inline]
    #[must_use]
    pub const fn step(self) -> PrivDropStep {
        match self {
            Self::Lookup(_) | Self::NoSuchAccount | Self::NameTooLong | Self::RootAccount => {
                PrivDropStep::Lookup
            }
            Self::SetSupplementaryGroups(_) => PrivDropStep::SetSupplementaryGroups,
            Self::InitGroups(_) => PrivDropStep::InitGroups,
            Self::SetResGid(_) => PrivDropStep::SetResGid,
            Self::SetResUid(_) => PrivDropStep::SetResUid,
            Self::GetResUid(_)
            | Self::GetResGid(_)
            | Self::GetGroups(_)
            | Self::Verification(_) => PrivDropStep::Verify,
        }
    }

    /// Returns the underlying operating-system error, if any.
    #[inline]
    #[must_use]
    pub const fn errno(self) -> Option<Errno> {
        match self {
            Self::Lookup(errno)
            | Self::SetSupplementaryGroups(errno)
            | Self::InitGroups(errno)
            | Self::SetResGid(errno)
            | Self::SetResUid(errno)
            | Self::GetResUid(errno)
            | Self::GetResGid(errno)
            | Self::GetGroups(errno) => Some(errno),
            Self::NoSuchAccount | Self::NameTooLong | Self::RootAccount | Self::Verification(_) => {
                None
            }
        }
    }
}

impl Error for PrivDropError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lookup(errno)
            | Self::SetSupplementaryGroups(errno)
            | Self::InitGroups(errno)
            | Self::SetResGid(errno)
            | Self::SetResUid(errno)
            | Self::GetResUid(errno)
            | Self::GetResGid(errno)
            | Self::GetGroups(errno) => Some(errno),
            Self::NoSuchAccount | Self::NameTooLong | Self::RootAccount | Self::Verification(_) => {
                None
            }
        }
    }
}

impl Display for PrivDropError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(errno) => write!(f, "cannot resolve account: {errno}"),
            Self::NoSuchAccount => f.write_str("no passwd(5) entry for the account"),
            Self::NameTooLong => f.write_str("login name does not fit in LOGIN_NAME_MAX bytes"),
            Self::RootAccount => f.write_str("refusing to drop privileges to root"),
            Self::SetSupplementaryGroups(errno) => write!(f, "setgroups(2) failed: {errno}"),
            Self::InitGroups(errno) => write!(f, "initgroups(3) failed: {errno}"),
            Self::SetResGid(errno) => write!(f, "setresgid(2) failed: {errno}"),
            Self::SetResUid(errno) => write!(f, "setresuid(2) failed: {errno}"),
            Self::GetResUid(errno) => write!(f, "getresuid(2) failed: {errno}"),
            Self::GetResGid(errno) => write!(f, "getresgid(2) failed: {errno}"),
            Self::GetGroups(errno) => write!(f, "getgroups(2) failed: {errno}"),
            Self::Verification(verification) => verification.fmt(f),
        }
    }
}

/// Sets the real, effective, and saved user IDs, as
/// [`setresuid(2)`](https://man.openbsd.org/setresuid.2).
///
/// [`None`] maps to the native `-1`, meaning "leave this ID unchanged". This is
/// the faithful form of the system call, including partial changes such as
/// setting only the effective user ID.
///
/// This is a mechanism with no policy attached; prefer [`drop_privileges`] for
/// the full daemon sequence.
///
/// # Errors
///
/// Errors if `setresuid(2)` does, typically [`Errno::EPERM`] without
/// sufficient privilege.
pub fn set_res_uid(ruid: Option<Uid>, euid: Option<Uid>, suid: Option<Uid>) -> Result<(), Errno> {
    let code = ffi::setresuid(id_value(ruid), id_value(euid), id_value(suid));
    if code == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Sets the real, effective, and saved group IDs, as
/// [`setresgid(2)`](https://man.openbsd.org/setresgid.2).
///
/// [`None`] maps to the native `-1`, meaning "leave this ID unchanged".
///
/// # Errors
///
/// Errors if `setresgid(2)` does.
pub fn set_res_gid(rgid: Option<Gid>, egid: Option<Gid>, sgid: Option<Gid>) -> Result<(), Errno> {
    let code = ffi::setresgid(id_value_gid(rgid), id_value_gid(egid), id_value_gid(sgid));
    if code == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Returns the native `-1` "leave unchanged" value for a user ID.
#[inline]
const fn id_value(id: Option<Uid>) -> u32 {
    match id {
        Some(uid) => uid.0,
        None => u32::MAX,
    }
}

/// Returns the native `-1` "leave unchanged" value for a group ID.
#[inline]
const fn id_value_gid(id: Option<Gid>) -> u32 {
    match id {
        Some(gid) => gid.0,
        None => u32::MAX,
    }
}

/// Returns the real, effective, and saved user IDs, as
/// [`getresuid(2)`](https://man.openbsd.org/getresuid.2).
///
/// # Errors
///
/// Errors if `getresuid(2)` does.
#[expect(unsafe_code, reason = "getresuid(2) writes through pointers")]
pub fn get_res_uid() -> Result<(Uid, Uid, Uid), Errno> {
    let mut real = 0_u32;
    let mut effective = 0_u32;
    let mut saved = 0_u32;
    // SAFETY:
    // All three pointers reference live, aligned, writable `u32` locals.
    let code = unsafe { ffi::getresuid(&raw mut real, &raw mut effective, &raw mut saved) };
    if code == SUCCESS {
        Ok((Uid(real), Uid(effective), Uid(saved)))
    } else {
        Err(Errno::last())
    }
}

/// Returns the real, effective, and saved group IDs, as
/// [`getresgid(2)`](https://man.openbsd.org/getresgid.2).
///
/// # Errors
///
/// Errors if `getresgid(2)` does.
#[expect(unsafe_code, reason = "getresgid(2) writes through pointers")]
pub fn get_res_gid() -> Result<(Gid, Gid, Gid), Errno> {
    let mut real = 0_u32;
    let mut effective = 0_u32;
    let mut saved = 0_u32;
    // SAFETY:
    // All three pointers reference live, aligned, writable `u32` locals.
    let code = unsafe { ffi::getresgid(&raw mut real, &raw mut effective, &raw mut saved) };
    if code == SUCCESS {
        Ok((Gid(real), Gid(effective), Gid(saved)))
    } else {
        Err(Errno::last())
    }
}

/// Sets the supplementary group list to exactly `groups`, as
/// [`setgroups(2)`](https://man.openbsd.org/setgroups.2).
///
/// The kernel caps the list at [`NGROUPS_MAX`] entries. Passing an empty slice
/// drops all supplementary groups.
///
/// # Errors
///
/// Errors if `setgroups(2)` does, typically [`Errno::EPERM`] without
/// sufficient privilege.
#[expect(unsafe_code, reason = "setgroups(2) takes a raw pointer")]
pub fn set_groups(groups: &[Gid]) -> Result<(), Errno> {
    let count = c_int::try_from(groups.len()).map_err(|_| Errno::EINVAL)?;
    let ptr = if groups.is_empty() {
        ptr::null()
    } else {
        groups.as_ptr().cast::<u32>()
    };
    // SAFETY:
    // `ptr` is either `NULL` (with `count == 0`) or points to `count` live, aligned `Gid`s, which
    // are `repr(transparent)` wrappers around `u32`. `setgroups(2)` only reads them.
    if unsafe { ffi::setgroups(count, ptr) } == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Drops all supplementary groups, as `setgroups(0, NULL)`.
///
/// # Errors
///
/// Errors if `setgroups(2)` does.
pub fn drop_supplementary_groups() -> Result<(), Errno> {
    set_groups(&[])
}

/// Returns the supplementary group list, as
/// [`getgroups(2)`](https://man.openbsd.org/getgroups.2).
///
/// # Errors
///
/// Errors if `getgroups(2)` does.
#[expect(unsafe_code, reason = "getgroups(2) writes through a pointer")]
pub fn groups() -> Result<Groups, Errno> {
    let mut result = Groups {
        gids: [Gid::ROOT; NGROUPS_MAX],
        len: 0,
    };
    let capacity = c_int::try_from(NGROUPS_MAX).map_err(|_| Errno::ERANGE)?;
    // SAFETY:
    // `result.gids` is a live, aligned array of `NGROUPS_MAX` `Gid`s (`repr(transparent)` over
    // `u32`), and `capacity` is exactly its length. `getgroups(2)` writes at most that many.
    let count = unsafe { ffi::getgroups(capacity, result.gids.as_mut_ptr().cast::<u32>()) };
    if count < 0 {
        return Err(Errno::last());
    }
    result.len = u8::try_from(count).map_err(|_| Errno::ERANGE)?;
    Ok(result)
}

/// Initializes the supplementary group list for `name`, as
/// [`initgroups(3)`](https://man.openbsd.org/initgroups.3).
///
/// This is the login-style group initialization used by
/// [`GroupPolicy::Initgroups`]. It is a mechanism, not a policy: it requires
/// privilege and the [`Promise::Id`](crate::Promise::Id) promise (plus
/// [`Promise::Getpw`](crate::Promise::Getpw) for the group lookup).
///
/// # Errors
///
/// Errors if `initgroups(3)` does.
#[expect(unsafe_code, reason = "initgroups(3) takes a raw pointer")]
pub fn init_groups<P: CStrHelper>(name: P, base_gid: Gid) -> Result<(), Errno> {
    name.convert_then_apply(|name| {
        // SAFETY:
        // `name` is a valid, NUL-terminated string borrowed for the duration of the call.
        // `initgroups(3)` only reads it.
        if unsafe { ffi::initgroups(name.as_ptr(), base_gid.0) } == SUCCESS {
            Ok(())
        } else {
            Err(Errno::last())
        }
    })
}

/// Performs a [`getpwnam_r`](https://man.openbsd.org/getpwnam_r.3) lookup for
/// `name` into `buf`.
///
/// Returns `Ok(None)` when there is no matching entry.
#[expect(
    unsafe_code,
    reason = "the passwd database lookup fills a `struct passwd` through pointers"
)]
fn resolve(name: &CStr, buf: &mut [u8]) -> Result<Option<Account>, Errno> {
    let mut passwd = MaybeUninit::<ffi::Passwd>::uninit();
    let mut result = ptr::null_mut();
    let size = buf.len();
    let buf_ptr = buf.as_mut_ptr().cast::<c_char>();
    let passwd_ptr = passwd.as_mut_ptr();
    let result_ptr = &raw mut result;
    // SAFETY:
    // `passwd_ptr` points at a `MaybeUninit<Passwd>`, which the function is documented to only
    // write to. `buf_ptr`/`size` describe a live, writable buffer. `result_ptr` is a live,
    // aligned pointer to a `*mut Passwd` initialized to null. `name` is a valid `CStr`.
    let code = unsafe { ffi::getpwnam_r(name.as_ptr(), passwd_ptr, buf_ptr, size, result_ptr) };
    if code != SUCCESS {
        return Err(Errno::from_raw(code));
    }
    if result.is_null() {
        return Ok(None);
    }
    // SAFETY:
    // `result` is non-null, so `getpwnam_r` initialized `passwd`.
    let passwd = unsafe { passwd.assume_init_ref() };
    // SAFETY:
    // `pw_name` points into `buf` at a NUL-terminated string that is live for as long as `buf`.
    let name = unsafe { CStr::from_ptr(passwd.name) };
    let account =
        Account::new(name, Uid(passwd.uid), Gid(passwd.gid)).map_err(|_| Errno::ERANGE)?;
    Ok(Some(account))
}

/// Resolves a login name using the password database.
///
/// The lookup uses `getpwnam_r(3)` and returns [`None`] when there is no
/// matching entry; other failures are reported as [`Errno`].
///
/// Resolve the account *before* dropping privileges (and before
/// [`chroot()`](crate::chroot())), because afterwards the password database may no
/// longer be reachable. Under pledge, resolution requires the
/// [`Promise::Getpw`](crate::Promise::Getpw) promise.
///
/// # Errors
///
/// Errors if `getpwnam_r(3)` does, or if the name does not fit (see
/// [`CStrHelper`]).
pub fn account_by_name<P: CStrHelper>(name: P) -> Result<Option<Account>, Errno> {
    name.convert_then_apply(|name| {
        let mut stack = [0_u8; 0x400];
        #[cfg(feature = "alloc")]
        {
            match resolve(name, &mut stack) {
                Err(Errno::ERANGE) => {
                    let mut heap = vec![0_u8; 0x10_0000];
                    resolve(name, &mut heap)
                }
                other => other,
            }
        }
        #[cfg(not(feature = "alloc"))]
        {
            resolve(name, &mut stack)
        }
    })
}

/// Drops privileges to the named account using the restrictive daemon policy.
///
/// This resolves the account and then performs the irreversible sequence with
/// [`GroupPolicy::PrimaryGroupOnly`]. See [`drop_privileges_to`] for the exact
/// steps and the failure semantics.
///
/// # Errors
///
/// Errors if the account cannot be resolved, is root, or if any step fails.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::drop_privileges;
/// drop_privileges("_mydaemon")?;
/// # Ok::<(), rust_openbsd::PrivDropError>(())
/// ```
#[inline]
pub fn drop_privileges<P: CStrHelper>(name: P) -> Result<(), PrivDropError> {
    drop_privileges_with(GroupPolicy::PrimaryGroupOnly, name)
}

/// Drops privileges to the named account with an explicit supplementary-group
/// policy.
///
/// # Errors
///
/// Errors if the account cannot be resolved, is root, or if any step fails.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{drop_privileges_with, GroupPolicy};
/// drop_privileges_with(GroupPolicy::PrimaryGroupOnly, "_mydaemon")?;
/// # Ok::<(), rust_openbsd::PrivDropError>(())
/// ```
pub fn drop_privileges_with<P: CStrHelper>(
    policy: GroupPolicy,
    name: P,
) -> Result<(), PrivDropError> {
    let account = account_by_name(name)
        .map_err(PrivDropError::Lookup)?
        .ok_or(PrivDropError::NoSuchAccount)?;
    if account.is_root() {
        return Err(PrivDropError::RootAccount);
    }
    drop_privileges_to(policy, account)
}

/// Drops privileges to an account that was resolved earlier.
///
/// Resolving the account first matters when it must be looked up while still
/// privileged, for example before [`chroot()`](crate::chroot()) hides the password
/// database.
///
/// The sequence is:
///
/// 1. set the supplementary groups (while still privileged);
/// 2. call [`setresgid(2)`](https://man.openbsd.org/setresgid.2) with the
///    account's primary GID for all three GID flavors;
/// 3. call [`setresuid(2)`](https://man.openbsd.org/setresuid.2) with the
///    account's UID for all three UID flavors;
/// 4. verify the resulting credentials.
///
/// Credential changes are not reversible: after a partial failure the process
/// may already have reduced privileges and must not continue normal service
/// execution.
///
/// This function does not special-case root. If `account` is root, the
/// sequence is effectively a no-op and verification succeeds, leaving the
/// process privileged. Use [`drop_privileges`] or [`drop_privileges_with`] when
/// the destination is resolved from a name; those refuse the root account.
///
/// # Errors
///
/// Every variant of [`PrivDropError`] identifies the failing step and preserves
/// the underlying [`Errno`].
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{account_by_name, drop_privileges_to, GroupPolicy};
/// if let Some(account) = account_by_name("_mydaemon")? {
///     drop_privileges_to(GroupPolicy::PrimaryGroupOnly, account)?;
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn drop_privileges_to(policy: GroupPolicy, account: Account) -> Result<(), PrivDropError> {
    let gid = account.gid();
    let uid = account.uid();
    match policy {
        GroupPolicy::PrimaryGroupOnly => {
            set_groups(&[gid]).map_err(PrivDropError::SetSupplementaryGroups)?;
        }
        GroupPolicy::Initgroups => {
            init_groups(account.name(), gid).map_err(PrivDropError::InitGroups)?;
        }
    }
    set_res_gid(Some(gid), Some(gid), Some(gid)).map_err(PrivDropError::SetResGid)?;
    set_res_uid(Some(uid), Some(uid), Some(uid)).map_err(PrivDropError::SetResUid)?;
    verify(policy, &account)
}

/// Verifies the credentials after a privilege drop.
fn verify(policy: GroupPolicy, account: &Account) -> Result<(), PrivDropError> {
    let uid = get_res_uid().map_err(PrivDropError::GetResUid)?;
    let gid = get_res_gid().map_err(PrivDropError::GetResGid)?;
    let groups = groups().map_err(PrivDropError::GetGroups)?;
    let expected_uid = (account.uid(), account.uid(), account.uid());
    let expected_gid = (account.gid(), account.gid(), account.gid());
    let groups_ok = match policy {
        GroupPolicy::PrimaryGroupOnly => groups.as_slice() == [account.gid()],
        GroupPolicy::Initgroups => groups.contains(&account.gid()),
    };
    if uid == expected_uid && gid == expected_gid && groups_ok {
        Ok(())
    } else {
        Err(PrivDropError::Verification(Verification {
            expected_uid,
            actual_uid: uid,
            expected_gid,
            actual_gid: gid,
            policy,
            actual_groups: groups,
        }))
    }
}
