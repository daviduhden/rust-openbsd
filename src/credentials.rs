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

//! Process and peer credential queries.
//!
//! Two credential-related OpenBSD interfaces:
//!
//! * [`is_setugid`] wraps [`issetugid(2)`](https://man.openbsd.org/issetugid.2),
//!   which reports whether the current process image was tainted by
//!   set-user-ID or set-group-ID execution.
//! * [`get_peer_credentials`] wraps
//!   [`getpeereid(3)`](https://man.openbsd.org/getpeereid.3), which returns the
//!   effective user and group IDs of the peer connected to a local Unix-domain
//!   socket.
//!
//! Neither is an authorization mechanism by itself; they supply facts that an
//! application can use as part of its own authorization decisions.

use core::ffi::c_int;

use crate::{
    error::Errno,
    ffi::{self, SUCCESS},
    privileges::{Gid, Uid},
};

/// Reports whether the current process image was tainted by set-user-ID or
/// set-group-ID execution, as
/// [`issetugid(2)`](https://man.openbsd.org/issetugid.2).
///
/// This is *not* a comparison of the current real and effective UIDs/GIDs, and
/// it is *not* affected by calls that change the IDs. It reflects whether the
/// process was created as the result of an
/// [`execve(2)`](https://man.openbsd.org/execve.2) whose file had the
/// set-user-ID or set-group-ID bits set, or whose real, effective, or saved
/// UIDs/GIDs were mismatched. A
/// [`fork(2)`](https://man.openbsd.org/fork.2) inherits the same status.
/// Library code uses it to decide whether inherited state (such as environment
/// variables naming files) may be trusted.
///
/// The call cannot fail. It is allowed under the `stdio` pledge promise.
#[inline]
#[must_use]
pub fn is_setugid() -> bool {
    ffi::issetugid() != 0
}

/// Returns the effective user ID and group ID of the peer connected to a local
/// Unix-domain socket, as
/// [`getpeereid(3)`](https://man.openbsd.org/getpeereid.3).
///
/// The descriptor must refer to a connected Unix-domain `SOCK_STREAM` or
/// `SOCK_SEQPACKET` socket. This is the credential source for Unix-domain
/// servers that want to know who their clients are; the returned values are
/// peer credentials, not an authentication result by themselves.
///
/// # Errors
///
/// Errors if `getpeereid(3)` does: for example [`Errno::EBADF`] for an invalid
/// descriptor, [`Errno::ENOTSOCK`] for a regular file, [`Errno::EOPNOTSUPP`]
/// for a non-Unix-domain socket, [`Errno::ENOTCONN`] for an unconnected
/// socket, or [`Errno::ENOBUFS`] when the kernel lacks resources.
///
/// # Pledge
///
/// `getpeereid(3)` is implemented with
/// [`getsockopt(2)`](https://man.openbsd.org/getsockopt.2) (`SO_PEERCRED`).
/// On current OpenBSD the call therefore needs the `stdio` promise plus one of
/// `unix`, `inet`, or `dns`; with only `stdio` it takes the pledge-violation
/// path. Calling it before pledging is the conservative choice and is the only
/// behavior this crate documents as guaranteed across versions.
#[expect(unsafe_code, reason = "getpeereid(3) writes through pointers")]
pub fn get_peer_credentials(fd: c_int) -> Result<(Uid, Gid), Errno> {
    let mut euid = 0_u32;
    let mut egid = 0_u32;
    // SAFETY:
    // Both pointers reference live, aligned, writable `u32` locals. `fd` is
    // passed by value and is validated by the kernel.
    let code = unsafe { ffi::getpeereid(fd, &raw mut euid, &raw mut egid) };
    if code == SUCCESS {
        Ok((Uid(euid), Gid(egid)))
    } else {
        Err(Errno::last())
    }
}
