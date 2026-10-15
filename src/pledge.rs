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

//! [`pledge(2)`](https://man.openbsd.org/pledge.2): restrict the system
//! operations of a process.
//!
//! `pledge(2)` partitions the POSIX feature set into subsystems called
//! *promises*. After a successful call, performing an operation outside the
//! declared set aborts the process with an uncatchable `SIGABRT`.
//!
//! Every call is *monotonic*: it may only reduce the available promises.
//! Attempts to increase them fail with [`Errno::EPERM`] (unless the
//! [`Promise::Error`] promise is active, in which case the increase is silently
//! ignored). Once removed, a promise can never be regained; there is
//! deliberately no bracket combinator here, because the restriction cannot be
//! undone.
//!
//! The second argument of `pledge(2)`, the *exec promises*, restricts programs
//! started later with [`execve(2)`](https://man.openbsd.org/execve.2). See
//! [`pledge_child`] and [`pledge_parts`].
//!
//! These operations change process-wide security state and should normally be
//! performed before arbitrary concurrent application work begins.

use core::{
    ffi::{CStr, c_char},
    fmt::{self, Display, Formatter},
    ptr,
};

use crate::{
    cstr::CStrHelper,
    error::Errno,
    ffi::{self, SUCCESS},
};

/// A `pledge(2)` promise: a subsystem of system operations.
///
/// The enumeration matches the `pledgereq` table accepted by the kernel on
/// OpenBSD 7.9 and OpenBSD-current
/// ([`sys/kern/kern_pledge.c`](https://github.com/openbsd/src/blob/master/sys/kern/kern_pledge.c)).
/// The removed `tmppath` promise is deliberately not represented: `pledge(2)`
/// rejects it with `EINVAL`. Use `rpath`, `wpath`, and `cpath` together with an
/// `unveil` rule for temporary files instead.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Promise {
    /// `audio`: `audio(4)` device `ioctl` operations.
    Audio,
    /// `bpf`: `bpf(4)` statistics collection (`BIOCGSTATS`).
    Bpf,
    /// `chown`: change file owner or group.
    Chown,
    /// `cpath`: create or remove files.
    Cpath,
    /// `disklabel`: disk label `ioctl` operations.
    Disklabel,
    /// `dns`: DNS resolution.
    Dns,
    /// `dpath`: create special files (`mkfifo(2)`, `mknod(2)`).
    Dpath,
    /// `drm`: `drm(4)` `ioctl` operations.
    Drm,
    /// `error`: return `ENOSYS` on violations instead of being killed.
    Error,
    /// `exec`: execute processes with `execve(2)`.
    Exec,
    /// `fattr`: change `struct stat` fields of files.
    Fattr,
    /// `flock`: file locking.
    Flock,
    /// `getpw`: read-only password database access.
    Getpw,
    /// `id`: change process rights (`setuid`, `setgroups`, ...).
    Id,
    /// `inet`: `AF_INET`/`AF_INET6` socket operations.
    Inet,
    /// `mcast`: multicast socket operations (used with [`Promise::Inet`]).
    Mcast,
    /// `pf`: `pf(4)` `ioctl` operations.
    Pf,
    /// `proc`: process relationship operations (`fork`, `kill`, ...).
    Proc,
    /// `prot_exec`: use `PROT_EXEC` with `mmap(2)`/`mprotect(2)`.
    ProtExec,
    /// `ps`: process listing `sysctl(2)` interfaces.
    Ps,
    /// `recvfd`: receive file descriptors with `recvmsg(2)`.
    Recvfd,
    /// `route`: inspect the routing table.
    Route,
    /// `rpath`: read-only filesystem operations.
    Rpath,
    /// `sendfd`: send file descriptors with `sendmsg(2)`.
    Sendfd,
    /// `settime`: set the system time.
    Settime,
    /// `stdio`: basic memory, fd, timer, and process-attribute operations.
    Stdio,
    /// `tape`: tape drive `ioctl` operations.
    Tape,
    /// `tty`: tty `ioctl` operations and `/dev/tty` access.
    Tty,
    /// `unix`: `AF_UNIX` socket operations.
    Unix,
    /// `unveil`: allow `unveil(2)` to be called.
    Unveil,
    /// `video`: `video(4)` `ioctl` operations.
    Video,
    /// `vminfo`: virtual-memory inspection (`top(1)`, `vmstat(8)`).
    Vminfo,
    /// `vmm`: `vmm(4)` `ioctl` operations.
    Vmm,
    /// `wpath`: write filesystem operations.
    Wpath,
    /// `wroute`: change the routing table.
    Wroute,
}

impl Promise {
    /// Every promise accepted by the kernel, in the order used by
    /// `kern_pledge.c`.
    pub const ALL: [Self; 35] = [
        Self::Audio,
        Self::Bpf,
        Self::Chown,
        Self::Cpath,
        Self::Disklabel,
        Self::Dns,
        Self::Dpath,
        Self::Drm,
        Self::Error,
        Self::Exec,
        Self::Fattr,
        Self::Flock,
        Self::Getpw,
        Self::Id,
        Self::Inet,
        Self::Mcast,
        Self::Pf,
        Self::Proc,
        Self::ProtExec,
        Self::Ps,
        Self::Recvfd,
        Self::Route,
        Self::Rpath,
        Self::Sendfd,
        Self::Settime,
        Self::Stdio,
        Self::Tape,
        Self::Tty,
        Self::Unix,
        Self::Unveil,
        Self::Video,
        Self::Vminfo,
        Self::Vmm,
        Self::Wpath,
        Self::Wroute,
    ];

    /// Returns the native name of `self`, exactly as accepted by `pledge(2)`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Promise;
    /// assert_eq!(Promise::ProtExec.name(), "prot_exec");
    /// ```
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Bpf => "bpf",
            Self::Chown => "chown",
            Self::Cpath => "cpath",
            Self::Disklabel => "disklabel",
            Self::Dns => "dns",
            Self::Dpath => "dpath",
            Self::Drm => "drm",
            Self::Error => "error",
            Self::Exec => "exec",
            Self::Fattr => "fattr",
            Self::Flock => "flock",
            Self::Getpw => "getpw",
            Self::Id => "id",
            Self::Inet => "inet",
            Self::Mcast => "mcast",
            Self::Pf => "pf",
            Self::Proc => "proc",
            Self::ProtExec => "prot_exec",
            Self::Ps => "ps",
            Self::Recvfd => "recvfd",
            Self::Route => "route",
            Self::Rpath => "rpath",
            Self::Sendfd => "sendfd",
            Self::Settime => "settime",
            Self::Stdio => "stdio",
            Self::Tape => "tape",
            Self::Tty => "tty",
            Self::Unix => "unix",
            Self::Unveil => "unveil",
            Self::Video => "video",
            Self::Vminfo => "vminfo",
            Self::Vmm => "vmm",
            Self::Wpath => "wpath",
            Self::Wroute => "wroute",
        }
    }

    /// Returns the promise with the native name `name`, if any.
    ///
    /// The lookup is exact and round-trips with [`Promise::name`]. The removed
    /// `tmppath` promise and any other unknown name yield [`None`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::Promise;
    /// assert_eq!(Promise::from_name("stdio"), Some(Promise::Stdio));
    /// assert_eq!(Promise::from_name("tmppath"), None);
    /// ```
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// Returns the internal bit flag for `self`.
    ///
    /// The flags are only an internal representation of a set; they are never
    /// sent to the kernel, which receives the native names instead.
    const fn flag(self) -> u64 {
        match self {
            Self::Audio => 0x1,
            Self::Bpf => 0x2,
            Self::Chown => 0x4,
            Self::Cpath => 0x8,
            Self::Disklabel => 0x10,
            Self::Dns => 0x20,
            Self::Dpath => 0x40,
            Self::Drm => 0x80,
            Self::Error => 0x100,
            Self::Exec => 0x200,
            Self::Fattr => 0x400,
            Self::Flock => 0x800,
            Self::Getpw => 0x1000,
            Self::Id => 0x2000,
            Self::Inet => 0x4000,
            Self::Mcast => 0x8000,
            Self::Pf => 0x10000,
            Self::Proc => 0x20000,
            Self::ProtExec => 0x40000,
            Self::Ps => 0x80000,
            Self::Recvfd => 0x0010_0000,
            Self::Route => 0x0020_0000,
            Self::Rpath => 0x0040_0000,
            Self::Sendfd => 0x0080_0000,
            Self::Settime => 0x0100_0000,
            Self::Stdio => 0x0200_0000,
            Self::Tape => 0x0400_0000,
            Self::Tty => 0x0800_0000,
            Self::Unix => 0x1000_0000,
            Self::Unveil => 0x2000_0000,
            Self::Video => 0x4000_0000,
            Self::Vminfo => 0x8000_0000,
            Self::Vmm => 0x0001_0000_0000,
            Self::Wpath => 0x0002_0000_0000,
            Self::Wroute => 0x0004_0000_0000,
        }
    }
}

impl Display for Promise {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Length of the buffer needed to encode the largest possible promise set.
///
/// Every promise contributes its name plus one separator; the empty set needs
/// a single NUL byte.
#[expect(
    clippy::indexing_slicing,
    reason = "the loop index is bounded by `all.len()`"
)]
pub(crate) const PLEDGE_BUFFER_LEN: usize = {
    let all = Promise::ALL;
    let mut total = 1;
    let mut i = 0;
    while i < all.len() {
        total += all[i].name().len() + 1;
        i += 1;
    }
    total
};

/// A set of [`Promise`]s.
///
/// The type is the natural way to express the *typed* side of `pledge(2)`. It
/// is intentionally not [`Copy`]: a promise set is a description of
/// monotonically decreasing process state, so duplicating it freely would
/// encourage keeping a broader copy around after a reduction.
///
/// All removal operations are available; because `pledge(2)` can only reduce
/// the promise set, there is no corresponding "add" operation on a set that has
/// already been pledged.
///
/// # Examples
///
/// ```
/// # use rust_openbsd::{Promise, Promises};
/// let mut promises = Promises::new([Promise::Stdio, Promise::Rpath]);
/// assert!(promises.contains(Promise::Rpath));
/// promises.remove(Promise::Rpath);
/// assert_eq!(promises.len(), 1);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    missing_copy_implementations,
    reason = "a promise set describes monotonic process state; copying is discouraged"
)]
pub struct Promises(u64);

impl Promises {
    /// The empty promise set.
    ///
    /// Pledging this set restricts the process to `_exit(2)` only.
    pub const NONE: Self = Self(0);

    /// The set containing every [`Promise`].
    pub const ALL: Self = Self(all_promise_flags());

    /// Returns the set containing the unique promises in `initial`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::{Promise, Promises};
    /// assert_eq!(Promises::new([Promise::Stdio, Promise::Stdio]).len(), 1);
    /// ```
    #[must_use]
    pub fn new(initial: impl IntoIterator<Item = Promise>) -> Self {
        initial.into_iter().fold(Self::NONE, Self::with)
    }

    /// Returns `self` with `promise` added.
    ///
    /// Building a set is not a privilege increase: the kernel only sees the
    /// value passed to the next `pledge(2)` call, and it still enforces
    /// monotonicity against the current process state.
    #[inline]
    #[must_use]
    pub const fn with(self, promise: Promise) -> Self {
        Self(self.0 | promise.flag())
    }

    /// Returns the number of promises in `self`.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.0.count_ones()
    }

    /// Returns `true` if `self` contains no promises.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if `self` contains `promise`.
    #[inline]
    #[must_use]
    pub const fn contains(&self, promise: Promise) -> bool {
        let flag = promise.flag();
        self.0 & flag == flag
    }

    /// Iterates over the promises in `self`, in [`Promise::ALL`] order.
    pub fn iter(&self) -> impl Iterator<Item = Promise> + '_ {
        Promise::ALL.into_iter().filter(|p| self.contains(*p))
    }

    /// Removes every promise not in `promises` from `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rust_openbsd::{Promise, Promises};
    /// let mut promises = Promises::new([Promise::Rpath, Promise::Stdio]);
    /// promises.retain([Promise::Stdio]);
    /// assert!(promises.contains(Promise::Stdio));
    /// assert!(!promises.contains(Promise::Rpath));
    /// ```
    pub fn retain(&mut self, promises: impl IntoIterator<Item = Promise>) {
        self.0 = promises
            .into_iter()
            .filter(|promise| self.contains(*promise))
            .fold(0, |bits, promise| bits | promise.flag());
    }

    /// Removes `promise` from `self`.
    #[inline]
    pub const fn remove(&mut self, promise: Promise) {
        self.0 &= !promise.flag();
    }

    /// Removes every promise in `promises` from `self`.
    pub fn remove_all(&mut self, promises: impl IntoIterator<Item = Promise>) {
        for promise in promises {
            self.remove(promise);
        }
    }

    /// Removes every promise not in `promises`, then pledges the result.
    ///
    /// This is "atomic" with respect to `self`: if `pledge(2)` fails, `self` is
    /// restored to its previous value. That matters because a failed reduction
    /// must not leave the tracked set disagreeing with the kernel. The pledge
    /// itself is only attempted when the set actually changes.
    ///
    /// # Errors
    ///
    /// Errors if `pledge(2)` does.
    pub fn retain_then_pledge(
        &mut self,
        promises: impl IntoIterator<Item = Promise>,
    ) -> Result<(), Errno> {
        let previous = Self(self.0);
        self.retain(promises);
        self.pledge_if_changed(previous)
    }

    /// Removes `promise`, then pledges the result.
    ///
    /// See [`Promises::retain_then_pledge`] for the failure semantics.
    ///
    /// # Errors
    ///
    /// Errors if `pledge(2)` does.
    pub fn remove_then_pledge(&mut self, promise: Promise) -> Result<(), Errno> {
        let previous = Self(self.0);
        self.remove(promise);
        self.pledge_if_changed(previous)
    }

    /// Removes every promise in `promises`, then pledges the result.
    ///
    /// See [`Promises::retain_then_pledge`] for the failure semantics.
    ///
    /// # Errors
    ///
    /// Errors if `pledge(2)` does.
    pub fn remove_all_then_pledge(
        &mut self,
        promises: impl IntoIterator<Item = Promise>,
    ) -> Result<(), Errno> {
        let previous = Self(self.0);
        self.remove_all(promises);
        self.pledge_if_changed(previous)
    }

    /// Pledges only when `self` differs from `previous`.
    ///
    /// On failure, `self` is restored to `previous`.
    fn pledge_if_changed(&mut self, previous: Self) -> Result<(), Errno> {
        if *self == previous {
            Ok(())
        } else {
            self.pledge().inspect_err(|_| *self = previous)
        }
    }

    /// Sets the current promises to `self`, passing `NULL` for `execpromises`.
    ///
    /// # Errors
    ///
    /// Errors if `pledge(2)` does.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rust_openbsd::{Promise, Promises};
    /// assert!(Promises::new([Promise::Stdio]).pledge().is_ok());
    /// ```
    #[inline]
    pub fn pledge(&self) -> Result<(), Errno> {
        pledge(self)
    }

    /// Encodes `self` into `buf` as the NUL-terminated string accepted by
    /// `pledge(2)`, returning the length including the terminating NUL.
    ///
    /// The empty set encodes as the empty string, which requests the empty
    /// promise set (as opposed to `NULL`, which leaves the value unchanged).
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "bounds follow from `PLEDGE_BUFFER_LEN` and the loop invariants"
    )]
    pub(crate) fn encode(&self, buf: &mut [u8; PLEDGE_BUFFER_LEN]) -> usize {
        let mut len = 0;
        for promise in Promise::ALL {
            if self.contains(promise) {
                let name = promise.name().as_bytes();
                let end = len + name.len();
                buf[len..end].copy_from_slice(name);
                buf[end] = b' ';
                len = end + 1;
            }
        }
        if len == 0 {
            buf[0] = 0;
            1
        } else {
            // Replace the trailing separator with the NUL terminator.
            buf[len - 1] = 0;
            len
        }
    }
}

/// Returns the OR of the internal flags of every promise.
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the loop index is bounded by `all.len()`"
)]
const fn all_promise_flags() -> u64 {
    let all = Promise::ALL;
    let mut bits = 0;
    let mut i = 0;
    while i < all.len() {
        bits |= all[i].flag();
        i += 1;
    }
    bits
}

impl FromIterator<Promise> for Promises {
    #[inline]
    fn from_iter<T: IntoIterator<Item = Promise>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl Extend<Promise> for Promises {
    #[inline]
    fn extend<T: IntoIterator<Item = Promise>>(&mut self, iter: T) {
        for promise in iter {
            *self = Self(self.0 | promise.flag());
        }
    }
}

impl core::ops::BitOr for Promises {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Promises {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::Sub for Promises {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 & !rhs.0)
    }
}

/// Encodes an optional promise set as a C string pointer.
///
/// [`None`] maps to `NULL` (leave the value unchanged); `Some(set)` maps to the
/// encoded set, which is the empty string for [`Promises::NONE`].
fn encode_arg(promises: Option<&Promises>, buf: &mut [u8; PLEDGE_BUFFER_LEN]) -> *const c_char {
    promises.map_or(ptr::null(), |promises| {
        let _length = promises.encode(buf);
        buf.as_ptr().cast()
    })
}

/// Calls `pledge(2)` with independent control over both arguments.
///
/// The arguments map onto the native call as follows:
///
/// | Argument | Value | Meaning |
/// | --- | --- | --- |
/// | `promises` | [`None`] | `NULL`: do not change the current promises |
/// | `promises` | `Some(&Promises::NONE)` | `""`: restrict the current process to `_exit(2)` only |
/// | `promises` | `Some(set)` | set the current promises to `set` |
/// | `execpromises` | [`None`] | `NULL`: do not change the exec promises |
/// | `execpromises` | `Some(&Promises::NONE)` | `""`: future execs start with no promises |
/// | `execpromises` | `Some(set)` | future execs start with `set` |
///
/// Both parts are changed in a single native call.
///
/// # Errors
///
/// Errors if `pledge(2)` does. A promise increase fails with
/// [`Errno::EPERM`]; an unknown promise fails with [`Errno::EINVAL`].
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{pledge_parts, Promise, Promises};
/// // Leave the current promises alone but restrict future execs.
/// assert!(pledge_parts(None, Some(&Promises::new([Promise::Stdio]))).is_ok());
/// ```
#[expect(unsafe_code, reason = "pledge(2) takes raw pointers")]
pub fn pledge_parts(
    promises: Option<&Promises>,
    execpromises: Option<&Promises>,
) -> Result<(), Errno> {
    let mut promise_buf = [0_u8; PLEDGE_BUFFER_LEN];
    let mut exec_buf = [0_u8; PLEDGE_BUFFER_LEN];
    let promises_ptr = encode_arg(promises, &mut promise_buf);
    let exec_ptr = encode_arg(execpromises, &mut exec_buf);
    // SAFETY:
    // `promises_ptr` is either `NULL` or points at a NUL-terminated string in `promise_buf`,
    // which is live for the duration of the call. The same holds for `exec_ptr` and `exec_buf`.
    // No other thread can observe the buffers, and `pledge(2)` only reads them.
    if unsafe { ffi::pledge(promises_ptr, exec_ptr) } == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Restricts the current process to `promises`, as `pledge(promises, NULL)`.
///
/// Once a promise has been removed it cannot be regained: subsequent calls may
/// only reduce the set further, and an attempt to increase it fails with
/// [`Errno::EPERM`].
///
/// # Errors
///
/// Errors if `pledge(2)` does.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{pledge, Promise, Promises};
/// assert!(pledge(&Promises::new([Promise::Stdio])).is_ok());
/// ```
#[inline]
pub fn pledge(promises: &Promises) -> Result<(), Errno> {
    pledge_parts(Some(promises), None)
}

/// Restricts future children to `execpromises`, as `pledge(NULL, execpromises)`.
///
/// This sets the *exec* promises only: the current process keeps its ordinary
/// promise set. Any program executed later with
/// [`execve(2)`](https://man.openbsd.org/execve.2) starts with exactly this
/// set (unless the executed file has setuid/setgid bits, in which case
/// execution is blocked with `EACCES`).
///
/// The setting is monotonic and is inherited across
/// [`fork(2)`](https://man.openbsd.org/fork.2): OpenBSD copies the exec-promise
/// state into every descendant, which applies it when that descendant executes
/// a new image. It is therefore the preferred way to configure the pledge
/// policy of a fork/exec child: call it *before forking*.
///
/// Note that when `execpromises` is left unset, `execve(2)` does **not**
/// automatically carry the current promises across; the new image starts with
/// no pledge restriction. Use this function (or [`pledge_both`]) to constrain
/// executed programs.
///
/// # Errors
///
/// Errors if `pledge(2)` does.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{pledge_child, Promise, Promises};
/// assert!(pledge_child(&Promises::new([Promise::Stdio])).is_ok());
/// ```
#[inline]
pub fn pledge_child(execpromises: &Promises) -> Result<(), Errno> {
    pledge_parts(None, Some(execpromises))
}

/// Restricts both the current process and future children in a single call, as
/// `pledge(promises, execpromises)`.
///
/// The current process is restricted immediately, which may be inappropriate if
/// the process still needs other operations; use [`pledge_child`] when only
/// future execs should be constrained.
///
/// # Errors
///
/// Errors if `pledge(2)` does.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::{pledge_both, Promise, Promises};
/// let current = Promises::new([Promise::Stdio, Promise::Proc, Promise::Exec]);
/// let exec = Promises::new([Promise::Stdio]);
/// assert!(pledge_both(&current, &exec).is_ok());
/// ```
#[inline]
pub fn pledge_both(promises: &Promises, execpromises: &Promises) -> Result<(), Errno> {
    pledge_parts(Some(promises), Some(execpromises))
}

/// Calls `pledge(2)` with raw C strings.
///
/// This is the lowest-level interface. [`None`] maps to `NULL` (leave the value
/// unchanged) and `Some(c"")` maps to the empty string, preserving the native
/// distinction between the two. The strings must be valid promise lists; an
/// unknown promise fails with [`Errno::EINVAL`].
///
/// Prefer the typed functions unless the promise list is only known at runtime.
///
/// # Errors
///
/// Errors if `pledge(2)` does.
///
/// # Examples
///
/// ```no_run
/// # use rust_openbsd::pledge_raw;
/// assert!(pledge_raw(Some(c"stdio"), None).is_ok());
/// ```
#[expect(unsafe_code, reason = "pledge(2) takes raw pointers")]
pub fn pledge_raw(promises: Option<&CStr>, execpromises: Option<&CStr>) -> Result<(), Errno> {
    let promises_ptr = promises.map_or(ptr::null(), CStr::as_ptr);
    let exec_ptr = execpromises.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY:
    // Each pointer is either `NULL` or a valid pointer to a NUL-terminated string owned by the
    // caller for the duration of this call. `pledge(2)` only reads the strings.
    if unsafe { ffi::pledge(promises_ptr, exec_ptr) } == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Converts a raw byte string into a promise set through [`CStrHelper`].
///
/// This is a convenience for callers that hold a native promise list (for
/// example from a configuration file). Unknown names yield [`Errno::EINVAL`],
/// matching `pledge(2)`.
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] for a NUL byte or an unknown promise name, and
/// [`Errno::ERANGE`] if the input cannot be converted (see [`CStrHelper`]).
pub fn promises_from_str<C: CStrHelper>(promises: C) -> Result<Promises, Errno> {
    promises.convert_then_apply(|cstr| {
        cstr.to_str()
            .map_err(|_| Errno::EINVAL)
            .and_then(parse_promises)
    })
}

/// Parses a whitespace-separated list of promise names.
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] for any unknown name.
fn parse_promises(text: &str) -> Result<Promises, Errno> {
    text.split_whitespace()
        .try_fold(Promises::NONE, |set, name| {
            Promise::from_name(name)
                .map(|promise| set.with(promise))
                .ok_or(Errno::EINVAL)
        })
}
