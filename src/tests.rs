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

//! Pure, host-independent unit tests.
//!
//! These tests exercise serialization and set logic only; they never call the
//! kernel. Kernel-dependent behavior is covered by the integration tests under
//! `tests/`, which run in isolated child processes on OpenBSD.

#![expect(
    clippy::indexing_slicing,
    reason = "test assertions index into small, statically sized buffers"
)]

use crate::{
    DaemonOptions, Errno, MAX_ENTROPY, PASSWORD_LEN, PROCTITLE_MAX, Rtable, STDERR_FILENO,
    STDIN_FILENO, STDOUT_FILENO, default_daemon_options,
    pledge::{PLEDGE_BUFFER_LEN, Promise, Promises, promises_from_str},
    privileges::{Account, Gid, LOGIN_NAME_MAX, PrivDropError, Uid, ensure_unprivileged},
    process::child_transition_permitted,
    unveil::{Permission, Permissions, permissions_from_str},
};

/// The promise enumeration must cover the selected API version.
#[test]
fn promise_table_is_complete() {
    #[cfg(not(feature = "openbsd-8-0"))]
    assert_eq!(Promise::ALL.len(), 35);
    #[cfg(feature = "openbsd-8-0")]
    {
        assert_eq!(Promise::ALL.len(), 33);
        assert_eq!(Promise::from_name("exec"), None);
        assert_eq!(Promise::from_name("error"), None);
    }
    for promise in Promise::ALL {
        assert_eq!(
            Promise::from_name(promise.name()),
            Some(promise),
            "promise {} did not round-trip",
            promise.name()
        );
    }
}

/// The removed `tmppath` promise must not be representable.
#[test]
fn tmppath_is_absent() {
    assert_eq!(Promise::from_name("tmppath"), None);
}

/// Promise boundaries: `disklabel`, `drm`, `vmm`, and `prot_exec` are present.
#[test]
fn boundary_promises_are_present() {
    for name in ["disklabel", "drm", "vmm", "prot_exec"] {
        assert!(Promise::from_name(name).is_some(), "{name} missing");
    }
}

/// Set operations must be consistent with `contains` and `len`.
#[test]
fn promises_set_operations() {
    let mut promises = Promises::new([Promise::Rpath, Promise::Stdio, Promise::Rpath]);
    assert_eq!(promises.len(), 2);
    assert!(promises.contains(Promise::Rpath));
    assert!(!promises.contains(Promise::Inet));

    promises.remove(Promise::Rpath);
    assert_eq!(promises.len(), 1);
    assert!(!promises.contains(Promise::Rpath));

    promises.remove_all([Promise::Stdio, Promise::Inet]);
    assert!(promises.is_empty());

    let mut retained = Promises::new([Promise::Rpath, Promise::Stdio]);
    retained.retain([Promise::Stdio]);
    assert!(retained.contains(Promise::Stdio));
    assert!(!retained.contains(Promise::Rpath));

    assert_eq!(
        Promises::new([Promise::Rpath, Promise::Stdio])
            .iter()
            .count(),
        2
    );
}

/// The empty set must encode as the empty string, not as `NULL`.
#[test]
fn empty_promise_set_encodes_as_empty_string() {
    let mut buf = [0_u8; PLEDGE_BUFFER_LEN];
    let len = Promises::NONE.encode(&mut buf);
    assert_eq!(len, 1);
    assert_eq!(&buf[..len], b"\0");
}

/// A nonempty set must encode as `name name ...` with a single trailing NUL.
#[test]
fn promise_set_encodes_as_native_string() {
    let mut buf = [0_u8; PLEDGE_BUFFER_LEN];
    let len = Promises::new([Promise::Stdio, Promise::Rpath]).encode(&mut buf);
    assert_eq!(&buf[..len], b"rpath stdio\0");
}

/// `promises_from_str` must parse native promise lists.
#[test]
fn promise_list_parsing() {
    assert_eq!(promises_from_str(c"rpath stdio").map(|p| p.len()), Ok(2));
    assert!(promises_from_str(c"tmppath").is_err());
    assert_eq!(promises_from_str(c"").map(|p| p.is_empty()), Ok(true));
}

/// Permission flags must round-trip through their characters.
#[test]
fn permission_flags() {
    let permissions = Permissions::READ
        .enable(Permission::Write)
        .enable(Permission::Create);
    assert!(permissions.is_enabled(Permission::Read));
    assert!(permissions.is_enabled(Permission::Write));
    assert!(permissions.is_enabled(Permission::Create));
    assert!(!permissions.is_enabled(Permission::Execute));

    assert_eq!(permissions_from_str("rwxc"), Ok(Permissions::ALL));
    assert_eq!(permissions_from_str(""), Ok(Permissions::NONE));
    assert!(permissions_from_str("z").is_err());
}

/// The permission encoding must be the canonical `rwxc` order, NUL-terminated.
#[test]
fn permission_encoding() {
    assert_eq!(Permissions::ALL.encode(), *b"rwxc\0");
    assert_eq!(Permissions::READ.encode(), *b"r\0\0\0\0");
    assert_eq!(Permissions::NONE.encode(), [0_u8; 5]);
}

/// Out-of-range and undefined `errno` values must map to `Other`.
#[test]
fn errno_boundaries() {
    assert_eq!(Errno::from_raw(0), Errno::Other);
    assert_eq!(Errno::from_raw(-1), Errno::Other);
    assert_eq!(Errno::from_raw(96), Errno::Other);
    assert_eq!(Errno::from_raw(1), Errno::EPERM);
    assert_eq!(Errno::from_raw(95), Errno::EPROTO);
    assert_eq!(Errno::LAST, Errno::EPROTO);
    assert_eq!(Errno::EAGAIN, Errno::EWOULDBLOCK);
    for code in 1_i32..=95 {
        assert_eq!(Errno::from_raw(code).into_raw(), code);
    }
}

/// Over-long login names must be rejected rather than truncated.
#[test]
fn account_name_length_is_enforced() {
    let too_long = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(too_long.to_bytes().len(), LOGIN_NAME_MAX);
    assert_eq!(
        Account::new(too_long, Uid(1), Gid(1)),
        Err(PrivDropError::NameTooLong)
    );

    let Ok(account) = Account::new(c"nobody", Uid(2), Gid(3)) else {
        return;
    };
    assert_eq!(account.uid(), Uid(2));
    assert_eq!(account.gid(), Gid(3));
    assert_eq!(account.name(), c"nobody");
}

/// Routing domain IDs are transparently wrapped but validated natively.
#[test]
fn rtable_identity() {
    assert_eq!(Rtable::new(3).into_raw(), 3);
    assert_eq!(Rtable::DEFAULT, Rtable(0));
    assert!(Rtable::DEFAULT < Rtable::new(1));
    assert_eq!(Rtable::default(), Rtable::DEFAULT);
}

/// Daemon options default to the documented positive behaviour.
#[test]
fn daemon_options_default() {
    let options = DaemonOptions::default();
    assert!(options.change_directory_to_root);
    assert!(options.redirect_standard_streams);
    assert_eq!(options, default_daemon_options());
}

/// Every requested daemon transition must succeed before the body runs.
#[test]
fn daemonize_requires_every_requested_transition() {
    let both = DaemonOptions {
        change_directory_to_root: true,
        redirect_standard_streams: true,
    };
    assert!(!child_transition_permitted(both, false, true));
    assert!(!child_transition_permitted(both, true, false));
    assert!(child_transition_permitted(both, true, true));

    let neither = DaemonOptions {
        change_directory_to_root: false,
        redirect_standard_streams: false,
    };
    assert!(child_transition_permitted(neither, false, false));

    let chdir_only = DaemonOptions {
        change_directory_to_root: true,
        redirect_standard_streams: false,
    };
    assert!(!child_transition_permitted(chdir_only, false, false));
    assert!(child_transition_permitted(chdir_only, true, false));
}

/// Name-based drops must reject a root UID or a root primary GID.
#[test]
fn named_drops_reject_root_identity() {
    let Ok(uid_root) = Account::new(c"root", Uid::ROOT, Gid(1)) else {
        return;
    };
    assert_eq!(
        ensure_unprivileged(&uid_root),
        Err(PrivDropError::RootAccount)
    );

    let Ok(gid_root) = Account::new(c"service", Uid(1000), Gid::ROOT) else {
        return;
    };
    assert_eq!(
        ensure_unprivileged(&gid_root),
        Err(PrivDropError::RootAccount)
    );

    let Ok(unprivileged) = Account::new(c"service", Uid(1000), Gid(1000)) else {
        return;
    };
    assert_eq!(ensure_unprivileged(&unprivileged), Ok(()));
}

/// Documented limits and descriptor numbers match the OpenBSD headers.
#[test]
fn documented_limits() {
    assert_eq!(MAX_ENTROPY, 256);
    assert_eq!(PASSWORD_LEN, 128);
    assert_eq!(PROCTITLE_MAX, 2048);
    assert_eq!(crate::PATH_MAX, 1024);
    assert_eq!((STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO), (0, 1, 2));
}

/// Every `ForkExecError` variant renders a distinguishable message.
#[cfg(feature = "std")]
#[test]
fn fork_exec_error_display() {
    use alloc::string::ToString;

    let pledge = crate::ForkExecError::Pledge(Errno::EPERM).to_string();
    assert!(pledge.contains("EPERM") || pledge.contains("not permitted"));
    let spawn =
        crate::ForkExecError::Spawn(std::io::Error::from_raw_os_error(Errno::ENOENT.into_raw()))
            .to_string();
    assert!(spawn.contains("spawn"));
}
