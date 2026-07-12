#![cfg_attr(
    feature = "std",
    expect(
        clippy::std_instead_of_core,
        reason = "false positive until core::io::ErrorKind is stable"
    )
)]
#[cfg(feature = "std")]
use super::PrivDropErr;
use super::{Errno, Gid, SetresidErr, Uid, UserInfo};
#[cfg(all(feature = "std", target_os = "openbsd"))]
use super::{Permissions, Promise, Promises};
#[cfg(feature = "std")]
use core::net::{Ipv6Addr, SocketAddrV6};
#[cfg(all(feature = "std", target_os = "openbsd"))]
extern crate alloc;
#[cfg(all(feature = "std", target_os = "openbsd"))]
use alloc::format;
#[cfg(all(feature = "std", target_os = "openbsd"))]
use std::io::{self, Write as _};
#[cfg(feature = "std")]
use std::{
    fs,
    io::{Error, ErrorKind},
    net::TcpListener,
};
use tokio as _;
#[cfg(feature = "std")]
const README: &str = "README.md";
#[test]
fn chdir() {
    assert_eq!(crate::chdir(c"./"), Ok(()));
}
#[cfg(not(target_os = "macos"))]
#[test]
fn setgroups() {
    if Uid::geteuid().is_root() {
        assert_eq!(crate::setgroups(&[Gid::getegid()]), Ok(()));
    } else {
        assert_eq!(crate::setgroups(&[Gid::getegid()]), Err(Errno::EPERM));
    }
}
#[test]
fn getuid() {
    _ = Uid::getuid();
}
#[test]
fn geteuid() {
    _ = Uid::geteuid();
}
#[test]
fn getgid() {
    _ = Gid::getgid();
}
#[test]
fn getegid() {
    _ = Gid::getegid();
}
#[test]
fn setresuid() -> Result<(), Errno> {
    Uid::geteuid().setresuid()
}
#[test]
fn setresgid() -> Result<(), Errno> {
    Gid::getegid().setresgid()
}
#[test]
fn user_info_new() {
    assert_eq!(
        UserInfo::new(c"root"),
        Ok(Some(UserInfo {
            uid: Uid::ROOT,
            gid: Gid(0),
        }))
    );
}
#[test]
fn user_info_setresid() -> Result<(), Errno> {
    UserInfo {
        uid: Uid::geteuid(),
        gid: Gid::getegid(),
    }
    .setresid()
}
#[test]
fn user_info_setresid_if_valid() -> Result<(), SetresidErr> {
    UserInfo {
        uid: Uid::geteuid(),
        gid: Gid::getegid(),
    }
    .setresid_if_valid()
}
#[test]
fn user_info_setresid_if_valid_failure() {
    assert_eq!(
        UserInfo {
            uid: Uid::geteuid(),
            gid: Gid(u32::MAX),
        }
        .setresid_if_valid(),
        Err(SetresidErr::GidMismatch)
    );
}
#[cfg(feature = "std")]
#[test]
#[ignore = "primarily useful for root and interferes with chroot_drop_priv"]
fn priv_drop() {
    if Uid::geteuid().is_root() {
        assert!(
            UserInfo::priv_drop(c"nobody", || {
                TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
            })
            .is_ok_and(|_| true)
        );
        assert!(
            TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0)).map_or_else(
                |e| matches!(e.kind(), ErrorKind::PermissionDenied),
                |_| false
            )
        );
    } else {
        assert!(
            UserInfo::priv_drop(c"root", || Ok::<_, Error>(()))
                .map_or_else(|e| matches!(e, PrivDropErr::RootEntry), |()| false)
        );
    }
}
#[cfg(feature = "std")]
#[test]
#[ignore = "primarily useful for root and interferes with priv_drop"]
fn chroot_drop_priv() {
    if Uid::geteuid().is_root() {
        assert!(
            UserInfo::chroot_then_priv_drop(c"nobody", c"./", false, || {
                TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 987, 0, 0))
            })
            .is_ok_and(|_| {
                fs::exists(README).is_ok_and(|exists| {
                    exists
                        && TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 82, 0, 0))
                            .map_or_else(
                                |e| matches!(e.kind(), ErrorKind::PermissionDenied),
                                |_| false,
                            )
                })
            })
        );
    }
}
#[expect(
    clippy::panic,
    reason = "reasonable to expect files to not exist that need to in order to test pledge and unveil"
)]
#[expect(
    clippy::expect_used,
    reason = "kinda reasonable to expect files to exist that mustn't in order to test pledge and unveil"
)]
#[cfg(all(feature = "std", target_os = "openbsd"))]
#[test]
#[ignore = "interferes with other tests"]
fn unveil_pledge() {
    const FILE_EXISTS: &str = "/home/zack/foo.txt";
    const FILE_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23";
    const DIR_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23/";
    _ = fs::metadata(FILE_EXISTS)
        .unwrap_or_else(|_e| panic!("{FILE_EXISTS} does not exist, so unit testing cannot occur"));
    drop(
        fs::metadata(FILE_NOT_EXISTS)
            .expect_err(format!("{FILE_NOT_EXISTS} exists, so unit testing cannot occur").as_str()),
    );
    drop(
        fs::metadata(DIR_NOT_EXISTS)
            .expect_err(format!("{DIR_NOT_EXISTS} exists, so unit testing cannot occur").as_str()),
    );
    // This tests that a NULL `promise` does nothing.
    assert_eq!(Promises::pledge_none(), Ok(()));
    assert!(writeln!(io::stdout()).is_ok_and(|()| true));
    assert_eq!(Promises::ALL.pledge(), Ok(()));
    // This tests that duplicates are ignored as well as the implementation of PartialEq.
    let mut initial_promises = Promises::new([
        Promise::Stdio,
        Promise::Unveil,
        Promise::Rpath,
        Promise::Stdio,
    ]);
    assert_eq!(initial_promises.len(), 3);
    assert_eq!(
        initial_promises,
        Promises::new([Promise::Rpath, Promise::Stdio, Promise::Unveil])
    );
    // Test retain.
    let mut vals = Promises::new([
        Promise::Audio,
        Promise::Bpf,
        Promise::Chown,
        Promise::Cpath,
        Promise::Error,
        Promise::Exec,
    ]);
    vals.retain([Promise::Error, Promise::Chown]);
    assert_eq!(vals.len(), 2);
    assert!(vals.contains(Promise::Chown));
    assert!(vals.contains(Promise::Error));
    assert_eq!(initial_promises.pledge(), Ok(()));
    // This tests unveil with no permissions.
    assert_eq!(Permissions::NONE.unveil(FILE_EXISTS), Ok(()));
    assert!(fs::metadata(FILE_EXISTS).map_or_else(
        |e| matches!(e.kind(), ErrorKind::PermissionDenied),
        |_| false
    ));
    // This tests unveil with read permissions,
    // and one can unveil more permissions (unlike pledge which can only remove promises).
    assert_eq!(Permissions::READ.unveil(FILE_EXISTS), Ok(()));
    assert!(fs::metadata(FILE_EXISTS).is_ok_and(|_| true));
    // This tests that calls to unveil on missing files don't error.
    assert_eq!(Permissions::NONE.unveil(FILE_NOT_EXISTS), Ok(()));
    // This tests that calls to unveil on missing directories error.
    assert_eq!(Permissions::NONE.unveil(DIR_NOT_EXISTS), Err(Errno::ENOENT));
    // This tests that unveil can no longer be called.
    assert_eq!(Permissions::unveil_no_more(), Ok(()));
    assert_eq!(Permissions::NONE.unveil(FILE_EXISTS), Err(Errno::EPERM));
    assert!(fs::metadata(FILE_EXISTS).is_ok_and(|_| true));
    // The below tests that Promises can only be removed and not added.
    initial_promises.remove_promises([Promise::Unveil]);
    assert_eq!(initial_promises.len(), 2);
    initial_promises.remove(Promise::Rpath);
    assert_eq!(initial_promises.len(), 1);
    initial_promises.remove(Promise::Rpath);
    assert_eq!(initial_promises.len(), 1);
    assert_eq!(initial_promises.pledge(), Ok(()));
    assert!(writeln!(io::stdout()).is_ok_and(|()| true));
    assert_eq!(Promises::new([Promise::Rpath]).pledge(), Err(Errno::EPERM));
    // If the below is uncommented, the program should crash since the above
    // call to pledge no longer allows access to the file system.
    // drop(fs::metadata(FILE_EXISTS));
}
#[cfg(all(feature = "std", target_os = "openbsd"))]
#[test]
#[ignore = "interferes with other tests when root"]
fn pledge_inet_drop_priv() {
    if Uid::geteuid().is_root() {
        assert!(
            Promises::new_priv_drop(
                c"nobody",
                [Promise::Inet, Promise::Rpath, Promise::Unveil],
                false,
                || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 47, 0, 0)),
            )
            .is_ok_and(|(_, _)| {
                Permissions::unveil_raw(README, c"r").is_ok_and(|()| {
                    fs::exists(README).is_ok_and(|exists| {
                        Permissions::NONE.unveil(README).is_ok_and(|()| {
                            Promises::pledge_raw(c"inet stdio").is_ok_and(|()| {
                                exists
                                    && TcpListener::bind(SocketAddrV6::new(
                                        Ipv6Addr::LOCALHOST,
                                        792,
                                        0,
                                        0,
                                    ))
                                    .map_or_else(
                                        |e| matches!(e.kind(), ErrorKind::PermissionDenied),
                                        |_| false,
                                    )
                            })
                        })
                    })
                })
            })
        );
    }
}
#[cfg(all(feature = "std", target_os = "openbsd"))]
#[test]
#[ignore = "interferes with other tests when root"]
fn inet_chroot_priv_pledge() {
    if Uid::geteuid().is_root() {
        assert!(
            Promises::new_chroot_then_priv_drop(
                c"nobody",
                c"./",
                [Promise::Inet, Promise::Rpath, Promise::Unveil],
                false,
                || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 382, 0, 0))
            )
            .is_ok_and(
                |(_, mut promises)| Permissions::READ.unveil(README).is_ok_and(|()| fs::exists(
                    README
                )
                .is_ok_and(
                    |exists| Permissions::NONE.unveil(README).is_ok_and(|()| promises
                        .remove_promises_then_pledge([Promise::Rpath, Promise::Unveil])
                        .is_ok_and(|()| exists
                            && TcpListener::bind(SocketAddrV6::new(
                                Ipv6Addr::LOCALHOST,
                                588,
                                0,
                                0
                            ))
                            .map_or_else(
                                |e| matches!(e.kind(), ErrorKind::PermissionDenied),
                                |_| false
                            )))
                ))
            )
        );
    }
}
