#[cfg(doc)]
use super::chroot_then_chdir;
use super::{NulOrIoErr, PrivDropErr, SUCCESS, UserInfo};
use alloc::ffi::CString;
#[cfg(doc)]
use alloc::ffi::NulError;
use core::{
    ffi::{c_char, c_int},
    fmt::{self, Display, Formatter},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not},
    ptr,
};
use std::{io::Error, os::unix::ffi::OsStrExt as _, path::Path};
#[expect(unsafe_code, reason = "FFI requires unsafe")]
unsafe extern "C" {
    /// [`pledge(2)`](https://man.openbsd.org/pledge.2).
    pub(crate) fn pledge(promises: *const c_char, execpromises: *const c_char) -> c_int;
    /// [`unveil(2)`](https://man.openbsd.org/unveil.2).
    pub(crate) fn unveil(path: *const c_char, permissions: *const c_char) -> c_int;
}
/// A `promise` to [`pledge(2)`](https://man.openbsd.org/pledge.2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Promise {
    /// [`audio`](https://man.openbsd.org/pledge.2#audio).
    Audio,
    /// [`bpf`](https://man.openbsd.org/pledge.2#bpf).
    Bpf,
    /// [`chown`](https://man.openbsd.org/pledge.2#chown).
    Chown,
    /// [`cpath`](https://man.openbsd.org/pledge.2#cpath).
    Cpath,
    /// `disklabel`.
    Disklabel,
    /// [`dns`](https://man.openbsd.org/pledge.2#dns).
    Dns,
    /// [`dpath`](https://man.openbsd.org/pledge.2#dpath).
    Dpath,
    /// `drm`.
    Drm,
    /// [`error`](https://man.openbsd.org/pledge.2#error).
    Error,
    /// [`exec`](https://man.openbsd.org/pledge.2#exec).
    Exec,
    /// [`fattr`](https://man.openbsd.org/pledge.2#fattr).
    Fattr,
    /// [`flock`](https://man.openbsd.org/pledge.2#flock).
    Flock,
    /// [`getpw`](https://man.openbsd.org/pledge.2#getpw).
    Getpw,
    /// [`id`](https://man.openbsd.org/pledge.2#id).
    Id,
    /// [`inet`](https://man.openbsd.org/pledge.2#inet).
    Inet,
    /// [`mcast`](https://man.openbsd.org/pledge.2#mcast).
    Mcast,
    /// [`pf`](https://man.openbsd.org/pledge.2#pf).
    Pf,
    /// [`proc`](https://man.openbsd.org/pledge.2#proc).
    Proc,
    /// [`prot_exec`](https://man.openbsd.org/pledge.2#prot_exec).
    ProtExec,
    /// [`ps`](https://man.openbsd.org/pledge.2#ps).
    Ps,
    /// [`recvfd`](https://man.openbsd.org/pledge.2#recvfd).
    Recvfd,
    /// [`route`](https://man.openbsd.org/pledge.2#route).
    Route,
    /// [`rpath`](https://man.openbsd.org/pledge.2#rpath).
    Rpath,
    /// [`sendfd`](https://man.openbsd.org/pledge.2#sendfd).
    Sendfd,
    /// [`settime`](https://man.openbsd.org/pledge.2#settime).
    Settime,
    /// [`stdio`](https://man.openbsd.org/pledge.2#stdio).
    Stdio,
    /// [`tape`](https://man.openbsd.org/pledge.2#tape).
    Tape,
    /// [`tmppath`](https://man.openbsd.org/pledge.2#tmppath).
    Tmppath,
    /// [`tty`](https://man.openbsd.org/pledge.2#tty).
    Tty,
    /// [`unix`](https://man.openbsd.org/pledge.2#unix).
    Unix,
    /// [`unveil`](https://man.openbsd.org/pledge.2#unveil).
    Unveil,
    /// [`video`](https://man.openbsd.org/pledge.2#video).
    Video,
    /// [`vminfo`](https://man.openbsd.org/pledge.2#vminfo).
    Vminfo,
    /// `vmm`.
    Vmm,
    /// [`wpath`](https://man.openbsd.org/pledge.2#wpath).
    Wpath,
    /// [`wroute`](https://man.openbsd.org/pledge.2#wroute).
    Wroute,
}
impl Promise {
    /// Returns `self` as a `u64`.
    const fn to_u64(self) -> u64 {
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
            Self::Tmppath => 0x0800_0000,
            Self::Tty => 0x1000_0000,
            Self::Unix => 0x2000_0000,
            Self::Unveil => 0x4000_0000,
            Self::Video => 0x8000_0000,
            Self::Vminfo => 0x0001_0000_0000,
            Self::Vmm => 0x0002_0000_0000,
            Self::Wpath => 0x0004_0000_0000,
            Self::Wroute => 0x0008_0000_0000,
        }
    }
}
impl Display for Promise {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Audio => f.write_str("pledge(2) 'audio' promise"),
            Self::Bpf => f.write_str("pledge(2) 'bpf' promise"),
            Self::Chown => f.write_str("pledge(2) 'chown' promise"),
            Self::Cpath => f.write_str("pledge(2) 'cpath' promise"),
            Self::Disklabel => f.write_str("pledge(2) 'disklabel' promise"),
            Self::Dns => f.write_str("pledge(2) 'dns' promise"),
            Self::Dpath => f.write_str("pledge(2) 'dpath' promise"),
            Self::Drm => f.write_str("pledge(2) 'drm' promise"),
            Self::Error => f.write_str("pledge(2) 'error' promise"),
            Self::Exec => f.write_str("pledge(2) 'exec' promise"),
            Self::Fattr => f.write_str("pledge(2) 'fattr' promise"),
            Self::Flock => f.write_str("pledge(2) 'flock' promise"),
            Self::Getpw => f.write_str("pledge(2) 'getpw' promise"),
            Self::Id => f.write_str("pledge(2) 'id' promise"),
            Self::Inet => f.write_str("pledge(2) 'inet' promise"),
            Self::Mcast => f.write_str("pledge(2) 'mcast' promise"),
            Self::Pf => f.write_str("pledge(2) 'pf' promise"),
            Self::Proc => f.write_str("pledge(2) 'proc' promise"),
            Self::ProtExec => f.write_str("pledge(2) 'prot_exec' promise"),
            Self::Ps => f.write_str("pledge(2) 'ps' promise"),
            Self::Recvfd => f.write_str("pledge(2) 'recvfd' promise"),
            Self::Route => f.write_str("pledge(2) 'route' promise"),
            Self::Rpath => f.write_str("pledge(2) 'rpath' promise"),
            Self::Sendfd => f.write_str("pledge(2) 'sendfd' promise"),
            Self::Settime => f.write_str("pledge(2) 'settime' promise"),
            Self::Stdio => f.write_str("pledge(2) 'stdio' promise"),
            Self::Tape => f.write_str("pledge(2) 'tape' promise"),
            Self::Tmppath => f.write_str("pledge(2) 'tmppath' promise"),
            Self::Tty => f.write_str("pledge(2) 'tty' promise"),
            Self::Unix => f.write_str("pledge(2) 'unix' promise"),
            Self::Unveil => f.write_str("pledge(2) 'unveil' promise"),
            Self::Video => f.write_str("pledge(2) 'video' promise"),
            Self::Vminfo => f.write_str("pledge(2) 'vminfo' promise"),
            Self::Vmm => f.write_str("pledge(2) 'vmm' promise"),
            Self::Wpath => f.write_str("pledge(2) 'wpath' promise"),
            Self::Wroute => f.write_str("pledge(2) 'wroute' promise"),
        }
    }
}
impl PartialEq<&Self> for Promise {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Promise> for &Promise {
    #[inline]
    fn eq(&self, other: &Promise) -> bool {
        **self == *other
    }
}
/// A set of [`Promise`]s that can only have `Promise`s removed after creation.
///
/// Once a set of `promises` has been [`pledge(2)`](https://man.openbsd.org/pledge.2)d,
/// only a subset of those `promises` can be `pledge(2)`d again; as a result, this type can be used
/// to ensure that `Promise`s are never added but only removed from an initial set.
#[expect(
    missing_copy_implementations,
    reason = "a single instance should be created"
)]
#[derive(Debug, Eq, PartialEq)]
pub struct Promises(u64);
impl Promises {
    /// Empty `Promises`.
    pub const NONE: Self = Self(0);
    /// `Promises` containing all [`Promise`]s.
    pub const ALL: Self = Self::NONE
        .add(Promise::Audio)
        .add(Promise::Bpf)
        .add(Promise::Chown)
        .add(Promise::Cpath)
        .add(Promise::Disklabel)
        .add(Promise::Dns)
        .add(Promise::Dpath)
        .add(Promise::Drm)
        .add(Promise::Error)
        .add(Promise::Exec)
        .add(Promise::Fattr)
        .add(Promise::Flock)
        .add(Promise::Getpw)
        .add(Promise::Id)
        .add(Promise::Inet)
        .add(Promise::Mcast)
        .add(Promise::Pf)
        .add(Promise::Proc)
        .add(Promise::ProtExec)
        .add(Promise::Ps)
        .add(Promise::Recvfd)
        .add(Promise::Route)
        .add(Promise::Rpath)
        .add(Promise::Sendfd)
        .add(Promise::Settime)
        .add(Promise::Stdio)
        .add(Promise::Tape)
        .add(Promise::Tmppath)
        .add(Promise::Tty)
        .add(Promise::Unix)
        .add(Promise::Unveil)
        .add(Promise::Video)
        .add(Promise::Vminfo)
        .add(Promise::Vmm)
        .add(Promise::Wpath)
        .add(Promise::Wroute);
    /// Returns a `Promises` containing all `Promise`s in `self` and `promise`.
    const fn add(self, promise: Promise) -> Self {
        Self(self.0 | promise.to_u64())
    }
    /// Returns a `Promises` containing the unique `Promise`s in `initial`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// assert_eq!(Promises::new([Promise::Stdio]).len(), 1);
    /// ```
    #[inline]
    #[must_use]
    pub fn new<P: AsRef<[Promise]>>(initial: P) -> Self {
        initial
            .as_ref()
            .iter()
            .fold(Self::NONE, |val, promise| val.add(*promise))
    }
    /// Same as [`UserInfo::priv_drop`] except [`Self::pledge`] is called between [`UserInfo::new`] and
    /// the invocation of `f`.
    ///
    /// Note [`Promise::Id`] and [`Promise::Stdio`] are automatically added to `initial`. `retain_id_promise`
    /// dictates if [`Promise::Id`] should subsequently be retained after [`UserInfo::setresid`]. Callers must
    /// ensure `initial` contains any necessary [`Promise`]s needed for `f`.
    ///
    /// # Errors
    ///
    /// Errors iff [`UserInfo::priv_drop`] or [`Self::pledge`] error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use priv_sep::PrivDropErr;
    /// # use std::{io::Error, net::TcpListener};
    /// # #[cfg(target_os = "openbsd")]
    /// let (listener, promises) = Promises::new_priv_drop("nobody", [Promise::Inet], false, || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
    /// })?;
    /// # Ok::<_, PrivDropErr<Error>>(())
    /// ```
    #[inline]
    pub fn new_priv_drop<
        U: Into<Vec<u8>>,
        Prom: AsRef<[Promise]>,
        T,
        E,
        F: FnOnce() -> Result<T, E>,
    >(
        name: U,
        initial: Prom,
        retain_id_promise: bool,
        f: F,
    ) -> Result<(T, Self), PrivDropErr<E>> {
        let mut promises = initial.as_ref().iter().fold(
            Self::NONE.add(Promise::Id).add(Promise::Stdio),
            |val, promise| val.add(*promise),
        );
        UserInfo::new(name)
            .map_err(PrivDropErr::from)
            .and_then(|opt| {
                opt.ok_or_else(|| PrivDropErr::NoPasswdEntry)
                    .and_then(|info| {
                        if info.is_root() {
                            Err(PrivDropErr::RootEntry)
                        } else {
                            promises.pledge().map_err(PrivDropErr::Io).and_then(|()| {
                                f().map_err(PrivDropErr::Other).and_then(|res| {
                                    info.setresid().map_err(PrivDropErr::Io).and_then(|()| {
                                        if retain_id_promise {
                                            Ok(())
                                        } else {
                                            promises
                                                .remove_then_pledge(Promise::Id)
                                                .map_err(PrivDropErr::Io)
                                        }
                                        .map(|()| (res, promises))
                                    })
                                })
                            })
                        }
                    })
            })
    }
    /// Same as [`Self::new_priv_drop`] except `f` is `async`.
    ///
    /// # Errors
    ///
    /// Read [`Self::new_priv_drop`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use tokio::net::TcpListener;
    /// # #[cfg(target_os = "openbsd")]
    /// let listener_fut = Promises::new_priv_drop_async("nobody", [Promise::Inet], false, async || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
    /// });
    /// ```
    #[inline]
    pub async fn new_priv_drop_async<
        U: Into<Vec<u8>>,
        Prom: AsRef<[Promise]>,
        T,
        E,
        F: AsyncFnOnce() -> Result<T, E>,
    >(
        name: U,
        initial: Prom,
        retain_id_promise: bool,
        f: F,
    ) -> Result<(T, Self), PrivDropErr<E>> {
        let mut promises = initial.as_ref().iter().fold(
            Self::NONE.add(Promise::Id).add(Promise::Stdio),
            |val, promise| val.add(*promise),
        );
        match UserInfo::new(name) {
            Ok(opt) => match opt {
                None => Err(PrivDropErr::NoPasswdEntry),
                Some(info) => {
                    if info.is_root() {
                        Err(PrivDropErr::RootEntry)
                    } else {
                        match promises.pledge() {
                            Ok(()) => f().await.map_err(PrivDropErr::Other).and_then(|res| {
                                info.setresid().map_err(PrivDropErr::Io).and_then(|()| {
                                    if retain_id_promise {
                                        Ok(())
                                    } else {
                                        promises
                                            .remove_then_pledge(Promise::Id)
                                            .map_err(PrivDropErr::Io)
                                    }
                                    .map(|()| (res, promises))
                                })
                            }),
                            Err(err) => Err(PrivDropErr::Io(err)),
                        }
                    }
                }
            },
            Err(err) => Err(PrivDropErr::from(err)),
        }
    }
    /// Same as [`Self::new_priv_drop`] except [`chroot_then_chdir`] is called before [`Self::pledge`]ing `initial`.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::new_priv_drop`] or [`chroot_then_chdir`] do.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use priv_sep::PrivDropErr;
    /// # use std::{io::Error, net::TcpListener};
    /// # #[cfg(target_os = "openbsd")]
    /// let (listener, promises) = Promises::new_chroot_then_priv_drop("nobody", "./", [Promise::Inet], false, || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
    /// })?;
    /// # Ok::<_, PrivDropErr<Error>>(())
    /// ```
    #[inline]
    pub fn new_chroot_then_priv_drop<
        U: Into<Vec<u8>>,
        P: AsRef<Path>,
        Prom: AsRef<[Promise]>,
        T,
        E,
        F: FnOnce() -> Result<T, E>,
    >(
        name: U,
        path: P,
        initial: Prom,
        retain_id_promise: bool,
        f: F,
    ) -> Result<(T, Self), PrivDropErr<E>> {
        let mut promises = initial.as_ref().iter().fold(
            Self::NONE.add(Promise::Id).add(Promise::Stdio),
            |val, promise| val.add(*promise),
        );
        UserInfo::new(name)
            .map_err(PrivDropErr::from)
            .and_then(|opt| {
                opt.ok_or_else(|| PrivDropErr::NoPasswdEntry)
                    .and_then(|info| {
                        if info.is_root() {
                            Err(PrivDropErr::RootEntry)
                        } else {
                            super::chroot_then_chdir(path)
                                .map_err(PrivDropErr::from)
                                .and_then(|()| {
                                    promises.pledge().map_err(PrivDropErr::Io).and_then(|()| {
                                        f().map_err(PrivDropErr::Other).and_then(|res| {
                                            info.setresid().map_err(PrivDropErr::Io).and_then(
                                                |()| {
                                                    if retain_id_promise {
                                                        Ok(())
                                                    } else {
                                                        promises
                                                            .remove_then_pledge(Promise::Id)
                                                            .map_err(PrivDropErr::Io)
                                                    }
                                                    .map(|()| (res, promises))
                                                },
                                            )
                                        })
                                    })
                                })
                        }
                    })
            })
    }
    /// Same as [`Self::new_chroot_then_priv_drop`] except `f` is `async`.
    ///
    /// # Errors
    ///
    /// Read [`Self::new_chroot_then_priv_drop`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # use core::net::{Ipv6Addr, SocketAddrV6};
    /// # use tokio::net::TcpListener;
    /// # #[cfg(target_os = "openbsd")]
    /// let listener_fut = Promises::new_chroot_then_priv_drop_async("nobody", "./", [Promise::Inet], false, async || {
    ///     TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
    /// });
    /// ```
    #[inline]
    pub async fn new_chroot_then_priv_drop_async<
        U: Into<Vec<u8>>,
        P: AsRef<Path>,
        Prom: AsRef<[Promise]>,
        T,
        E,
        F: AsyncFnOnce() -> Result<T, E>,
    >(
        name: U,
        path: P,
        initial: Prom,
        retain_id_promise: bool,
        f: F,
    ) -> Result<(T, Self), PrivDropErr<E>> {
        let mut promises = initial.as_ref().iter().fold(
            Self::NONE.add(Promise::Id).add(Promise::Stdio),
            |val, promise| val.add(*promise),
        );
        match UserInfo::new(name) {
            Ok(opt) => match opt {
                None => Err(PrivDropErr::NoPasswdEntry),
                Some(info) => {
                    if info.is_root() {
                        Err(PrivDropErr::RootEntry)
                    } else {
                        match super::chroot_then_chdir(path) {
                            Ok(()) => match promises.pledge() {
                                Ok(()) => f().await.map_err(PrivDropErr::Other).and_then(|res| {
                                    info.setresid().map_err(PrivDropErr::Io).and_then(|()| {
                                        if retain_id_promise {
                                            Ok(())
                                        } else {
                                            promises
                                                .remove_then_pledge(Promise::Id)
                                                .map_err(PrivDropErr::Io)
                                        }
                                        .map(|()| (res, promises))
                                    })
                                }),
                                Err(err) => Err(PrivDropErr::Io(err)),
                            },
                            Err(err) => Err(PrivDropErr::from(err)),
                        }
                    }
                }
            },
            Err(err) => Err(PrivDropErr::from(err)),
        }
    }
    /// Returns the number of [`Promise`]s.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// assert_eq!(Promises::new([Promise::Stdio]).len(), 1);
    /// ```
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.0.count_ones()
    }
    /// Returns `true` iff there are no [`Promise`]s.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::Promises;
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Promises::NONE.is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns `true` iff `self` contains `promise`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Promises::new([Promise::Stdio]).contains(Promise::Stdio));
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(!Promises::new([Promise::Stdio]).contains(Promise::Rpath));
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains(&self, promise: Promise) -> bool {
        let val = promise.to_u64();
        self.0 & val == val
    }
    /// Removes all `Promise`s _not_ in `promises` from `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// let mut proms = Promises::new([Promise::Rpath, Promise::Stdio]);
    /// # #[cfg(target_os = "openbsd")]
    /// proms.retain([Promise::Stdio]);
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(proms.len() == 1 && proms.contains(Promise::Stdio));
    /// ```
    #[inline]
    pub fn retain<P: AsRef<[Promise]>>(&mut self, promises: P) {
        self.0 = promises
            .as_ref()
            .iter()
            .fold(Self::NONE, |val, promise| {
                if self.contains(*promise) {
                    val.add(*promise)
                } else {
                    val
                }
            })
            .0;
    }
    /// Same as [`Self::retain`] then [`Self::pledge`]; however this is "atomic" in that if an error occurs from `pledge`,
    /// `self` is left unchanged. This is useful when one wants to "recover" from an error since there is no
    /// way to add `Promise`s back forcing one to have to create a second `Promises`.
    ///
    /// Note that when `retain` doesn't change `self`, `pledge` is not called.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] iff `pledge` does.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Promises::new([Promise::Rpath, Promise::Stdio]).retain_then_pledge([Promise::Rpath]).is_ok());
    /// ```
    #[inline]
    pub fn retain_then_pledge<P: AsRef<[Promise]>>(&mut self, promises: P) -> Result<(), Error> {
        // We opt for the easy way by copying `self`. This should be the fastest for the
        // typical case since `self` likely has very few `Promise`s, and it makes for less code.
        let cur = Self(self.0);
        self.retain(promises);
        if *self == cur {
            Ok(())
        } else {
            self.pledge().inspect_err(|_| *self = cur)
        }
    }
    /// Removes all `Promise`s in `promises` from `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// let mut proms = Promises::new([Promise::Rpath, Promise::Stdio]);
    /// # #[cfg(target_os = "openbsd")]
    /// proms.remove_promises([Promise::Stdio]);
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(proms.len() == 1 && proms.contains(Promise::Rpath));
    /// ```
    #[inline]
    pub fn remove_promises<P: AsRef<[Promise]>>(&mut self, promises: P) {
        promises
            .as_ref()
            .iter()
            .fold((), |(), promise| self.remove(*promise));
    }
    /// Same as [`Self::remove_promises`] then [`Self::pledge`]; however this is "atomic" in that if an error occurs from
    /// `pledge`, `self` is left unchanged. This is useful when one wants to "recover" from an error since there
    /// is no way to add `Promise`s back forcing one to have to create a second `Promises`.
    ///
    /// Note that when `remove_promises` doesn't remove any, `pledge` is not called.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] iff `pledge` does.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Promises::new([Promise::Rpath, Promise::Stdio]).remove_promises_then_pledge([Promise::Rpath]).is_ok());
    /// ```
    #[inline]
    pub fn remove_promises_then_pledge<P: AsRef<[Promise]>>(
        &mut self,
        promises: P,
    ) -> Result<(), Error> {
        // We opt for the easy way by copying `self`. This should be the fastest for the
        // typical case since `self` likely has very few `Promise`s, and it makes for less code.
        let cur = Self(self.0);
        self.remove_promises(promises);
        if *self == cur {
            Ok(())
        } else {
            self.pledge().inspect_err(|_| *self = cur)
        }
    }
    /// Removes `promise` from `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// let mut proms = Promises::new([Promise::Rpath, Promise::Stdio]);
    /// # #[cfg(target_os = "openbsd")]
    /// proms.remove(Promise::Stdio);
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(proms.len() == 1 && proms.contains(Promise::Rpath));
    /// ```
    #[inline]
    pub const fn remove(&mut self, promise: Promise) {
        self.0 &= !promise.to_u64();
    }
    /// Same as [`Self::remove`] then [`Self::pledge`]; however this is "atomic" in that if an error occurs from `pledge`,
    /// `self` is left unchanged. This is useful when one wants to "recover" from an error since there is no
    /// way to add `Promise`s back forcing one to have to create a second `Promises`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] iff `pledge` does.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Promises::new([Promise::Rpath, Promise::Stdio]).remove_then_pledge(Promise::Rpath).is_ok());
    /// ```
    #[inline]
    pub fn remove_then_pledge(&mut self, promise: Promise) -> Result<(), Error> {
        // We opt for the easy way by copying `self`. This should be the fastest for the
        // typical case since `self` likely has very few `Promise`s, and it makes for less code.
        let cur = Self(self.0);
        self.remove(promise);
        if *self == cur {
            Ok(())
        } else {
            self.pledge().inspect_err(|_| *self = cur)
        }
    }
    /// Invokes `pledge(2)` always passing `NULL` for `execpromises` and `promises` for `promises`.
    ///
    /// This function MUST only be called by [`Self::pledge`] and [`Self::pledge_none`].
    #[expect(unsafe_code, reason = "pledge(2) takes in pointers")]
    fn inner_pledge(promises: *const c_char) -> Result<(), Error> {
        // SAFETY:
        // `promises` is either null or valid as can be seen in the only functions that call this
        // function:
        // `Self::pledge` and `Self::pledge_none`.
        if unsafe { pledge(promises, ptr::null()) } == SUCCESS {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    }
    /// Invokes [`pledge(2)`](https://man.openbsd.org/pledge.2) always passing in
    /// `NULL` for `execpromises` and its contained [`Promise`]s for `promises`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] iff `pledge(2)` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Promise, Promises};
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Promises::new([Promise::Stdio]).pledge().is_ok());
    /// ```
    #[expect(
        unsafe_code,
        reason = "we manually construct a valid CString and ensure its safety"
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "we replace a trailing space with 0 to ensure CString is correctly constructed"
    )]
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "many if blocks to handle each Promise"
    )]
    #[inline]
    pub fn pledge(&self) -> Result<(), Error> {
        let mut p = Vec::new();
        if self.contains(Promise::Audio) {
            p.extend_from_slice(b"audio ");
        }
        if self.contains(Promise::Bpf) {
            p.extend_from_slice(b"bpf ");
        }
        if self.contains(Promise::Chown) {
            p.extend_from_slice(b"chown ");
        }
        if self.contains(Promise::Cpath) {
            p.extend_from_slice(b"cpath ");
        }
        if self.contains(Promise::Disklabel) {
            p.extend_from_slice(b"disklabel ");
        }
        if self.contains(Promise::Dns) {
            p.extend_from_slice(b"dns ");
        }
        if self.contains(Promise::Dpath) {
            p.extend_from_slice(b"dpath ");
        }
        if self.contains(Promise::Drm) {
            p.extend_from_slice(b"drm ");
        }
        if self.contains(Promise::Error) {
            p.extend_from_slice(b"error ");
        }
        if self.contains(Promise::Exec) {
            p.extend_from_slice(b"exec ");
        }
        if self.contains(Promise::Fattr) {
            p.extend_from_slice(b"fattr ");
        }
        if self.contains(Promise::Flock) {
            p.extend_from_slice(b"flock ");
        }
        if self.contains(Promise::Getpw) {
            p.extend_from_slice(b"getpw ");
        }
        if self.contains(Promise::Id) {
            p.extend_from_slice(b"id ");
        }
        if self.contains(Promise::Inet) {
            p.extend_from_slice(b"inet ");
        }
        if self.contains(Promise::Mcast) {
            p.extend_from_slice(b"mcast ");
        }
        if self.contains(Promise::Pf) {
            p.extend_from_slice(b"pf ");
        }
        if self.contains(Promise::Proc) {
            p.extend_from_slice(b"proc ");
        }
        if self.contains(Promise::ProtExec) {
            p.extend_from_slice(b"prot_exec ");
        }
        if self.contains(Promise::Ps) {
            p.extend_from_slice(b"ps ");
        }
        if self.contains(Promise::Recvfd) {
            p.extend_from_slice(b"recvfd ");
        }
        if self.contains(Promise::Route) {
            p.extend_from_slice(b"route ");
        }
        if self.contains(Promise::Rpath) {
            p.extend_from_slice(b"rpath ");
        }
        if self.contains(Promise::Sendfd) {
            p.extend_from_slice(b"sendfd ");
        }
        if self.contains(Promise::Settime) {
            p.extend_from_slice(b"settime ");
        }
        if self.contains(Promise::Stdio) {
            p.extend_from_slice(b"stdio ");
        }
        if self.contains(Promise::Tape) {
            p.extend_from_slice(b"tape ");
        }
        if self.contains(Promise::Tmppath) {
            p.extend_from_slice(b"tmppath ");
        }
        if self.contains(Promise::Tty) {
            p.extend_from_slice(b"tty ");
        }
        if self.contains(Promise::Unix) {
            p.extend_from_slice(b"unix ");
        }
        if self.contains(Promise::Unveil) {
            p.extend_from_slice(b"unveil ");
        }
        if self.contains(Promise::Video) {
            p.extend_from_slice(b"video ");
        }
        if self.contains(Promise::Vminfo) {
            p.extend_from_slice(b"vminfo ");
        }
        if self.contains(Promise::Vmm) {
            p.extend_from_slice(b"vmm ");
        }
        if self.contains(Promise::Wpath) {
            p.extend_from_slice(b"wpath ");
        }
        if self.contains(Promise::Wroute) {
            p.extend_from_slice(b"wroute ");
        }
        let idx = p.len();
        if idx == 0 {
            p.push(0);
        } else {
            // All promises have a space after them which means
            // we must replace the last promise's space with
            // 0/nul byte.
            // `idx` is at least 1 based on the above check.
            p[idx - 1] = 0;
        }
        // SAFETY:
        // `p` was populated above with correct ASCII-encoding of the literal
        // values all of which do not have 0 bytes.
        // `p` ends with a 0/nul byte.
        let arg = unsafe { CString::from_vec_with_nul_unchecked(p) };
        Self::inner_pledge(arg.as_ptr())
    }
    /// Invokes [`pledge(2)`](https://man.openbsd.org/pledge.2) with `NULL` for both `promises` and
    /// `execpromises`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] iff `pledge(2)` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::Promises;
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Promises::pledge_none().is_ok());
    /// ```
    #[inline]
    pub fn pledge_none() -> Result<(), Error> {
        // `NULL` is always valid for `promises`.
        Self::inner_pledge(ptr::null())
    }
}
impl PartialEq<&Self> for Promises {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Promises> for &Promises {
    #[inline]
    fn eq(&self, other: &Promises) -> bool {
        **self == *other
    }
}
/// A permission in [`Permissions`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Permission {
    /// [c](https://man.openbsd.org/unveil.2#c).
    Create,
    /// [x](https://man.openbsd.org/unveil.2#x).
    Execute,
    /// [r](https://man.openbsd.org/unveil.2#r).
    Read,
    /// [w](https://man.openbsd.org/unveil.2#w).
    Write,
}
impl Permission {
    /// Transforms `self` into a `u8`.
    const fn to_u8(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::Execute => 2,
            Self::Read => 4,
            Self::Write => 8,
        }
    }
}
impl PartialEq<&Self> for Permission {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Permission> for &Permission {
    #[inline]
    fn eq(&self, other: &Permission) -> bool {
        **self == *other
    }
}
/// `permissions` to [`unveil(2)`](https://man.openbsd.org/unveil.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permissions(u8);
impl Permissions {
    /// A `Permissions` with no [`Permission`]s enabled.
    pub const NONE: Self = Self(0);
    /// A `Permissions` with all [`Permission`]s enabled.
    pub const ALL: Self = Self::NONE
        .enable(Permission::Create)
        .enable(Permission::Execute)
        .enable(Permission::Read)
        .enable(Permission::Write);
    /// A `Permissions` with only [`Permission::Create`] enabled.
    pub const CREATE: Self = Self::NONE.enable(Permission::Create);
    /// A `Permissions` with only [`Permission::Execute`] enabled.
    pub const EXECUTE: Self = Self::NONE.enable(Permission::Execute);
    /// A `Permissions` with only [`Permission::Read`] enabled.
    pub const READ: Self = Self::NONE.enable(Permission::Read);
    /// A `Permissions` with only [`Permission::Write`] enabled.
    pub const WRITE: Self = Self::NONE.enable(Permission::Write);
    /// `const` version of [`Self::bitor`].
    #[inline]
    #[must_use]
    pub const fn enable(self, permission: Permission) -> Self {
        Self(self.0 | permission.to_u8())
    }
    /// Returns `true` iff `self` has `permission` enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Permission, Permissions};
    /// # #[cfg(target_os = "openbsd")]
    /// let perms = Permissions::CREATE;
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(perms.is_enabled(Permission::Create));
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(!perms.is_enabled(Permission::Write));
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_enabled(self, permission: Permission) -> bool {
        let val = permission.to_u8();
        self.0 & val == val
    }
    /// Invokes `unveil(2)` passing `path` for `path` and `permissions` for `permissions`.
    ///
    /// This function MUST only be called by the functions [`Self::unveil`] and [`Self::unveil_no_more`].
    #[expect(unsafe_code, reason = "unveil(2) takes in pointers")]
    fn inner_unveil(path: *const c_char, permissions: *const c_char) -> Result<(), Error> {
        // SAFETY:
        // `path` and `permissions` are either null or valid as can be seen in the only functions that call this
        // function:
        // `Self::unveil` and `Self::unveil_no_more`.
        if unsafe { unveil(path, permissions) } == SUCCESS {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    }
    /// Invokes [`unveil(2)`](https://man.openbsd.org/unveil.2)
    /// passing `path` for `path` and the contained permissions for `permissions`.
    ///
    /// # Errors
    ///
    /// Returns [`NulError`] iff [`CString::new`] does.
    /// Returns [`Error`] iff `unveil(2)` errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use std::io::ErrorKind;
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::{Permissions, NulOrIoErr};
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Permissions::READ.unveil("/path/to/read").is_ok());
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Permissions::READ.unveil("/path/does/not/exist").map_or_else(
    ///     |err| match err {
    ///         NulOrIoErr::Io(e) => e.kind() == ErrorKind::NotFound,
    ///         NulOrIoErr::Nul(_) => false,
    ///     },
    ///     |()| false
    /// ));
    /// ```
    #[expect(
        unsafe_code,
        reason = "we manually construct a valid CString and ensure its safety"
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "we pre-allocate a Vec with the exact capacity which is capped at 5"
    )]
    #[inline]
    pub fn unveil<P: AsRef<Path>>(self, path: P) -> Result<(), NulOrIoErr> {
        CString::new(path.as_ref().as_os_str().as_bytes()).map_or_else(
            |e| Err(NulOrIoErr::Nul(e)),
            |path_c| {
                // The max sum is 5, so overflow is not possible.
                let mut vec = Vec::with_capacity(
                    usize::from(self.is_enabled(Permission::Create))
                        + usize::from(self.is_enabled(Permission::Execute))
                        + usize::from(self.is_enabled(Permission::Read))
                        + usize::from(self.is_enabled(Permission::Write))
                        + 1,
                );
                if self.is_enabled(Permission::Create) {
                    vec.push(b'c');
                }
                if self.is_enabled(Permission::Execute) {
                    vec.push(b'x');
                }
                if self.is_enabled(Permission::Read) {
                    vec.push(b'r');
                }
                if self.is_enabled(Permission::Write) {
                    vec.push(b'w');
                }
                vec.push(0);
                // SAFETY:
                // `vec` was populated above with correct ASCII-encoding of the literal
                // values all of which do not have 0 bytes.
                // `vec` ends with a 0/nul byte.
                let perm_c = unsafe { CString::from_vec_with_nul_unchecked(vec) };
                Self::inner_unveil(path_c.as_ptr(), perm_c.as_ptr()).map_err(NulOrIoErr::Io)
            },
        )
    }
    /// Invokes [`unveil(2)`](https://man.openbsd.org/unveil.2) by passing `NULL` for both `path` and
    /// `permissions`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when a problem occurs.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(target_os = "openbsd")]
    /// # use priv_sep::Permissions;
    /// # #[cfg(target_os = "openbsd")]
    /// assert!(Permissions::unveil_no_more().is_ok());
    /// ```
    #[inline]
    pub fn unveil_no_more() -> Result<(), Error> {
        // `NULL` is valid for both `path` and `permissions`.
        Self::inner_unveil(ptr::null(), ptr::null())
    }
}
impl Display for Permissions {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unveil(2) '{}{}{}{}' permissions",
            if self.is_enabled(Permission::Create) {
                "c"
            } else {
                ""
            },
            if self.is_enabled(Permission::Execute) {
                "x"
            } else {
                ""
            },
            if self.is_enabled(Permission::Read) {
                "r"
            } else {
                ""
            },
            if self.is_enabled(Permission::Write) {
                "w"
            } else {
                ""
            },
        )
    }
}
impl BitAnd<Permission> for Permissions {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Permission) -> Self::Output {
        Self(self.0 & rhs.to_u8())
    }
}
impl BitAndAssign<Permission> for Permissions {
    #[inline]
    fn bitand_assign(&mut self, rhs: Permission) {
        self.0 &= rhs.to_u8();
    }
}
impl BitOr<Permission> for Permissions {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Permission) -> Self::Output {
        Self(self.0 | rhs.to_u8())
    }
}
impl BitOrAssign<Permission> for Permissions {
    #[inline]
    fn bitor_assign(&mut self, rhs: Permission) {
        self.0 |= rhs.to_u8();
    }
}
impl BitXor<Permission> for Permissions {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Permission) -> Self::Output {
        Self(self.0 ^ rhs.to_u8())
    }
}
impl BitXorAssign<Permission> for Permissions {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Permission) {
        self.0 ^= rhs.to_u8();
    }
}
impl Not for Permissions {
    type Output = Self;
    #[inline]
    fn not(self) -> Self::Output {
        Self(Self::ALL.0 & !self.0)
    }
}
impl PartialEq<&Self> for Permissions {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Permissions> for &Permissions {
    #[inline]
    fn eq(&self, other: &Permissions) -> bool {
        **self == *other
    }
}
#[cfg(test)]
mod tests {
    use super::{Permissions, Promise, Promises};
    use crate::{PrivDropErr, Uid};
    use core::net::{Ipv6Addr, SocketAddrV6};
    use std::{fs, io::Error, net::TcpListener};
    const README: &str = "README.md";
    #[test]
    #[ignore]
    fn test_pledge_unveil() {
        const FILE_EXISTS: &str = "/home/zack/foo.txt";
        _ = fs::metadata(FILE_EXISTS)
            .expect(format!("{FILE_EXISTS} does not exist, so unit testing cannot occur").as_str());
        const FILE_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23";
        drop(fs::metadata(FILE_NOT_EXISTS).expect_err(
            format!("{FILE_NOT_EXISTS} exists, so unit testing cannot occur").as_str(),
        ));
        const DIR_NOT_EXISTS: &str = "/home/zack/aadkjfasj3s23/";
        drop(
            fs::metadata(DIR_NOT_EXISTS).expect_err(
                format!("{DIR_NOT_EXISTS} exists, so unit testing cannot occur").as_str(),
            ),
        );
        // This tests that a NULL `promise` does nothing.
        assert!(Promises::pledge_none().is_ok());
        print!("");
        assert!(Promises::ALL.pledge().is_ok());
        // This tests that duplicates are ignored as well as the implementation of PartialEq.
        let mut initial_promises = Promises::new([
            Promise::Stdio,
            Promise::Unveil,
            Promise::Rpath,
            Promise::Stdio,
        ]);
        assert!(initial_promises.len() == 3);
        assert!(
            initial_promises == Promises::new([Promise::Rpath, Promise::Stdio, Promise::Unveil])
        );
        // Test retain.
        assert!({
            let mut vals = Promises::new([
                Promise::Audio,
                Promise::Bpf,
                Promise::Chown,
                Promise::Cpath,
                Promise::Error,
                Promise::Exec,
            ]);
            vals.retain([Promise::Error, Promise::Chown]);
            vals.len() == 2 && vals.contains(Promise::Chown) && vals.contains(Promise::Error)
        });
        assert!(initial_promises.pledge().is_ok());
        // This tests unveil with no permissions.
        assert!(Permissions::NONE.unveil(FILE_EXISTS).is_ok());
        assert!(fs::metadata(FILE_EXISTS).is_err());
        // This tests unveil with read permissions,
        // and one can unveil more permissions (unlike pledge which can only remove promises).
        assert!(Permissions::READ.unveil(FILE_EXISTS).is_ok());
        assert!(fs::metadata(FILE_EXISTS).is_ok());
        // This tests that calls to unveil on missing files don't error.
        assert!(Permissions::NONE.unveil(FILE_NOT_EXISTS).is_ok());
        // This tests that calls to unveil on missing directories error.
        assert!(Permissions::NONE.unveil(DIR_NOT_EXISTS).is_err());
        // This tests that unveil can no longer be called.
        assert!(Permissions::unveil_no_more().is_ok());
        assert!(Permissions::NONE.unveil(FILE_EXISTS).is_err());
        assert!(fs::metadata(FILE_EXISTS).is_ok());
        // The below tests that Promises can only be removed and not added.
        initial_promises.remove_promises([Promise::Unveil]);
        assert_eq!(initial_promises.len(), 2);
        initial_promises.remove(Promise::Rpath);
        assert_eq!(initial_promises.len(), 1);
        initial_promises.remove(Promise::Rpath);
        assert_eq!(initial_promises.len(), 1);
        assert!(initial_promises.pledge().is_ok());
        print!("");
        assert!(Promises::new([Promise::Rpath]).pledge().is_err());
        // If the below is uncommented, the program should crash since the above
        // call to pledge no longer allows access to the file system.
        // drop(fs::metadata(FILE_EXISTS));
    }
    #[test]
    #[ignore]
    fn test_pledge_priv_drop() -> Result<(), PrivDropErr<Error>> {
        if Uid::geteuid().is_root() {
            Promises::new_priv_drop(
                "zack",
                [Promise::Inet, Promise::Rpath, Promise::Unveil],
                false,
                || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
            )
            .and_then(|(_, mut promises)| {
                Permissions::READ
                    .unveil(README)
                    .map_err(PrivDropErr::from)
                    .and_then(|()| {
                        fs::exists(README)
                            .map_err(PrivDropErr::Io)
                            .and_then(|exists| {
                                Permissions::NONE
                                    .unveil(README)
                                    .map_err(PrivDropErr::from)
                                    .and_then(|()| {
                                        promises
                                            .remove_promises_then_pledge([
                                                Promise::Rpath,
                                                Promise::Unveil,
                                            ])
                                            .map_err(PrivDropErr::Io)
                                            .map(|()| {
                                                assert!(exists);
                                                assert!(
                                                    TcpListener::bind(SocketAddrV6::new(
                                                        Ipv6Addr::LOCALHOST,
                                                        80,
                                                        0,
                                                        0
                                                    ))
                                                    .is_err()
                                                );
                                            })
                                    })
                            })
                    })
            })
        } else {
            Ok(())
        }
    }
    #[test]
    #[ignore]
    fn test_pledge_chroot_priv_drop() -> Result<(), PrivDropErr<Error>> {
        if Uid::geteuid().is_root() {
            Promises::new_chroot_then_priv_drop(
                "zack",
                "./",
                [Promise::Inet, Promise::Rpath, Promise::Unveil],
                false,
                || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
            )
            .and_then(|(_, mut promises)| {
                Permissions::READ
                    .unveil(README)
                    .map_err(PrivDropErr::from)
                    .and_then(|()| {
                        fs::exists(README)
                            .map_err(PrivDropErr::Io)
                            .and_then(|exists| {
                                Permissions::NONE
                                    .unveil(README)
                                    .map_err(PrivDropErr::from)
                                    .and_then(|()| {
                                        promises
                                            .remove_promises_then_pledge([
                                                Promise::Rpath,
                                                Promise::Unveil,
                                            ])
                                            .map_err(PrivDropErr::Io)
                                            .map(|()| {
                                                assert!(exists);
                                                assert!(
                                                    TcpListener::bind(SocketAddrV6::new(
                                                        Ipv6Addr::LOCALHOST,
                                                        80,
                                                        0,
                                                        0
                                                    ))
                                                    .is_err()
                                                );
                                            })
                                    })
                            })
                    })
            })
        } else {
            Ok(())
        }
    }
}
