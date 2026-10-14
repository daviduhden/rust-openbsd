//! OpenBSD routing domains (routing tables).
//!
//! A routing domain, also called a routing table or *rtable*, isolates the
//! routing state of a process: each domain has its own routing table, and
//! domains are referenced by a numeric ID. These bind
//! [`getrtable(2)`](https://man.openbsd.org/getrtable.2) and
//! [`setrtable(2)`](https://man.openbsd.org/setrtable.2).
//!
//! These are process-wide settings: they apply to the calling process and to
//! sockets it creates. Unlike [`pledge(2)`](https://man.openbsd.org/pledge.2)
//! restrictions they are *not* monotonic; a sufficiently privileged process can
//! switch domains at will.

use crate::{
    error::Errno,
    ffi::{self, SUCCESS},
};

/// A routing domain ID, as used by
/// [`getrtable(2)`](https://man.openbsd.org/getrtable.2) and
/// [`setrtable(2)`](https://man.openbsd.org/setrtable.2).
///
/// The kernel validates the range on use: the constructor is public so callers
/// can reference known domain IDs (for example [`Rtable::DEFAULT`]), but an
/// invalid value fails with [`Errno::EINVAL`] at the native boundary rather
/// than being silently truncated or wrapped.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Rtable(pub i32);

impl Rtable {
    /// The default routing domain (`0`).
    pub const DEFAULT: Self = Self(0);

    /// Creates a routing domain ID from its numeric value.
    #[inline]
    #[must_use]
    pub const fn new(id: i32) -> Self {
        Self(id)
    }

    /// Returns the raw numeric routing domain ID.
    #[inline]
    #[must_use]
    pub const fn into_raw(self) -> i32 {
        self.0
    }
}

/// Returns the routing domain of the calling process, as
/// [`getrtable(2)`](https://man.openbsd.org/getrtable.2).
///
/// Allowed under the `stdio` pledge promise.
///
/// # Errors
///
/// Errors if `getrtable(2)` does.
#[inline]
pub fn get_rtable() -> Result<Rtable, Errno> {
    let table = ffi::getrtable();
    if table < 0 {
        Err(Errno::last())
    } else {
        Ok(Rtable(table))
    }
}

/// Sets the routing domain of the calling process, as
/// [`setrtable(2)`](https://man.openbsd.org/setrtable.2).
///
/// The documented privilege rule is asymmetric: an unprivileged process may
/// change the domain while it is [`Rtable::DEFAULT`], but once the domain is
/// non-zero only the superuser may change it (otherwise [`Errno::EPERM`]). The
/// target domain must exist: on a default system only domain `0` is
/// configured, and selecting another fails with [`Errno::EINVAL`].
///
/// This is a process-wide change but not a monotonic restriction: a
/// sufficiently privileged process can change the domain again later. Sockets
/// created after the change live in the new domain.
///
/// # Errors
///
/// Errors if `setrtable(2)` does.
///
/// # Pledge
///
/// The `id` pledge promise is required.
#[inline]
pub fn set_rtable(table: Rtable) -> Result<(), Errno> {
    if ffi::setrtable(table.0) == SUCCESS {
        Ok(())
    } else {
        Err(Errno::last())
    }
}
