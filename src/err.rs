use super::c;
use core::{
    error::Error,
    ffi::c_int,
    fmt::{self, Display, Formatter},
};
#[cfg(feature = "std")]
use std::io::Error as StdErr;
/// `newtype` around a [`c_int`] that is used to contain unknown error numbers in the [`Errno::Other`]
/// variant.
///
/// Note this cannot be constructed directly since the purpose is to only contain unknown error codes
/// ensuring that any non-[`Errno::Other`] is not equal to an `Errno::Other`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OtherErrno(c_int);
impl OtherErrno {
    /// Returns the contained error number.
    #[inline]
    #[must_use]
    pub const fn into_raw(self) -> c_int {
        self.0
    }
}
impl From<OtherErrno> for c_int {
    #[inline]
    fn from(value: OtherErrno) -> Self {
        value.0
    }
}
/// Error returned from calls to the system's libc.
///
/// Note this contains variants associated with all supported targets; thus for a given target,
/// it's likely a non-empty subset of the variants will never be returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Errno {
    /// Operation not permitted.
    EPERM,
    /// No such file or directory.
    ENOENT,
    /// No such process.
    ESRCH,
    /// Interrupted system call.
    EINTR,
    /// Input/output error.
    EIO,
    /// Device not configured.
    ENXIO,
    /// Argument list too long.
    E2BIG,
    /// Exec format error.
    ENOEXEC,
    /// Bad file descriptor.
    EBADF,
    /// No child processes.
    ECHILD,
    /// Resource deadlock avoided.
    EDEADLK,
    /// Cannot allocate memory.
    ENOMEM,
    /// Permission denied.
    EACCES,
    /// Bad address.
    EFAULT,
    /// Block device required.
    ENOTBLK,
    /// Device busy.
    EBUSY,
    /// File exists.
    EEXIST,
    /// Cross-device link.
    EXDEV,
    /// Operation not supported by device.
    ENODEV,
    /// Not a directory.
    ENOTDIR,
    /// Is a directory.
    EISDIR,
    /// Invalid argument.
    EINVAL,
    /// Too many open files in system.
    ENFILE,
    /// Too many open files.
    EMFILE,
    /// Inappropriate ioctl for device.
    ENOTTY,
    /// Text file busy.
    ETXTBSY,
    /// File too large.
    EFBIG,
    /// No space left on device.
    ENOSPC,
    /// Illegal seek.
    ESPIPE,
    /// Read-only file system.
    EROFS,
    /// Too many links.
    EMLINK,
    /// Broken pipe.
    EPIPE,
    /// Numerical argument out of domain.
    EDOM,
    /// Result too large.
    ERANGE,
    /// Operation would block.
    EWOULDBLOCK,
    /// Operation now in progress.
    EINPROGRESS,
    /// Operation already in progress.
    EALREADY,
    /// Socket operation on non-socket.
    ENOTSOCK,
    /// Destination address required.
    EDESTADDRREQ,
    /// Message too long.
    EMSGSIZE,
    /// Protocol wrong type for socket.
    EPROTOTYPE,
    /// Protocol not available.
    ENOPROTOOPT,
    /// Protocol not supported.
    EPROTONOSUPPORT,
    /// Socket type not supported.
    ESOCKTNOSUPPORT,
    /// Operation not supported.
    EOPNOTSUPP,
    /// Protocol family not supported.
    EPFNOSUPPORT,
    /// Address family not supported by protocol family.
    EAFNOSUPPORT,
    /// Address already in use.
    EADDRINUSE,
    /// Can't assign requested address.
    EADDRNOTAVAIL,
    /// Network is down.
    ENETDOWN,
    /// Network is unreachable.
    ENETUNREACH,
    /// Network dropped connection on reset.
    ENETRESET,
    /// Software caused connection abort.
    ECONNABORTED,
    /// Connection reset by peer.
    ECONNRESET,
    /// No buffer space available.
    ENOBUFS,
    /// Socket is already connected.
    EISCONN,
    /// Socket is not connected.
    ENOTCONN,
    /// Can't send after socket shutdown.
    ESHUTDOWN,
    /// Too many references: can't splice.
    ETOOMANYREFS,
    /// Operation timed out.
    ETIMEDOUT,
    /// Connection refused.
    ECONNREFUSED,
    /// Too many levels of symbolic links.
    ELOOP,
    /// File name too long.
    ENAMETOOLONG,
    /// Host is down.
    EHOSTDOWN,
    /// No route to host.
    EHOSTUNREACH,
    /// Directory not empty.
    ENOTEMPTY,
    /// Too many processes.
    EPROCLIM,
    /// Too many users.
    EUSERS,
    /// Disk quota exceeded.
    EDQUOT,
    /// Stale NFS file handle.
    ESTALE,
    /// Too many levels of remote in path.
    EREMOTE,
    /// RPC struct is bad.
    EBADRPC,
    /// RPC version wrong.
    ERPCMISMATCH,
    /// RPC program not available.
    EPROGUNAVAIL,
    /// Program version wrong.
    EPROGMISMATCH,
    /// Bad procedure for program.
    EPROCUNAVAIL,
    /// No locks available.
    ENOLCK,
    /// Function not implemented.
    ENOSYS,
    /// Inappropriate file type or format.
    EFTYPE,
    /// Authentication error.
    EAUTH,
    /// Need authenticator.
    ENEEDAUTH,
    /// IPsec processing failure.
    #[expect(clippy::doc_markdown, reason = "false positive")]
    EIPSEC,
    /// Attribute not found.
    ENOATTR,
    /// Illegal byte sequence.
    EILSEQ,
    /// No medium found.
    ENOMEDIUM,
    /// Wrong medium type.
    EMEDIUMTYPE,
    /// Value too large to be stored in data type.
    EOVERFLOW,
    /// Operation canceled.
    ECANCELED,
    /// Identifier removed.
    EIDRM,
    /// No message of desired type.
    ENOMSG,
    /// Not supported.
    ENOTSUP,
    /// Bad message.
    EBADMSG,
    /// State not recoverable.
    ENOTRECOVERABLE,
    /// Previous owner died.
    EOWNERDEAD,
    /// Protocol error.
    EPROTO,
    /// Programming error.
    EDOOFUS,
    /// Multihop attempted.
    EMULTIHOP,
    /// Link has been severed.
    ENOLINK,
    /// Capabilities insufficient.
    ENOTCAPABLE,
    /// Not permitted in capability mode.
    ECAPMODE,
    /// Integrity check failed.
    EINTEGRITY,
    /// Channel number out of range.
    ECHRNG,
    /// Level 2 not synchronized.
    EL2NSYNC,
    /// Level 3 halted.
    EL3HLT,
    /// Level 3 reset.
    EL3RST,
    /// Link number out of range.
    ELNRNG,
    /// Protocol driver not attached.
    EUNATCH,
    /// No CSI structure available.
    ENOCSI,
    /// Level 2 halted.
    EL2HLT,
    /// Invalid exchange.
    EBADE,
    /// Invalid request descriptor.
    EBADR,
    /// Exchange full.
    EXFULL,
    /// No anode.
    ENOANO,
    /// Invalid request code.
    EBADRQC,
    /// Invalid slot.
    EBADSLT,
    /// Bad font file format.
    EBFONT,
    /// Device not a stream.
    ENOSTR,
    /// No data available.
    ENODATA,
    /// Timer expired.
    ETIME,
    /// Out of streams resources.
    ENOSR,
    /// Machine is not on the network.
    ENONET,
    /// Package not installed.
    ENOPKG,
    /// Advertise error.
    EADV,
    /// Srmount error.
    ESRMNT,
    /// Communication error on send.
    ECOMM,
    /// RFS specific error.
    EDOTDOT,
    /// Name not unique on network.
    ENOTUNIQ,
    /// File descriptor in bad state.
    EBADFD,
    /// Remote address changed.
    EREMCHG,
    /// Can not access a needed shared library.
    ELIBACC,
    /// Accessing a corrupted shared library.
    ELIBBAD,
    /// .lib section in a.out corrupted.
    ELIBSCN,
    /// Attempting to link in too many shared libraries.
    ELIBMAX,
    /// Cannot exec a shared library directly.
    ELIBEXEC,
    /// Interrupted system call should be restarted.
    ERESTART,
    /// Streams pipe error.
    ESTRPIPE,
    /// Structure needs cleaning.
    EUCLEAN,
    /// Not a XENIX named type file.
    ENOTNAM,
    /// No XENIX semaphores available.
    ENAVAIL,
    /// Is a named type file.
    EISNAM,
    /// Remote I/O error.
    EREMOTEIO,
    /// Required key not available.
    ENOKEY,
    /// Key has expired.
    EKEYEXPIRED,
    /// Key has been revoked.
    EKEYREVOKED,
    /// Key was rejected by service.
    EKEYREJECTED,
    /// Operation not possible due to RF-kill.
    ERFKILL,
    /// Memory page has hardware error.
    EHWPOISON,
    /// Device power is off.
    EPWROFF,
    /// Device error, e.g. paper out.
    EDEVERR,
    /// Bad executable.
    EBADEXEC,
    /// Bad CPU type in executable.
    EBADARCH,
    /// Shared library version mismatch.
    ESHLIBVERS,
    /// Malformed Macho file.
    EBADMACHO,
    /// No such policy registered.
    ENOPOLICY,
    /// Interface output queue is full.
    EQFULL,
    /// All other error codes.
    ///
    /// Note this is guaranteed to contain an error code that is not the same as any of the above
    /// variants.
    Other(OtherErrno),
}
impl Errno {
    /// Returns a `Self` equivalent to `code`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Errno;
    /// assert_eq!(Errno::from_raw(1), Errno::EPERM);
    /// ```
    #[expect(clippy::too_many_lines, reason = "large match expression")]
    #[inline]
    #[must_use]
    pub const fn from_raw(code: c_int) -> Self {
        #[cfg(target_os = "dragonfly")]
        match code {
            1 => Self::EPERM,
            2 => Self::ENOENT,
            3 => Self::ESRCH,
            4 => Self::EINTR,
            5 => Self::EIO,
            6 => Self::ENXIO,
            7 => Self::E2BIG,
            8 => Self::ENOEXEC,
            9 => Self::EBADF,
            10 => Self::ECHILD,
            11 => Self::EDEADLK,
            12 => Self::ENOMEM,
            13 => Self::EACCES,
            14 => Self::EFAULT,
            15 => Self::ENOTBLK,
            16 => Self::EBUSY,
            17 => Self::EEXIST,
            18 => Self::EXDEV,
            19 => Self::ENODEV,
            20 => Self::ENOTDIR,
            21 => Self::EISDIR,
            22 => Self::EINVAL,
            23 => Self::ENFILE,
            24 => Self::EMFILE,
            25 => Self::ENOTTY,
            26 => Self::ETXTBSY,
            27 => Self::EFBIG,
            28 => Self::ENOSPC,
            29 => Self::ESPIPE,
            30 => Self::EROFS,
            31 => Self::EMLINK,
            32 => Self::EPIPE,
            33 => Self::EDOM,
            34 => Self::ERANGE,
            35 => Self::EWOULDBLOCK,
            36 => Self::EINPROGRESS,
            37 => Self::EALREADY,
            38 => Self::ENOTSOCK,
            39 => Self::EDESTADDRREQ,
            40 => Self::EMSGSIZE,
            41 => Self::EPROTOTYPE,
            42 => Self::ENOPROTOOPT,
            43 => Self::EPROTONOSUPPORT,
            44 => Self::ESOCKTNOSUPPORT,
            45 => Self::EOPNOTSUPP,
            46 => Self::EPFNOSUPPORT,
            47 => Self::EAFNOSUPPORT,
            48 => Self::EADDRINUSE,
            49 => Self::EADDRNOTAVAIL,
            50 => Self::ENETDOWN,
            51 => Self::ENETUNREACH,
            52 => Self::ENETRESET,
            53 => Self::ECONNABORTED,
            54 => Self::ECONNRESET,
            55 => Self::ENOBUFS,
            56 => Self::EISCONN,
            57 => Self::ENOTCONN,
            58 => Self::ESHUTDOWN,
            59 => Self::ETOOMANYREFS,
            60 => Self::ETIMEDOUT,
            61 => Self::ECONNREFUSED,
            62 => Self::ELOOP,
            63 => Self::ENAMETOOLONG,
            64 => Self::EHOSTDOWN,
            65 => Self::EHOSTUNREACH,
            66 => Self::ENOTEMPTY,
            67 => Self::EPROCLIM,
            68 => Self::EUSERS,
            69 => Self::EDQUOT,
            70 => Self::ESTALE,
            71 => Self::EREMOTE,
            72 => Self::EBADRPC,
            73 => Self::ERPCMISMATCH,
            74 => Self::EPROGUNAVAIL,
            75 => Self::EPROGMISMATCH,
            76 => Self::EPROCUNAVAIL,
            77 => Self::ENOLCK,
            78 => Self::ENOSYS,
            79 => Self::EFTYPE,
            80 => Self::EAUTH,
            81 => Self::ENEEDAUTH,
            82 => Self::EIDRM,
            83 => Self::ENOMSG,
            84 => Self::EOVERFLOW,
            85 => Self::ECANCELED,
            86 => Self::EILSEQ,
            87 => Self::ENOATTR,
            88 => Self::EDOOFUS,
            89 => Self::EBADMSG,
            90 => Self::EMULTIHOP,
            91 => Self::ENOLINK,
            92 => Self::EPROTO,
            93 => Self::ENOMEDIUM,
            94 => Self::ENOTRECOVERABLE,
            95 => Self::EOWNERDEAD,
            _ => Self::Other(OtherErrno(code)),
        }
        #[cfg(target_os = "freebsd")]
        match code {
            1 => Self::EPERM,
            2 => Self::ENOENT,
            3 => Self::ESRCH,
            4 => Self::EINTR,
            5 => Self::EIO,
            6 => Self::ENXIO,
            7 => Self::E2BIG,
            8 => Self::ENOEXEC,
            9 => Self::EBADF,
            10 => Self::ECHILD,
            11 => Self::EDEADLK,
            12 => Self::ENOMEM,
            13 => Self::EACCES,
            14 => Self::EFAULT,
            15 => Self::ENOTBLK,
            16 => Self::EBUSY,
            17 => Self::EEXIST,
            18 => Self::EXDEV,
            19 => Self::ENODEV,
            20 => Self::ENOTDIR,
            21 => Self::EISDIR,
            22 => Self::EINVAL,
            23 => Self::ENFILE,
            24 => Self::EMFILE,
            25 => Self::ENOTTY,
            26 => Self::ETXTBSY,
            27 => Self::EFBIG,
            28 => Self::ENOSPC,
            29 => Self::ESPIPE,
            30 => Self::EROFS,
            31 => Self::EMLINK,
            32 => Self::EPIPE,
            33 => Self::EDOM,
            34 => Self::ERANGE,
            35 => Self::EWOULDBLOCK,
            36 => Self::EINPROGRESS,
            37 => Self::EALREADY,
            38 => Self::ENOTSOCK,
            39 => Self::EDESTADDRREQ,
            40 => Self::EMSGSIZE,
            41 => Self::EPROTOTYPE,
            42 => Self::ENOPROTOOPT,
            43 => Self::EPROTONOSUPPORT,
            44 => Self::ESOCKTNOSUPPORT,
            45 => Self::EOPNOTSUPP,
            46 => Self::EPFNOSUPPORT,
            47 => Self::EAFNOSUPPORT,
            48 => Self::EADDRINUSE,
            49 => Self::EADDRNOTAVAIL,
            50 => Self::ENETDOWN,
            51 => Self::ENETUNREACH,
            52 => Self::ENETRESET,
            53 => Self::ECONNABORTED,
            54 => Self::ECONNRESET,
            55 => Self::ENOBUFS,
            56 => Self::EISCONN,
            57 => Self::ENOTCONN,
            58 => Self::ESHUTDOWN,
            59 => Self::ETOOMANYREFS,
            60 => Self::ETIMEDOUT,
            61 => Self::ECONNREFUSED,
            62 => Self::ELOOP,
            63 => Self::ENAMETOOLONG,
            64 => Self::EHOSTDOWN,
            65 => Self::EHOSTUNREACH,
            66 => Self::ENOTEMPTY,
            67 => Self::EPROCLIM,
            68 => Self::EUSERS,
            69 => Self::EDQUOT,
            70 => Self::ESTALE,
            71 => Self::EREMOTE,
            72 => Self::EBADRPC,
            73 => Self::ERPCMISMATCH,
            74 => Self::EPROGUNAVAIL,
            75 => Self::EPROGMISMATCH,
            76 => Self::EPROCUNAVAIL,
            77 => Self::ENOLCK,
            78 => Self::ENOSYS,
            79 => Self::EFTYPE,
            80 => Self::EAUTH,
            81 => Self::ENEEDAUTH,
            82 => Self::EIDRM,
            83 => Self::ENOMSG,
            84 => Self::EOVERFLOW,
            85 => Self::ECANCELED,
            86 => Self::EILSEQ,
            87 => Self::ENOATTR,
            88 => Self::EDOOFUS,
            89 => Self::EBADMSG,
            90 => Self::EMULTIHOP,
            91 => Self::ENOLINK,
            92 => Self::EPROTO,
            93 => Self::ENOTCAPABLE,
            94 => Self::ECAPMODE,
            95 => Self::ENOTRECOVERABLE,
            96 => Self::EOWNERDEAD,
            97 => Self::EINTEGRITY,
            _ => Self::Other(OtherErrno(code)),
        }
        #[cfg(target_os = "macos")]
        match code {
            1 => Self::EPERM,
            2 => Self::ENOENT,
            3 => Self::ESRCH,
            4 => Self::EINTR,
            5 => Self::EIO,
            6 => Self::ENXIO,
            7 => Self::E2BIG,
            8 => Self::ENOEXEC,
            9 => Self::EBADF,
            10 => Self::ECHILD,
            11 => Self::EDEADLK,
            12 => Self::ENOMEM,
            13 => Self::EACCES,
            14 => Self::EFAULT,
            15 => Self::ENOTBLK,
            16 => Self::EBUSY,
            17 => Self::EEXIST,
            18 => Self::EXDEV,
            19 => Self::ENODEV,
            20 => Self::ENOTDIR,
            21 => Self::EISDIR,
            22 => Self::EINVAL,
            23 => Self::ENFILE,
            24 => Self::EMFILE,
            25 => Self::ENOTTY,
            26 => Self::ETXTBSY,
            27 => Self::EFBIG,
            28 => Self::ENOSPC,
            29 => Self::ESPIPE,
            30 => Self::EROFS,
            31 => Self::EMLINK,
            32 => Self::EPIPE,
            33 => Self::EDOM,
            34 => Self::ERANGE,
            35 => Self::EWOULDBLOCK,
            36 => Self::EINPROGRESS,
            37 => Self::EALREADY,
            38 => Self::ENOTSOCK,
            39 => Self::EDESTADDRREQ,
            40 => Self::EMSGSIZE,
            41 => Self::EPROTOTYPE,
            42 => Self::ENOPROTOOPT,
            43 => Self::EPROTONOSUPPORT,
            44 => Self::ESOCKTNOSUPPORT,
            45 => Self::ENOTSUP,
            46 => Self::EPFNOSUPPORT,
            47 => Self::EAFNOSUPPORT,
            48 => Self::EADDRINUSE,
            49 => Self::EADDRNOTAVAIL,
            50 => Self::ENETDOWN,
            51 => Self::ENETUNREACH,
            52 => Self::ENETRESET,
            53 => Self::ECONNABORTED,
            54 => Self::ECONNRESET,
            55 => Self::ENOBUFS,
            56 => Self::EISCONN,
            57 => Self::ENOTCONN,
            58 => Self::ESHUTDOWN,
            59 => Self::ETOOMANYREFS,
            60 => Self::ETIMEDOUT,
            61 => Self::ECONNREFUSED,
            62 => Self::ELOOP,
            63 => Self::ENAMETOOLONG,
            64 => Self::EHOSTDOWN,
            65 => Self::EHOSTUNREACH,
            66 => Self::ENOTEMPTY,
            67 => Self::EPROCLIM,
            68 => Self::EUSERS,
            69 => Self::EDQUOT,
            70 => Self::ESTALE,
            71 => Self::EREMOTE,
            72 => Self::EBADRPC,
            73 => Self::ERPCMISMATCH,
            74 => Self::EPROGUNAVAIL,
            75 => Self::EPROGMISMATCH,
            76 => Self::EPROCUNAVAIL,
            77 => Self::ENOLCK,
            78 => Self::ENOSYS,
            79 => Self::EFTYPE,
            80 => Self::EAUTH,
            81 => Self::ENEEDAUTH,
            82 => Self::EPWROFF,
            83 => Self::EDEVERR,
            84 => Self::EOVERFLOW,
            85 => Self::EBADEXEC,
            86 => Self::EBADARCH,
            87 => Self::ESHLIBVERS,
            88 => Self::EBADMACHO,
            89 => Self::ECANCELED,
            90 => Self::EIDRM,
            91 => Self::ENOMSG,
            92 => Self::EILSEQ,
            93 => Self::ENOATTR,
            94 => Self::EBADMSG,
            95 => Self::EMULTIHOP,
            96 => Self::ENODATA,
            97 => Self::ENOLINK,
            98 => Self::ENOSR,
            99 => Self::ENOSTR,
            100 => Self::EPROTO,
            101 => Self::ETIME,
            102 => Self::EOPNOTSUPP,
            103 => Self::ENOPOLICY,
            104 => Self::ENOTRECOVERABLE,
            105 => Self::EOWNERDEAD,
            106 => Self::EQFULL,
            _ => Self::Other(OtherErrno(code)),
        }
        #[cfg(target_os = "netbsd")]
        match code {
            1 => Self::EPERM,
            2 => Self::ENOENT,
            3 => Self::ESRCH,
            4 => Self::EINTR,
            5 => Self::EIO,
            6 => Self::ENXIO,
            7 => Self::E2BIG,
            8 => Self::ENOEXEC,
            9 => Self::EBADF,
            10 => Self::ECHILD,
            11 => Self::EDEADLK,
            12 => Self::ENOMEM,
            13 => Self::EACCES,
            14 => Self::EFAULT,
            15 => Self::ENOTBLK,
            16 => Self::EBUSY,
            17 => Self::EEXIST,
            18 => Self::EXDEV,
            19 => Self::ENODEV,
            20 => Self::ENOTDIR,
            21 => Self::EISDIR,
            22 => Self::EINVAL,
            23 => Self::ENFILE,
            24 => Self::EMFILE,
            25 => Self::ENOTTY,
            26 => Self::ETXTBSY,
            27 => Self::EFBIG,
            28 => Self::ENOSPC,
            29 => Self::ESPIPE,
            30 => Self::EROFS,
            31 => Self::EMLINK,
            32 => Self::EPIPE,
            33 => Self::EDOM,
            34 => Self::ERANGE,
            35 => Self::EWOULDBLOCK,
            36 => Self::EINPROGRESS,
            37 => Self::EALREADY,
            38 => Self::ENOTSOCK,
            39 => Self::EDESTADDRREQ,
            40 => Self::EMSGSIZE,
            41 => Self::EPROTOTYPE,
            42 => Self::ENOPROTOOPT,
            43 => Self::EPROTONOSUPPORT,
            44 => Self::ESOCKTNOSUPPORT,
            45 => Self::EOPNOTSUPP,
            46 => Self::EPFNOSUPPORT,
            47 => Self::EAFNOSUPPORT,
            48 => Self::EADDRINUSE,
            49 => Self::EADDRNOTAVAIL,
            50 => Self::ENETDOWN,
            51 => Self::ENETUNREACH,
            52 => Self::ENETRESET,
            53 => Self::ECONNABORTED,
            54 => Self::ECONNRESET,
            55 => Self::ENOBUFS,
            56 => Self::EISCONN,
            57 => Self::ENOTCONN,
            58 => Self::ESHUTDOWN,
            59 => Self::ETOOMANYREFS,
            60 => Self::ETIMEDOUT,
            61 => Self::ECONNREFUSED,
            62 => Self::ELOOP,
            63 => Self::ENAMETOOLONG,
            64 => Self::EHOSTDOWN,
            65 => Self::EHOSTUNREACH,
            66 => Self::ENOTEMPTY,
            67 => Self::EPROCLIM,
            68 => Self::EUSERS,
            69 => Self::EDQUOT,
            70 => Self::ESTALE,
            71 => Self::EREMOTE,
            72 => Self::EBADRPC,
            73 => Self::ERPCMISMATCH,
            74 => Self::EPROGUNAVAIL,
            75 => Self::EPROGMISMATCH,
            76 => Self::EPROCUNAVAIL,
            77 => Self::ENOLCK,
            78 => Self::ENOSYS,
            79 => Self::EFTYPE,
            80 => Self::EAUTH,
            81 => Self::ENEEDAUTH,
            82 => Self::EIDRM,
            83 => Self::ENOMSG,
            84 => Self::EOVERFLOW,
            85 => Self::EILSEQ,
            86 => Self::ENOTSUP,
            87 => Self::ECANCELED,
            88 => Self::EBADMSG,
            89 => Self::ENODATA,
            90 => Self::ENOSR,
            91 => Self::ENOSTR,
            92 => Self::ETIME,
            93 => Self::ENOATTR,
            94 => Self::EMULTIHOP,
            95 => Self::ENOLINK,
            96 => Self::EPROTO,
            97 => Self::EOWNERDEAD,
            98 => Self::ENOTRECOVERABLE,
            _ => Self::Other(OtherErrno(code)),
        }
        #[cfg(target_os = "openbsd")]
        match code {
            1 => Self::EPERM,
            2 => Self::ENOENT,
            3 => Self::ESRCH,
            4 => Self::EINTR,
            5 => Self::EIO,
            6 => Self::ENXIO,
            7 => Self::E2BIG,
            8 => Self::ENOEXEC,
            9 => Self::EBADF,
            10 => Self::ECHILD,
            11 => Self::EDEADLK,
            12 => Self::ENOMEM,
            13 => Self::EACCES,
            14 => Self::EFAULT,
            15 => Self::ENOTBLK,
            16 => Self::EBUSY,
            17 => Self::EEXIST,
            18 => Self::EXDEV,
            19 => Self::ENODEV,
            20 => Self::ENOTDIR,
            21 => Self::EISDIR,
            22 => Self::EINVAL,
            23 => Self::ENFILE,
            24 => Self::EMFILE,
            25 => Self::ENOTTY,
            26 => Self::ETXTBSY,
            27 => Self::EFBIG,
            28 => Self::ENOSPC,
            29 => Self::ESPIPE,
            30 => Self::EROFS,
            31 => Self::EMLINK,
            32 => Self::EPIPE,
            33 => Self::EDOM,
            34 => Self::ERANGE,
            35 => Self::EWOULDBLOCK,
            36 => Self::EINPROGRESS,
            37 => Self::EALREADY,
            38 => Self::ENOTSOCK,
            39 => Self::EDESTADDRREQ,
            40 => Self::EMSGSIZE,
            41 => Self::EPROTOTYPE,
            42 => Self::ENOPROTOOPT,
            43 => Self::EPROTONOSUPPORT,
            44 => Self::ESOCKTNOSUPPORT,
            45 => Self::EOPNOTSUPP,
            46 => Self::EPFNOSUPPORT,
            47 => Self::EAFNOSUPPORT,
            48 => Self::EADDRINUSE,
            49 => Self::EADDRNOTAVAIL,
            50 => Self::ENETDOWN,
            51 => Self::ENETUNREACH,
            52 => Self::ENETRESET,
            53 => Self::ECONNABORTED,
            54 => Self::ECONNRESET,
            55 => Self::ENOBUFS,
            56 => Self::EISCONN,
            57 => Self::ENOTCONN,
            58 => Self::ESHUTDOWN,
            59 => Self::ETOOMANYREFS,
            60 => Self::ETIMEDOUT,
            61 => Self::ECONNREFUSED,
            62 => Self::ELOOP,
            63 => Self::ENAMETOOLONG,
            64 => Self::EHOSTDOWN,
            65 => Self::EHOSTUNREACH,
            66 => Self::ENOTEMPTY,
            67 => Self::EPROCLIM,
            68 => Self::EUSERS,
            69 => Self::EDQUOT,
            70 => Self::ESTALE,
            71 => Self::EREMOTE,
            72 => Self::EBADRPC,
            73 => Self::ERPCMISMATCH,
            74 => Self::EPROGUNAVAIL,
            75 => Self::EPROGMISMATCH,
            76 => Self::EPROCUNAVAIL,
            77 => Self::ENOLCK,
            78 => Self::ENOSYS,
            79 => Self::EFTYPE,
            80 => Self::EAUTH,
            81 => Self::ENEEDAUTH,
            82 => Self::EIPSEC,
            83 => Self::ENOATTR,
            84 => Self::EILSEQ,
            85 => Self::ENOMEDIUM,
            86 => Self::EMEDIUMTYPE,
            87 => Self::EOVERFLOW,
            88 => Self::ECANCELED,
            89 => Self::EIDRM,
            90 => Self::ENOMSG,
            91 => Self::ENOTSUP,
            92 => Self::EBADMSG,
            93 => Self::ENOTRECOVERABLE,
            94 => Self::EOWNERDEAD,
            95 => Self::EPROTO,
            _ => Self::Other(OtherErrno(code)),
        }
        #[cfg(target_os = "linux")]
        match code {
            1 => Self::EPERM,
            2 => Self::ENOENT,
            3 => Self::ESRCH,
            4 => Self::EINTR,
            5 => Self::EIO,
            6 => Self::ENXIO,
            7 => Self::E2BIG,
            8 => Self::ENOEXEC,
            9 => Self::EBADF,
            10 => Self::ECHILD,
            11 => Self::EWOULDBLOCK,
            12 => Self::ENOMEM,
            13 => Self::EACCES,
            14 => Self::EFAULT,
            15 => Self::ENOTBLK,
            16 => Self::EBUSY,
            17 => Self::EEXIST,
            18 => Self::EXDEV,
            19 => Self::ENODEV,
            20 => Self::ENOTDIR,
            21 => Self::EISDIR,
            22 => Self::EINVAL,
            23 => Self::ENFILE,
            24 => Self::EMFILE,
            25 => Self::ENOTTY,
            26 => Self::ETXTBSY,
            27 => Self::EFBIG,
            28 => Self::ENOSPC,
            29 => Self::ESPIPE,
            30 => Self::EROFS,
            31 => Self::EMLINK,
            32 => Self::EPIPE,
            33 => Self::EDOM,
            34 => Self::ERANGE,
            35 => Self::EDEADLK,
            36 => Self::ENAMETOOLONG,
            37 => Self::ENOLCK,
            38 => Self::ENOSYS,
            39 => Self::ENOTEMPTY,
            40 => Self::ELOOP,
            42 => Self::ENOMSG,
            43 => Self::EIDRM,
            44 => Self::ECHRNG,
            45 => Self::EL2NSYNC,
            46 => Self::EL3HLT,
            47 => Self::EL3RST,
            48 => Self::ELNRNG,
            49 => Self::EUNATCH,
            50 => Self::ENOCSI,
            51 => Self::EL2HLT,
            52 => Self::EBADE,
            53 => Self::EBADR,
            54 => Self::EXFULL,
            55 => Self::ENOANO,
            56 => Self::EBADRQC,
            57 => Self::EBADSLT,
            59 => Self::EBFONT,
            60 => Self::ENOSTR,
            61 => Self::ENODATA,
            62 => Self::ETIME,
            63 => Self::ENOSR,
            64 => Self::ENONET,
            65 => Self::ENOPKG,
            66 => Self::EREMOTE,
            67 => Self::ENOLINK,
            68 => Self::EADV,
            69 => Self::ESRMNT,
            70 => Self::ECOMM,
            71 => Self::EPROTO,
            72 => Self::EMULTIHOP,
            73 => Self::EDOTDOT,
            74 => Self::EBADMSG,
            75 => Self::EOVERFLOW,
            76 => Self::ENOTUNIQ,
            77 => Self::EBADFD,
            78 => Self::EREMCHG,
            79 => Self::ELIBACC,
            80 => Self::ELIBBAD,
            81 => Self::ELIBSCN,
            82 => Self::ELIBMAX,
            83 => Self::ELIBEXEC,
            84 => Self::EILSEQ,
            85 => Self::ERESTART,
            86 => Self::ESTRPIPE,
            87 => Self::EUSERS,
            88 => Self::ENOTSOCK,
            89 => Self::EDESTADDRREQ,
            90 => Self::EMSGSIZE,
            91 => Self::EPROTOTYPE,
            92 => Self::ENOPROTOOPT,
            93 => Self::EPROTONOSUPPORT,
            94 => Self::ESOCKTNOSUPPORT,
            95 => Self::EOPNOTSUPP,
            96 => Self::EPFNOSUPPORT,
            97 => Self::EAFNOSUPPORT,
            98 => Self::EADDRINUSE,
            99 => Self::EADDRNOTAVAIL,
            100 => Self::ENETDOWN,
            101 => Self::ENETUNREACH,
            102 => Self::ENETRESET,
            103 => Self::ECONNABORTED,
            104 => Self::ECONNRESET,
            105 => Self::ENOBUFS,
            106 => Self::EISCONN,
            107 => Self::ENOTCONN,
            108 => Self::ESHUTDOWN,
            109 => Self::ETOOMANYREFS,
            110 => Self::ETIMEDOUT,
            111 => Self::ECONNREFUSED,
            112 => Self::EHOSTDOWN,
            113 => Self::EHOSTUNREACH,
            114 => Self::EALREADY,
            115 => Self::EINPROGRESS,
            116 => Self::ESTALE,
            117 => Self::EUCLEAN,
            118 => Self::ENOTNAM,
            119 => Self::ENAVAIL,
            120 => Self::EISNAM,
            121 => Self::EREMOTEIO,
            122 => Self::EDQUOT,
            123 => Self::ENOMEDIUM,
            124 => Self::EMEDIUMTYPE,
            125 => Self::ECANCELED,
            126 => Self::ENOKEY,
            127 => Self::EKEYEXPIRED,
            128 => Self::EKEYREVOKED,
            129 => Self::EKEYREJECTED,
            130 => Self::EOWNERDEAD,
            131 => Self::ENOTRECOVERABLE,
            132 => Self::ERFKILL,
            133 => Self::EHWPOISON,
            _ => Self::Other(OtherErrno(code)),
        }
    }
    /// Returns the raw error code `self` is equivalent to.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Errno;
    /// assert_eq!(Errno::EPERM.into_raw(), 1);
    /// ```
    #[expect(clippy::too_many_lines, reason = "large match expression")]
    #[inline]
    #[must_use]
    pub const fn into_raw(self) -> c_int {
        /// Essentially `unreachable` but `const`.
        macro_rules! impossible {
            () => {
                panic!("there is a bug in priv_sep::Errno. Impossible variant for the target.")
            };
        }
        #[cfg(target_os = "dragonfly")]
        match self {
            Self::EPERM => 1,
            Self::ENOENT => 2,
            Self::ESRCH => 3,
            Self::EINTR => 4,
            Self::EIO => 5,
            Self::ENXIO => 6,
            Self::E2BIG => 7,
            Self::ENOEXEC => 8,
            Self::EBADF => 9,
            Self::ECHILD => 10,
            Self::EDEADLK => 11,
            Self::ENOMEM => 12,
            Self::EACCES => 13,
            Self::EFAULT => 14,
            Self::ENOTBLK => 15,
            Self::EBUSY => 16,
            Self::EEXIST => 17,
            Self::EXDEV => 18,
            Self::ENODEV => 19,
            Self::ENOTDIR => 20,
            Self::EISDIR => 21,
            Self::EINVAL => 22,
            Self::ENFILE => 23,
            Self::EMFILE => 24,
            Self::ENOTTY => 25,
            Self::ETXTBSY => 26,
            Self::EFBIG => 27,
            Self::ENOSPC => 28,
            Self::ESPIPE => 29,
            Self::EROFS => 30,
            Self::EMLINK => 31,
            Self::EPIPE => 32,
            Self::EDOM => 33,
            Self::ERANGE => 34,
            Self::EWOULDBLOCK => 35,
            Self::EINPROGRESS => 36,
            Self::EALREADY => 37,
            Self::ENOTSOCK => 38,
            Self::EDESTADDRREQ => 39,
            Self::EMSGSIZE => 40,
            Self::EPROTOTYPE => 41,
            Self::ENOPROTOOPT => 42,
            Self::EPROTONOSUPPORT => 43,
            Self::ESOCKTNOSUPPORT => 44,
            Self::EOPNOTSUPP => 45,
            Self::EPFNOSUPPORT => 46,
            Self::EAFNOSUPPORT => 47,
            Self::EADDRINUSE => 48,
            Self::EADDRNOTAVAIL => 49,
            Self::ENETDOWN => 50,
            Self::ENETUNREACH => 51,
            Self::ENETRESET => 52,
            Self::ECONNABORTED => 53,
            Self::ECONNRESET => 54,
            Self::ENOBUFS => 55,
            Self::EISCONN => 56,
            Self::ENOTCONN => 57,
            Self::ESHUTDOWN => 58,
            Self::ETOOMANYREFS => 59,
            Self::ETIMEDOUT => 60,
            Self::ECONNREFUSED => 61,
            Self::ELOOP => 62,
            Self::ENAMETOOLONG => 63,
            Self::EHOSTDOWN => 64,
            Self::EHOSTUNREACH => 65,
            Self::ENOTEMPTY => 66,
            Self::EPROCLIM => 67,
            Self::EUSERS => 68,
            Self::EDQUOT => 69,
            Self::ESTALE => 70,
            Self::EREMOTE => 71,
            Self::EBADRPC => 72,
            Self::ERPCMISMATCH => 73,
            Self::EPROGUNAVAIL => 74,
            Self::EPROGMISMATCH => 75,
            Self::EPROCUNAVAIL => 76,
            Self::ENOLCK => 77,
            Self::ENOSYS => 78,
            Self::EFTYPE => 79,
            Self::EAUTH => 80,
            Self::ENEEDAUTH => 81,
            Self::EIDRM => 82,
            Self::ENOMSG => 83,
            Self::EOVERFLOW => 84,
            Self::ECANCELED => 85,
            Self::EILSEQ => 86,
            Self::ENOATTR => 87,
            Self::EDOOFUS => 88,
            Self::EBADMSG => 89,
            Self::EMULTIHOP => 90,
            Self::ENOLINK => 91,
            Self::EPROTO => 92,
            Self::ENOMEDIUM => 93,
            Self::ENOTRECOVERABLE => 94,
            Self::EOWNERDEAD => 95,
            Self::Other(OtherErrno(code)) => code,
            Self::EIPSEC
            | Self::EMEDIUMTYPE
            | Self::ENOTSUP
            | Self::ENOTCAPABLE
            | Self::ECAPMODE
            | Self::EINTEGRITY
            | Self::ECHRNG
            | Self::EL2NSYNC
            | Self::EL3HLT
            | Self::EL3RST
            | Self::ELNRNG
            | Self::EUNATCH
            | Self::ENOCSI
            | Self::EL2HLT
            | Self::EBADE
            | Self::EBADR
            | Self::EXFULL
            | Self::ENOANO
            | Self::EBADRQC
            | Self::EBADSLT
            | Self::EBFONT
            | Self::ENOSTR
            | Self::ENODATA
            | Self::ETIME
            | Self::ENOSR
            | Self::ENONET
            | Self::ENOPKG
            | Self::EADV
            | Self::ESRMNT
            | Self::ECOMM
            | Self::EDOTDOT
            | Self::ENOTUNIQ
            | Self::EBADFD
            | Self::EREMCHG
            | Self::ELIBACC
            | Self::ELIBBAD
            | Self::ELIBSCN
            | Self::ELIBMAX
            | Self::ELIBEXEC
            | Self::ERESTART
            | Self::ESTRPIPE
            | Self::EUCLEAN
            | Self::ENOTNAM
            | Self::ENAVAIL
            | Self::EISNAM
            | Self::EREMOTEIO
            | Self::ENOKEY
            | Self::EKEYEXPIRED
            | Self::EKEYREVOKED
            | Self::EKEYREJECTED
            | Self::ERFKILL
            | Self::EHWPOISON
            | Self::EPWROFF
            | Self::EDEVERR
            | Self::EBADEXEC
            | Self::EBADARCH
            | Self::ESHLIBVERS
            | Self::EBADMACHO
            | Self::ENOPOLICY
            | Self::EQFULL => impossible!(),
        }
        #[cfg(target_os = "freebsd")]
        match self {
            Self::EPERM => 1,
            Self::ENOENT => 2,
            Self::ESRCH => 3,
            Self::EINTR => 4,
            Self::EIO => 5,
            Self::ENXIO => 6,
            Self::E2BIG => 7,
            Self::ENOEXEC => 8,
            Self::EBADF => 9,
            Self::ECHILD => 10,
            Self::EDEADLK => 11,
            Self::ENOMEM => 12,
            Self::EACCES => 13,
            Self::EFAULT => 14,
            Self::ENOTBLK => 15,
            Self::EBUSY => 16,
            Self::EEXIST => 17,
            Self::EXDEV => 18,
            Self::ENODEV => 19,
            Self::ENOTDIR => 20,
            Self::EISDIR => 21,
            Self::EINVAL => 22,
            Self::ENFILE => 23,
            Self::EMFILE => 24,
            Self::ENOTTY => 25,
            Self::ETXTBSY => 26,
            Self::EFBIG => 27,
            Self::ENOSPC => 28,
            Self::ESPIPE => 29,
            Self::EROFS => 30,
            Self::EMLINK => 31,
            Self::EPIPE => 32,
            Self::EDOM => 33,
            Self::ERANGE => 34,
            Self::EWOULDBLOCK => 35,
            Self::EINPROGRESS => 36,
            Self::EALREADY => 37,
            Self::ENOTSOCK => 38,
            Self::EDESTADDRREQ => 39,
            Self::EMSGSIZE => 40,
            Self::EPROTOTYPE => 41,
            Self::ENOPROTOOPT => 42,
            Self::EPROTONOSUPPORT => 43,
            Self::ESOCKTNOSUPPORT => 44,
            Self::EOPNOTSUPP => 45,
            Self::EPFNOSUPPORT => 46,
            Self::EAFNOSUPPORT => 47,
            Self::EADDRINUSE => 48,
            Self::EADDRNOTAVAIL => 49,
            Self::ENETDOWN => 50,
            Self::ENETUNREACH => 51,
            Self::ENETRESET => 52,
            Self::ECONNABORTED => 53,
            Self::ECONNRESET => 54,
            Self::ENOBUFS => 55,
            Self::EISCONN => 56,
            Self::ENOTCONN => 57,
            Self::ESHUTDOWN => 58,
            Self::ETOOMANYREFS => 59,
            Self::ETIMEDOUT => 60,
            Self::ECONNREFUSED => 61,
            Self::ELOOP => 62,
            Self::ENAMETOOLONG => 63,
            Self::EHOSTDOWN => 64,
            Self::EHOSTUNREACH => 65,
            Self::ENOTEMPTY => 66,
            Self::EPROCLIM => 67,
            Self::EUSERS => 68,
            Self::EDQUOT => 69,
            Self::ESTALE => 70,
            Self::EREMOTE => 71,
            Self::EBADRPC => 72,
            Self::ERPCMISMATCH => 73,
            Self::EPROGUNAVAIL => 74,
            Self::EPROGMISMATCH => 75,
            Self::EPROCUNAVAIL => 76,
            Self::ENOLCK => 77,
            Self::ENOSYS => 78,
            Self::EFTYPE => 79,
            Self::EAUTH => 80,
            Self::ENEEDAUTH => 81,
            Self::EIDRM => 82,
            Self::ENOMSG => 83,
            Self::EOVERFLOW => 84,
            Self::ECANCELED => 85,
            Self::EILSEQ => 86,
            Self::ENOATTR => 87,
            Self::EDOOFUS => 88,
            Self::EBADMSG => 89,
            Self::EMULTIHOP => 90,
            Self::ENOLINK => 91,
            Self::EPROTO => 92,
            Self::ENOTCAPABLE => 93,
            Self::ECAPMODE => 94,
            Self::ENOTRECOVERABLE => 95,
            Self::EOWNERDEAD => 96,
            Self::EINTEGRITY => 97,
            Self::Other(OtherErrno(code)) => code,
            Self::EIPSEC
            | Self::ENOMEDIUM
            | Self::EMEDIUMTYPE
            | Self::ENOTSUP
            | Self::ECHRNG
            | Self::EL2NSYNC
            | Self::EL3HLT
            | Self::EL3RST
            | Self::ELNRNG
            | Self::EUNATCH
            | Self::ENOCSI
            | Self::EL2HLT
            | Self::EBADE
            | Self::EBADR
            | Self::EXFULL
            | Self::ENOANO
            | Self::EBADRQC
            | Self::EBADSLT
            | Self::EBFONT
            | Self::ENOSTR
            | Self::ENODATA
            | Self::ETIME
            | Self::ENOSR
            | Self::ENONET
            | Self::ENOPKG
            | Self::EADV
            | Self::ESRMNT
            | Self::ECOMM
            | Self::EDOTDOT
            | Self::ENOTUNIQ
            | Self::EBADFD
            | Self::EREMCHG
            | Self::ELIBACC
            | Self::ELIBBAD
            | Self::ELIBSCN
            | Self::ELIBMAX
            | Self::ELIBEXEC
            | Self::ERESTART
            | Self::ESTRPIPE
            | Self::EUCLEAN
            | Self::ENOTNAM
            | Self::ENAVAIL
            | Self::EISNAM
            | Self::EREMOTEIO
            | Self::ENOKEY
            | Self::EKEYEXPIRED
            | Self::EKEYREVOKED
            | Self::EKEYREJECTED
            | Self::ERFKILL
            | Self::EHWPOISON
            | Self::EPWROFF
            | Self::EDEVERR
            | Self::EBADEXEC
            | Self::EBADARCH
            | Self::ESHLIBVERS
            | Self::EBADMACHO
            | Self::ENOPOLICY
            | Self::EQFULL => impossible!(),
        }
        #[cfg(target_os = "macos")]
        match self {
            Self::EPERM => 1,
            Self::ENOENT => 2,
            Self::ESRCH => 3,
            Self::EINTR => 4,
            Self::EIO => 5,
            Self::ENXIO => 6,
            Self::E2BIG => 7,
            Self::ENOEXEC => 8,
            Self::EBADF => 9,
            Self::ECHILD => 10,
            Self::EDEADLK => 11,
            Self::ENOMEM => 12,
            Self::EACCES => 13,
            Self::EFAULT => 14,
            Self::ENOTBLK => 15,
            Self::EBUSY => 16,
            Self::EEXIST => 17,
            Self::EXDEV => 18,
            Self::ENODEV => 19,
            Self::ENOTDIR => 20,
            Self::EISDIR => 21,
            Self::EINVAL => 22,
            Self::ENFILE => 23,
            Self::EMFILE => 24,
            Self::ENOTTY => 25,
            Self::ETXTBSY => 26,
            Self::EFBIG => 27,
            Self::ENOSPC => 28,
            Self::ESPIPE => 29,
            Self::EROFS => 30,
            Self::EMLINK => 31,
            Self::EPIPE => 32,
            Self::EDOM => 33,
            Self::ERANGE => 34,
            Self::EWOULDBLOCK => 35,
            Self::EINPROGRESS => 36,
            Self::EALREADY => 37,
            Self::ENOTSOCK => 38,
            Self::EDESTADDRREQ => 39,
            Self::EMSGSIZE => 40,
            Self::EPROTOTYPE => 41,
            Self::ENOPROTOOPT => 42,
            Self::EPROTONOSUPPORT => 43,
            Self::ESOCKTNOSUPPORT => 44,
            Self::ENOTSUP => 45,
            Self::EPFNOSUPPORT => 46,
            Self::EAFNOSUPPORT => 47,
            Self::EADDRINUSE => 48,
            Self::EADDRNOTAVAIL => 49,
            Self::ENETDOWN => 50,
            Self::ENETUNREACH => 51,
            Self::ENETRESET => 52,
            Self::ECONNABORTED => 53,
            Self::ECONNRESET => 54,
            Self::ENOBUFS => 55,
            Self::EISCONN => 56,
            Self::ENOTCONN => 57,
            Self::ESHUTDOWN => 58,
            Self::ETOOMANYREFS => 59,
            Self::ETIMEDOUT => 60,
            Self::ECONNREFUSED => 61,
            Self::ELOOP => 62,
            Self::ENAMETOOLONG => 63,
            Self::EHOSTDOWN => 64,
            Self::EHOSTUNREACH => 65,
            Self::ENOTEMPTY => 66,
            Self::EPROCLIM => 67,
            Self::EUSERS => 68,
            Self::EDQUOT => 69,
            Self::ESTALE => 70,
            Self::EREMOTE => 71,
            Self::EBADRPC => 72,
            Self::ERPCMISMATCH => 73,
            Self::EPROGUNAVAIL => 74,
            Self::EPROGMISMATCH => 75,
            Self::EPROCUNAVAIL => 76,
            Self::ENOLCK => 77,
            Self::ENOSYS => 78,
            Self::EFTYPE => 79,
            Self::EAUTH => 80,
            Self::ENEEDAUTH => 81,
            Self::EPWROFF => 82,
            Self::EDEVERR => 83,
            Self::EOVERFLOW => 84,
            Self::EBADEXEC => 85,
            Self::EBADARCH => 86,
            Self::ESHLIBVERS => 87,
            Self::EBADMACHO => 88,
            Self::ECANCELED => 89,
            Self::EIDRM => 90,
            Self::ENOMSG => 91,
            Self::EILSEQ => 92,
            Self::ENOATTR => 93,
            Self::EBADMSG => 94,
            Self::EMULTIHOP => 95,
            Self::ENODATA => 96,
            Self::ENOLINK => 97,
            Self::ENOSR => 98,
            Self::ENOSTR => 99,
            Self::EPROTO => 100,
            Self::ETIME => 101,
            Self::EOPNOTSUPP => 102,
            Self::ENOPOLICY => 103,
            Self::ENOTRECOVERABLE => 104,
            Self::EOWNERDEAD => 105,
            Self::EQFULL => 106,
            Self::Other(OtherErrno(code)) => code,
            Self::EIPSEC
            | Self::ENOMEDIUM
            | Self::EMEDIUMTYPE
            | Self::EDOOFUS
            | Self::ENOTCAPABLE
            | Self::ECAPMODE
            | Self::EINTEGRITY
            | Self::ECHRNG
            | Self::EL2NSYNC
            | Self::EL3HLT
            | Self::EL3RST
            | Self::ELNRNG
            | Self::EUNATCH
            | Self::ENOCSI
            | Self::EL2HLT
            | Self::EBADE
            | Self::EBADR
            | Self::EXFULL
            | Self::ENOANO
            | Self::EBADRQC
            | Self::EBADSLT
            | Self::EBFONT
            | Self::ENONET
            | Self::ENOPKG
            | Self::EADV
            | Self::ESRMNT
            | Self::ECOMM
            | Self::EDOTDOT
            | Self::ENOTUNIQ
            | Self::EBADFD
            | Self::EREMCHG
            | Self::ELIBACC
            | Self::ELIBBAD
            | Self::ELIBSCN
            | Self::ELIBMAX
            | Self::ELIBEXEC
            | Self::ERESTART
            | Self::ESTRPIPE
            | Self::EUCLEAN
            | Self::ENOTNAM
            | Self::ENAVAIL
            | Self::EISNAM
            | Self::EREMOTEIO
            | Self::ENOKEY
            | Self::EKEYEXPIRED
            | Self::EKEYREVOKED
            | Self::EKEYREJECTED
            | Self::ERFKILL
            | Self::EHWPOISON => impossible!(),
        }
        #[cfg(target_os = "netbsd")]
        match self {
            Self::EPERM => 1,
            Self::ENOENT => 2,
            Self::ESRCH => 3,
            Self::EINTR => 4,
            Self::EIO => 5,
            Self::ENXIO => 6,
            Self::E2BIG => 7,
            Self::ENOEXEC => 8,
            Self::EBADF => 9,
            Self::ECHILD => 10,
            Self::EDEADLK => 11,
            Self::ENOMEM => 12,
            Self::EACCES => 13,
            Self::EFAULT => 14,
            Self::ENOTBLK => 15,
            Self::EBUSY => 16,
            Self::EEXIST => 17,
            Self::EXDEV => 18,
            Self::ENODEV => 19,
            Self::ENOTDIR => 20,
            Self::EISDIR => 21,
            Self::EINVAL => 22,
            Self::ENFILE => 23,
            Self::EMFILE => 24,
            Self::ENOTTY => 25,
            Self::ETXTBSY => 26,
            Self::EFBIG => 27,
            Self::ENOSPC => 28,
            Self::ESPIPE => 29,
            Self::EROFS => 30,
            Self::EMLINK => 31,
            Self::EPIPE => 32,
            Self::EDOM => 33,
            Self::ERANGE => 34,
            Self::EWOULDBLOCK => 35,
            Self::EINPROGRESS => 36,
            Self::EALREADY => 37,
            Self::ENOTSOCK => 38,
            Self::EDESTADDRREQ => 39,
            Self::EMSGSIZE => 40,
            Self::EPROTOTYPE => 41,
            Self::ENOPROTOOPT => 42,
            Self::EPROTONOSUPPORT => 43,
            Self::ESOCKTNOSUPPORT => 44,
            Self::EOPNOTSUPP => 45,
            Self::EPFNOSUPPORT => 46,
            Self::EAFNOSUPPORT => 47,
            Self::EADDRINUSE => 48,
            Self::EADDRNOTAVAIL => 49,
            Self::ENETDOWN => 50,
            Self::ENETUNREACH => 51,
            Self::ENETRESET => 52,
            Self::ECONNABORTED => 53,
            Self::ECONNRESET => 54,
            Self::ENOBUFS => 55,
            Self::EISCONN => 56,
            Self::ENOTCONN => 57,
            Self::ESHUTDOWN => 58,
            Self::ETOOMANYREFS => 59,
            Self::ETIMEDOUT => 60,
            Self::ECONNREFUSED => 61,
            Self::ELOOP => 62,
            Self::ENAMETOOLONG => 63,
            Self::EHOSTDOWN => 64,
            Self::EHOSTUNREACH => 65,
            Self::ENOTEMPTY => 66,
            Self::EPROCLIM => 67,
            Self::EUSERS => 68,
            Self::EDQUOT => 69,
            Self::ESTALE => 70,
            Self::EREMOTE => 71,
            Self::EBADRPC => 72,
            Self::ERPCMISMATCH => 73,
            Self::EPROGUNAVAIL => 74,
            Self::EPROGMISMATCH => 75,
            Self::EPROCUNAVAIL => 76,
            Self::ENOLCK => 77,
            Self::ENOSYS => 78,
            Self::EFTYPE => 79,
            Self::EAUTH => 80,
            Self::ENEEDAUTH => 81,
            Self::EIDRM => 82,
            Self::ENOMSG => 83,
            Self::EOVERFLOW => 84,
            Self::EILSEQ => 85,
            Self::ENOTSUP => 86,
            Self::ECANCELED => 87,
            Self::EBADMSG => 88,
            Self::ENODATA => 89,
            Self::ENOSR => 90,
            Self::ENOSTR => 91,
            Self::ETIME => 92,
            Self::ENOATTR => 93,
            Self::EMULTIHOP => 94,
            Self::ENOLINK => 95,
            Self::EPROTO => 96,
            Self::EOWNERDEAD => 97,
            Self::ENOTRECOVERABLE => 98,
            Self::Other(OtherErrno(code)) => code,
            Self::EIPSEC
            | Self::ENOMEDIUM
            | Self::EMEDIUMTYPE
            | Self::EDOOFUS
            | Self::ENOTCAPABLE
            | Self::ECAPMODE
            | Self::EINTEGRITY
            | Self::ECHRNG
            | Self::EL2NSYNC
            | Self::EL3HLT
            | Self::EL3RST
            | Self::ELNRNG
            | Self::EUNATCH
            | Self::ENOCSI
            | Self::EL2HLT
            | Self::EBADE
            | Self::EBADR
            | Self::EXFULL
            | Self::ENOANO
            | Self::EBADRQC
            | Self::EBADSLT
            | Self::EBFONT
            | Self::ENONET
            | Self::ENOPKG
            | Self::EADV
            | Self::ESRMNT
            | Self::ECOMM
            | Self::EDOTDOT
            | Self::ENOTUNIQ
            | Self::EBADFD
            | Self::EREMCHG
            | Self::ELIBACC
            | Self::ELIBBAD
            | Self::ELIBSCN
            | Self::ELIBMAX
            | Self::ELIBEXEC
            | Self::ERESTART
            | Self::ESTRPIPE
            | Self::EUCLEAN
            | Self::ENOTNAM
            | Self::ENAVAIL
            | Self::EISNAM
            | Self::EREMOTEIO
            | Self::ENOKEY
            | Self::EKEYEXPIRED
            | Self::EKEYREVOKED
            | Self::EKEYREJECTED
            | Self::ERFKILL
            | Self::EHWPOISON
            | Self::EPWROFF
            | Self::EDEVERR
            | Self::EBADEXEC
            | Self::EBADARCH
            | Self::ESHLIBVERS
            | Self::EBADMACHO
            | Self::ENOPOLICY
            | Self::EQFULL => impossible!(),
        }
        #[cfg(target_os = "openbsd")]
        match self {
            Self::EPERM => 1,
            Self::ENOENT => 2,
            Self::ESRCH => 3,
            Self::EINTR => 4,
            Self::EIO => 5,
            Self::ENXIO => 6,
            Self::E2BIG => 7,
            Self::ENOEXEC => 8,
            Self::EBADF => 9,
            Self::ECHILD => 10,
            Self::EDEADLK => 11,
            Self::ENOMEM => 12,
            Self::EACCES => 13,
            Self::EFAULT => 14,
            Self::ENOTBLK => 15,
            Self::EBUSY => 16,
            Self::EEXIST => 17,
            Self::EXDEV => 18,
            Self::ENODEV => 19,
            Self::ENOTDIR => 20,
            Self::EISDIR => 21,
            Self::EINVAL => 22,
            Self::ENFILE => 23,
            Self::EMFILE => 24,
            Self::ENOTTY => 25,
            Self::ETXTBSY => 26,
            Self::EFBIG => 27,
            Self::ENOSPC => 28,
            Self::ESPIPE => 29,
            Self::EROFS => 30,
            Self::EMLINK => 31,
            Self::EPIPE => 32,
            Self::EDOM => 33,
            Self::ERANGE => 34,
            Self::EWOULDBLOCK => 35,
            Self::EINPROGRESS => 36,
            Self::EALREADY => 37,
            Self::ENOTSOCK => 38,
            Self::EDESTADDRREQ => 39,
            Self::EMSGSIZE => 40,
            Self::EPROTOTYPE => 41,
            Self::ENOPROTOOPT => 42,
            Self::EPROTONOSUPPORT => 43,
            Self::ESOCKTNOSUPPORT => 44,
            Self::EOPNOTSUPP => 45,
            Self::EPFNOSUPPORT => 46,
            Self::EAFNOSUPPORT => 47,
            Self::EADDRINUSE => 48,
            Self::EADDRNOTAVAIL => 49,
            Self::ENETDOWN => 50,
            Self::ENETUNREACH => 51,
            Self::ENETRESET => 52,
            Self::ECONNABORTED => 53,
            Self::ECONNRESET => 54,
            Self::ENOBUFS => 55,
            Self::EISCONN => 56,
            Self::ENOTCONN => 57,
            Self::ESHUTDOWN => 58,
            Self::ETOOMANYREFS => 59,
            Self::ETIMEDOUT => 60,
            Self::ECONNREFUSED => 61,
            Self::ELOOP => 62,
            Self::ENAMETOOLONG => 63,
            Self::EHOSTDOWN => 64,
            Self::EHOSTUNREACH => 65,
            Self::ENOTEMPTY => 66,
            Self::EPROCLIM => 67,
            Self::EUSERS => 68,
            Self::EDQUOT => 69,
            Self::ESTALE => 70,
            Self::EREMOTE => 71,
            Self::EBADRPC => 72,
            Self::ERPCMISMATCH => 73,
            Self::EPROGUNAVAIL => 74,
            Self::EPROGMISMATCH => 75,
            Self::EPROCUNAVAIL => 76,
            Self::ENOLCK => 77,
            Self::ENOSYS => 78,
            Self::EFTYPE => 79,
            Self::EAUTH => 80,
            Self::ENEEDAUTH => 81,
            Self::EIPSEC => 82,
            Self::ENOATTR => 83,
            Self::EILSEQ => 84,
            Self::ENOMEDIUM => 85,
            Self::EMEDIUMTYPE => 86,
            Self::EOVERFLOW => 87,
            Self::ECANCELED => 88,
            Self::EIDRM => 89,
            Self::ENOMSG => 90,
            Self::ENOTSUP => 91,
            Self::EBADMSG => 92,
            Self::ENOTRECOVERABLE => 93,
            Self::EOWNERDEAD => 94,
            Self::EPROTO => 95,
            Self::Other(OtherErrno(code)) => code,
            Self::EDOOFUS
            | Self::EMULTIHOP
            | Self::ENOLINK
            | Self::ENOTCAPABLE
            | Self::ECAPMODE
            | Self::EINTEGRITY
            | Self::ECHRNG
            | Self::EL2NSYNC
            | Self::EL3HLT
            | Self::EL3RST
            | Self::ELNRNG
            | Self::EUNATCH
            | Self::ENOCSI
            | Self::EL2HLT
            | Self::EBADE
            | Self::EBADR
            | Self::EXFULL
            | Self::ENOANO
            | Self::EBADRQC
            | Self::EBADSLT
            | Self::EBFONT
            | Self::ENOSTR
            | Self::ENODATA
            | Self::ETIME
            | Self::ENOSR
            | Self::ENONET
            | Self::ENOPKG
            | Self::EADV
            | Self::ESRMNT
            | Self::ECOMM
            | Self::EDOTDOT
            | Self::ENOTUNIQ
            | Self::EBADFD
            | Self::EREMCHG
            | Self::ELIBACC
            | Self::ELIBBAD
            | Self::ELIBSCN
            | Self::ELIBMAX
            | Self::ELIBEXEC
            | Self::ERESTART
            | Self::ESTRPIPE
            | Self::EUCLEAN
            | Self::ENOTNAM
            | Self::ENAVAIL
            | Self::EISNAM
            | Self::EREMOTEIO
            | Self::ENOKEY
            | Self::EKEYEXPIRED
            | Self::EKEYREVOKED
            | Self::EKEYREJECTED
            | Self::ERFKILL
            | Self::EHWPOISON
            | Self::EPWROFF
            | Self::EDEVERR
            | Self::EBADEXEC
            | Self::EBADARCH
            | Self::ESHLIBVERS
            | Self::EBADMACHO
            | Self::ENOPOLICY
            | Self::EQFULL => impossible!(),
        }
        #[cfg(target_os = "linux")]
        match self {
            Self::EPERM => 1,
            Self::ENOENT => 2,
            Self::ESRCH => 3,
            Self::EINTR => 4,
            Self::EIO => 5,
            Self::ENXIO => 6,
            Self::E2BIG => 7,
            Self::ENOEXEC => 8,
            Self::EBADF => 9,
            Self::ECHILD => 10,
            Self::EWOULDBLOCK => 11,
            Self::ENOMEM => 12,
            Self::EACCES => 13,
            Self::EFAULT => 14,
            Self::ENOTBLK => 15,
            Self::EBUSY => 16,
            Self::EEXIST => 17,
            Self::EXDEV => 18,
            Self::ENODEV => 19,
            Self::ENOTDIR => 20,
            Self::EISDIR => 21,
            Self::EINVAL => 22,
            Self::ENFILE => 23,
            Self::EMFILE => 24,
            Self::ENOTTY => 25,
            Self::ETXTBSY => 26,
            Self::EFBIG => 27,
            Self::ENOSPC => 28,
            Self::ESPIPE => 29,
            Self::EROFS => 30,
            Self::EMLINK => 31,
            Self::EPIPE => 32,
            Self::EDOM => 33,
            Self::ERANGE => 34,
            Self::EDEADLK => 35,
            Self::ENAMETOOLONG => 36,
            Self::ENOLCK => 37,
            Self::ENOSYS => 38,
            Self::ENOTEMPTY => 39,
            Self::ELOOP => 40,
            Self::ENOMSG => 42,
            Self::EIDRM => 43,
            Self::ECHRNG => 44,
            Self::EL2NSYNC => 45,
            Self::EL3HLT => 46,
            Self::EL3RST => 47,
            Self::ELNRNG => 48,
            Self::EUNATCH => 49,
            Self::ENOCSI => 50,
            Self::EL2HLT => 51,
            Self::EBADE => 52,
            Self::EBADR => 53,
            Self::EXFULL => 54,
            Self::ENOANO => 55,
            Self::EBADRQC => 56,
            Self::EBADSLT => 57,
            Self::EBFONT => 59,
            Self::ENOSTR => 60,
            Self::ENODATA => 61,
            Self::ETIME => 62,
            Self::ENOSR => 63,
            Self::ENONET => 64,
            Self::ENOPKG => 65,
            Self::EREMOTE => 66,
            Self::ENOLINK => 67,
            Self::EADV => 68,
            Self::ESRMNT => 69,
            Self::ECOMM => 70,
            Self::EPROTO => 71,
            Self::EMULTIHOP => 72,
            Self::EDOTDOT => 73,
            Self::EBADMSG => 74,
            Self::EOVERFLOW => 75,
            Self::ENOTUNIQ => 76,
            Self::EBADFD => 77,
            Self::EREMCHG => 78,
            Self::ELIBACC => 79,
            Self::ELIBBAD => 80,
            Self::ELIBSCN => 81,
            Self::ELIBMAX => 82,
            Self::ELIBEXEC => 83,
            Self::EILSEQ => 84,
            Self::ERESTART => 85,
            Self::ESTRPIPE => 86,
            Self::EUSERS => 87,
            Self::ENOTSOCK => 88,
            Self::EDESTADDRREQ => 89,
            Self::EMSGSIZE => 90,
            Self::EPROTOTYPE => 91,
            Self::ENOPROTOOPT => 92,
            Self::EPROTONOSUPPORT => 93,
            Self::ESOCKTNOSUPPORT => 94,
            Self::EOPNOTSUPP => 95,
            Self::EPFNOSUPPORT => 96,
            Self::EAFNOSUPPORT => 97,
            Self::EADDRINUSE => 98,
            Self::EADDRNOTAVAIL => 99,
            Self::ENETDOWN => 100,
            Self::ENETUNREACH => 101,
            Self::ENETRESET => 102,
            Self::ECONNABORTED => 103,
            Self::ECONNRESET => 104,
            Self::ENOBUFS => 105,
            Self::EISCONN => 106,
            Self::ENOTCONN => 107,
            Self::ESHUTDOWN => 108,
            Self::ETOOMANYREFS => 109,
            Self::ETIMEDOUT => 110,
            Self::ECONNREFUSED => 111,
            Self::EHOSTDOWN => 112,
            Self::EHOSTUNREACH => 113,
            Self::EALREADY => 114,
            Self::EINPROGRESS => 115,
            Self::ESTALE => 116,
            Self::EUCLEAN => 117,
            Self::ENOTNAM => 118,
            Self::ENAVAIL => 119,
            Self::EISNAM => 120,
            Self::EREMOTEIO => 121,
            Self::EDQUOT => 122,
            Self::ENOMEDIUM => 123,
            Self::EMEDIUMTYPE => 124,
            Self::ECANCELED => 125,
            Self::ENOKEY => 126,
            Self::EKEYEXPIRED => 127,
            Self::EKEYREVOKED => 128,
            Self::EKEYREJECTED => 129,
            Self::EOWNERDEAD => 130,
            Self::ENOTRECOVERABLE => 131,
            Self::ERFKILL => 132,
            Self::EHWPOISON => 133,
            Self::Other(OtherErrno(code)) => code,
            Self::EPROCLIM
            | Self::EBADRPC
            | Self::ERPCMISMATCH
            | Self::EPROGUNAVAIL
            | Self::EPROGMISMATCH
            | Self::EPROCUNAVAIL
            | Self::EFTYPE
            | Self::EAUTH
            | Self::ENEEDAUTH
            | Self::EIPSEC
            | Self::ENOATTR
            | Self::ENOTSUP
            | Self::EDOOFUS
            | Self::ENOTCAPABLE
            | Self::ECAPMODE
            | Self::EINTEGRITY
            | Self::EPWROFF
            | Self::EDEVERR
            | Self::EBADEXEC
            | Self::EBADARCH
            | Self::ESHLIBVERS
            | Self::EBADMACHO
            | Self::ENOPOLICY
            | Self::EQFULL => impossible!(),
        }
    }
    /// Returns the error pointer.
    #[expect(unsafe_code, reason = "safety comment justifies correctness")]
    fn get_raw_err_ptr() -> *mut c_int {
        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        // SAFETY:
        // Safe because errno is a thread-local variable.
        unsafe {
            c::__errno()
        }
        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        // SAFETY:
        // Safe because errno is a thread-local variable.
        unsafe {
            c::__error()
        }
        #[cfg(any(target_os = "dragonfly", target_os = "linux"))]
        // SAFETY:
        // Safe because errno is a thread-local variable.
        unsafe {
            c::__errno_location()
        }
    }
    /// Sets the platform error to `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Errno;
    /// Errno::ENOENT.set();
    /// ```
    #[expect(unsafe_code, reason = "safety comment justifies correctness")]
    #[inline]
    pub fn set(self) {
        let ptr = Self::get_raw_err_ptr();
        debug_assert!(
            !ptr.is_null() && ptr.is_aligned(),
            "libc errno returned a pointer that was either null or not aligned. Something is terribly wrong with your system"
        );
        let code = self.into_raw();
        // SAFETY:
        // Verified above that `ptr` is not null and aligned. Note while we only verify
        // this on non-release builds, the situation is so dire that one could argue we are
        // already in "undefined" territory.
        unsafe { *ptr = code };
    }
    /// Returns the current platform error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Errno;
    /// Errno::ENOENT.set();
    /// assert_eq!(Errno::last(), Errno::ENOENT);
    /// ```
    #[expect(unsafe_code, reason = "safety comment justifies correctness")]
    #[inline]
    #[must_use]
    pub fn last() -> Self {
        let ptr = Self::get_raw_err_ptr();
        debug_assert!(
            !ptr.is_null() && ptr.is_aligned(),
            "libc errno returned a pointer that was either null or not aligned. Something is terribly wrong with your system"
        );
        // SAFETY:
        // Verified above that `ptr` is not null and aligned. Note while we only verify
        // this on non-release builds, the situation is so dire that one could argue we are
        // already in "undefined" territory.
        Self::from_raw(unsafe { *ptr })
    }
    /// Clears any error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Errno;
    /// Errno::clear();
    /// assert!(matches!(Errno::last(), Errno::Other(other) if other.into_raw() == 0));
    /// ```
    #[inline]
    pub fn clear() {
        Self::Other(OtherErrno(0)).set();
    }
}
impl From<Errno> for c_int {
    #[inline]
    fn from(value: Errno) -> Self {
        value.into_raw()
    }
}
impl From<c_int> for Errno {
    #[inline]
    fn from(value: c_int) -> Self {
        Self::from_raw(value)
    }
}
impl Display for Errno {
    #[expect(clippy::too_many_lines, reason = "large match expression")]
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::EPERM => f.write_str("Operation not permitted"),
            Self::ENOENT => f.write_str("No such file or directory"),
            Self::ESRCH => f.write_str("No such process"),
            Self::EINTR => f.write_str("Interrupted system call"),
            Self::EIO => f.write_str("Input/output error"),
            Self::ENXIO => f.write_str("Device not configured"),
            Self::E2BIG => f.write_str("Argument list too long"),
            Self::ENOEXEC => f.write_str("Exec format error"),
            Self::EBADF => f.write_str("Bad file descriptor"),
            Self::ECHILD => f.write_str("No child processes"),
            Self::EDEADLK => f.write_str("Resource deadlock avoided"),
            Self::ENOMEM => f.write_str("Cannot allocate memory"),
            Self::EACCES => f.write_str("Permission denied"),
            Self::EFAULT => f.write_str("Bad address"),
            Self::ENOTBLK => f.write_str("Block device required"),
            Self::EBUSY => f.write_str("Device busy"),
            Self::EEXIST => f.write_str("File exists"),
            Self::EXDEV => f.write_str("Cross-device link"),
            Self::ENODEV => f.write_str("Operation not supported by device"),
            Self::ENOTDIR => f.write_str("Not a directory"),
            Self::EISDIR => f.write_str("Is a directory"),
            Self::EINVAL => f.write_str("Invalid argument"),
            Self::ENFILE => f.write_str("Too many open files in system"),
            Self::EMFILE => f.write_str("Too many open files"),
            Self::ENOTTY => f.write_str("Inappropriate ioctl for device"),
            Self::ETXTBSY => f.write_str("Text file busy"),
            Self::EFBIG => f.write_str("File too large"),
            Self::ENOSPC => f.write_str("No space left on device"),
            Self::ESPIPE => f.write_str("Illegal seek"),
            Self::EROFS => f.write_str("Read-only file system"),
            Self::EMLINK => f.write_str("Too many links"),
            Self::EPIPE => f.write_str("Broken pipe"),
            Self::EDOM => f.write_str("Numerical argument out of domain"),
            Self::ERANGE => f.write_str("Result too large"),
            Self::EWOULDBLOCK => f.write_str("Operation would block"),
            Self::EINPROGRESS => f.write_str("Operation now in progress"),
            Self::EALREADY => f.write_str("Operation already in progress"),
            Self::ENOTSOCK => f.write_str("Socket operation on non-socket"),
            Self::EDESTADDRREQ => f.write_str("Destination address required"),
            Self::EMSGSIZE => f.write_str("Message too long"),
            Self::EPROTOTYPE => f.write_str("Protocol wrong type for socket"),
            Self::ENOPROTOOPT => f.write_str("Protocol not available"),
            Self::EPROTONOSUPPORT => f.write_str("Protocol not supported"),
            Self::ESOCKTNOSUPPORT => f.write_str("Socket type not supported"),
            Self::EOPNOTSUPP => f.write_str("Operation not supported"),
            Self::EPFNOSUPPORT => f.write_str("Protocol family not supported"),
            Self::EAFNOSUPPORT => f.write_str("Address family not supported by protocol family"),
            Self::EADDRINUSE => f.write_str("Address already in use"),
            Self::EADDRNOTAVAIL => f.write_str("Can't assign requested address"),
            Self::ENETDOWN => f.write_str("Network is down"),
            Self::ENETUNREACH => f.write_str("Network is unreachable"),
            Self::ENETRESET => f.write_str("Network dropped connection on reset"),
            Self::ECONNABORTED => f.write_str("Software caused connection abort"),
            Self::ECONNRESET => f.write_str("Connection reset by peer"),
            Self::ENOBUFS => f.write_str("No buffer space available"),
            Self::EISCONN => f.write_str("Socket is already connected"),
            Self::ENOTCONN => f.write_str("Socket is not connected"),
            Self::ESHUTDOWN => f.write_str("Can't send after socket shutdown"),
            Self::ETOOMANYREFS => f.write_str("Too many references: can't splice"),
            Self::ETIMEDOUT => f.write_str("Operation timed out"),
            Self::ECONNREFUSED => f.write_str("Connection refused"),
            Self::ELOOP => f.write_str("Too many levels of symbolic links"),
            Self::ENAMETOOLONG => f.write_str("File name too long"),
            Self::EHOSTDOWN => f.write_str("Host is down"),
            Self::EHOSTUNREACH => f.write_str("No route to host"),
            Self::ENOTEMPTY => f.write_str("Directory not empty"),
            Self::EPROCLIM => f.write_str("Too many processes"),
            Self::EUSERS => f.write_str("Too many users"),
            Self::EDQUOT => f.write_str("Disk quota exceeded"),
            Self::ESTALE => f.write_str("Stale NFS file handle"),
            Self::EREMOTE => f.write_str("Too many levels of remote in path"),
            Self::EBADRPC => f.write_str("RPC struct is bad"),
            Self::ERPCMISMATCH => f.write_str("RPC version wrong"),
            Self::EPROGUNAVAIL => f.write_str("RPC program not available"),
            Self::EPROGMISMATCH => f.write_str("Program version wrong"),
            Self::EPROCUNAVAIL => f.write_str("Bad procedure for program"),
            Self::ENOLCK => f.write_str("No locks available"),
            Self::ENOSYS => f.write_str("Function not implemented"),
            Self::EFTYPE => f.write_str("Inappropriate file type or format"),
            Self::EAUTH => f.write_str("Authentication error"),
            Self::ENEEDAUTH => f.write_str("Need authenticator"),
            Self::EIPSEC => f.write_str("IPsec processing failure"),
            Self::ENOATTR => f.write_str("Attribute not found"),
            Self::EILSEQ => f.write_str("Illegal byte sequence"),
            Self::ENOMEDIUM => f.write_str("No medium found"),
            Self::EMEDIUMTYPE => f.write_str("Wrong medium type"),
            Self::EOVERFLOW => f.write_str("Value too large to be stored in data type"),
            Self::ECANCELED => f.write_str("Operation canceled"),
            Self::EIDRM => f.write_str("Identifier removed"),
            Self::ENOMSG => f.write_str("No message of desired type"),
            Self::ENOTSUP => f.write_str("Not supported"),
            Self::EBADMSG => f.write_str("Bad message"),
            Self::ENOTRECOVERABLE => f.write_str("State not recoverable"),
            Self::EOWNERDEAD => f.write_str("Previous owner died"),
            Self::EPROTO => f.write_str("Protocol error"),
            Self::EDOOFUS => f.write_str("Programming error"),
            Self::EMULTIHOP => f.write_str("Multihop attempted"),
            Self::ENOLINK => f.write_str("Link has been severed"),
            Self::ENOTCAPABLE => f.write_str("Capabilities insufficient"),
            Self::ECAPMODE => f.write_str("Not permitted in capability mode"),
            Self::EINTEGRITY => f.write_str("Integrity check failed"),
            Self::ECHRNG => f.write_str("Channel number out of range"),
            Self::EL2NSYNC => f.write_str("Level 2 not synchronized"),
            Self::EL3HLT => f.write_str("Level 3 halted"),
            Self::EL3RST => f.write_str("Level 3 reset"),
            Self::ELNRNG => f.write_str("Link number out of range"),
            Self::EUNATCH => f.write_str("Protocol driver not attached"),
            Self::ENOCSI => f.write_str("No CSI structure available"),
            Self::EL2HLT => f.write_str("Level 2 halted"),
            Self::EBADE => f.write_str("Invalid exchange"),
            Self::EBADR => f.write_str("Invalid request descriptor"),
            Self::EXFULL => f.write_str("Exchange full"),
            Self::ENOANO => f.write_str("No anode"),
            Self::EBADRQC => f.write_str("Invalid request code"),
            Self::EBADSLT => f.write_str("Invalid slot"),
            Self::EBFONT => f.write_str("Bad font file format"),
            Self::ENOSTR => f.write_str("Device not a stream"),
            Self::ENODATA => f.write_str("No data available"),
            Self::ETIME => f.write_str("Timer expired"),
            Self::ENOSR => f.write_str("Out of streams resources"),
            Self::ENONET => f.write_str("Machine is not on the network"),
            Self::ENOPKG => f.write_str("Package not installed"),
            Self::EADV => f.write_str("Advertise error"),
            Self::ESRMNT => f.write_str("Srmount error"),
            Self::ECOMM => f.write_str("Communication error on send"),
            Self::EDOTDOT => f.write_str("RFS specific error"),
            Self::ENOTUNIQ => f.write_str("Name not unique on network"),
            Self::EBADFD => f.write_str("File descriptor in bad state"),
            Self::EREMCHG => f.write_str("Remote address changed"),
            Self::ELIBACC => f.write_str("Can not access a needed shared library"),
            Self::ELIBBAD => f.write_str("Accessing a corrupted shared library"),
            Self::ELIBSCN => f.write_str(".lib section in a.out corrupted"),
            Self::ELIBMAX => f.write_str("Attempting to link in too many shared libraries"),
            Self::ELIBEXEC => f.write_str("Cannot exec a shared library directly"),
            Self::ERESTART => f.write_str("Interrupted system call should be restarted"),
            Self::ESTRPIPE => f.write_str("Streams pipe error"),
            Self::EUCLEAN => f.write_str("Structure needs cleaning"),
            Self::ENOTNAM => f.write_str("Not a XENIX named type file"),
            Self::ENAVAIL => f.write_str("No XENIX semaphores available"),
            Self::EISNAM => f.write_str("Is a named type file"),
            Self::EREMOTEIO => f.write_str("Remote I/O error"),
            Self::ENOKEY => f.write_str("Required key not available"),
            Self::EKEYEXPIRED => f.write_str("Key has expired"),
            Self::EKEYREVOKED => f.write_str("Key has been revoked"),
            Self::EKEYREJECTED => f.write_str("Key was rejected by service"),
            Self::ERFKILL => f.write_str("Operation not possible due to RF-kill"),
            Self::EHWPOISON => f.write_str("Memory page has hardware error"),
            Self::EPWROFF => f.write_str("Device power is off"),
            Self::EDEVERR => f.write_str("Device error, e.g. paper out"),
            Self::EBADEXEC => f.write_str("Bad executable"),
            Self::EBADARCH => f.write_str("Bad CPU type in executable"),
            Self::ESHLIBVERS => f.write_str("Shared library version mismatch"),
            Self::EBADMACHO => f.write_str("Malformed Macho file"),
            Self::ENOPOLICY => f.write_str("No such policy registered"),
            Self::EQFULL => f.write_str("Interface output queue is full"),
            Self::Other(other) => write!(f, "Unknown error code: {}", other.0),
        }
    }
}
impl Error for Errno {}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl From<Errno> for StdErr {
    #[inline]
    fn from(value: Errno) -> Self {
        // All platforms we support have `RawOsError` as `c_int`; thus no conversion is needed.
        Self::from_raw_os_error(value.into_raw())
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl TryFrom<StdErr> for Errno {
    type Error = StdErr;
    #[inline]
    fn try_from(value: StdErr) -> Result<Self, Self::Error> {
        // All platforms we support have `RawOsError` as `c_int`; thus no conversion is needed.
        value.raw_os_error().ok_or(value).map(Self::from_raw)
    }
}
