use super::c;
use core::{
    error::Error,
    ffi::c_int,
    fmt::{self, Display, Formatter},
    mem,
};
#[cfg(feature = "std")]
use std::io::Error as StdErr;
/// Error returned from calls to the system's libc.
#[cfg(target_os = "dragonfly")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to `match` an error against `Other`; `match` on `_` instead.
    #[doc(hidden)]
    Other,
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
    /// Read-only filesystem.
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
    /// Disc quota exceeded.
    EDQUOT,
    /// Stale NFS file handle.
    ESTALE,
    /// Too many levels of remote in path.
    EREMOTE,
    /// RPC struct is bad.
    EBADRPC,
    /// RPC version wrong.
    ERPCMISMATCH,
    /// RPC prog. not avail.
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
    /// Identifier removed.
    EIDRM,
    /// No message of desired type.
    ENOMSG,
    /// Value too large to be stored in data type.
    EOVERFLOW,
    /// Operation canceled.
    ECANCELED,
    /// Illegal byte sequence.
    EILSEQ,
    /// Attribute not found.
    ENOATTR,
    /// Programming error.
    EDOOFUS,
    /// Bad message.
    EBADMSG,
    /// Multihop attempted.
    EMULTIHOP,
    /// Link has been severed.
    ENOLINK,
    /// Protocol error.
    EPROTO,
    /// Linux.
    ENOMEDIUM,
    /// State not recoverable.
    ENOTRECOVERABLE,
    /// Previous owner died.
    EOWNERDEAD,
    /// XXX.
    EASYNC = 99,
}
/// Error returned from calls to the system's libc.
#[cfg(target_os = "freebsd")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to `match` an error against `Other`; `match` on `_` instead.
    #[doc(hidden)]
    Other,
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
    /// Read-only filesystem.
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
    /// Disc quota exceeded.
    EDQUOT,
    /// Stale NFS file handle.
    ESTALE,
    /// Too many levels of remote in path.
    EREMOTE,
    /// RPC struct is bad.
    EBADRPC,
    /// RPC version wrong.
    ERPCMISMATCH,
    /// RPC prog. not avail.
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
    /// Identifier removed.
    EIDRM,
    /// No message of desired type.
    ENOMSG,
    /// Value too large to be stored in data type.
    EOVERFLOW,
    /// Operation canceled.
    ECANCELED,
    /// Illegal byte sequence.
    EILSEQ,
    /// Attribute not found.
    ENOATTR,
    /// Programming error.
    EDOOFUS,
    /// Bad message.
    EBADMSG,
    /// Multihop attempted.
    EMULTIHOP,
    /// Link has been severed.
    ENOLINK,
    /// Protocol error.
    EPROTO,
    /// Capabilities insufficient.
    ENOTCAPABLE,
    /// Not permitted in capability mode.
    ECAPMODE,
    /// State not recoverable.
    ENOTRECOVERABLE,
    /// Previous owner died.
    EOWNERDEAD,
    /// Integrity check failed.
    EINTEGRITY,
}
/// Error returned from calls to the system's libc.
#[cfg(all(
    not(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64",
    )),
    target_os = "linux"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to `match` an error against `Other`; `match` on `_` instead.
    #[doc(hidden)]
    Other,
    /// Operation not permitted.
    EPERM,
    /// No such file or directory.
    ENOENT,
    /// No such process.
    ESRCH,
    /// Interrupted system call.
    EINTR,
    /// I/O error.
    EIO,
    /// No such device or address.
    ENXIO,
    /// Argument list too long.
    E2BIG,
    /// Exec format error.
    ENOEXEC,
    /// Bad file number.
    EBADF,
    /// No child processes.
    ECHILD,
    /// Operation would block.
    EWOULDBLOCK,
    /// Out of memory.
    ENOMEM,
    /// Permission denied.
    EACCES,
    /// Bad address.
    EFAULT,
    /// Block device required.
    ENOTBLK,
    /// Device or resource busy.
    EBUSY,
    /// File exists.
    EEXIST,
    /// Cross-device link.
    EXDEV,
    /// No such device.
    ENODEV,
    /// Not a directory.
    ENOTDIR,
    /// Is a directory.
    EISDIR,
    /// Invalid argument.
    EINVAL,
    /// File table overflow.
    ENFILE,
    /// Too many open files.
    EMFILE,
    /// Not a typewriter.
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
    /// Math argument out of domain of func.
    EDOM,
    /// Math result not representable.
    ERANGE,
    /// Resource deadlock would occur.
    EDEADLK,
    /// File name too long.
    ENAMETOOLONG,
    /// No record locks available.
    ENOLCK,
    /// Invalid system call number.
    ENOSYS,
    /// Directory not empty.
    ENOTEMPTY,
    /// Too many symbolic links encountered.
    ELOOP,
    /// No message of desired type.
    ENOMSG = 42,
    /// Identifier removed.
    EIDRM,
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
    /// File locking deadlock error.
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_arch = "powerpc", target_arch = "powerpc64")))
    )]
    #[cfg(any(doc, target_arch = "powerpc", target_arch = "powerpc64"))]
    EDEADLOCK,
    /// Bad font file format.
    EBFONT = 59,
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
    /// Object is remote.
    EREMOTE,
    /// Link has been severed.
    ENOLINK,
    /// Advertise error.
    EADV,
    /// Srmount error.
    ESRMNT,
    /// Communication error on send.
    ECOMM,
    /// Protocol error.
    EPROTO,
    /// Multihop attempted.
    EMULTIHOP,
    /// RFS specific error.
    EDOTDOT,
    /// Not a data message.
    EBADMSG,
    /// Value too large for defined data type.
    EOVERFLOW,
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
    /// Illegal byte sequence.
    EILSEQ,
    /// Interrupted system call should be restarted.
    ERESTART,
    /// Streams pipe error.
    ESTRPIPE,
    /// Too many users.
    EUSERS,
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
    /// Operation not supported on transport endpoint.
    EOPNOTSUPP,
    /// Protocol family not supported.
    EPFNOSUPPORT,
    /// Address family not supported by protocol.
    EAFNOSUPPORT,
    /// Address already in use.
    EADDRINUSE,
    /// Cannot assign requested address.
    EADDRNOTAVAIL,
    /// Network is down.
    ENETDOWN,
    /// Network is unreachable.
    ENETUNREACH,
    /// Network dropped connection because of reset.
    ENETRESET,
    /// Software caused connection abort.
    ECONNABORTED,
    /// Connection reset by peer.
    ECONNRESET,
    /// No buffer space available.
    ENOBUFS,
    /// Transport endpoint is already connected.
    EISCONN,
    /// Transport endpoint is not connected.
    ENOTCONN,
    /// Cannot send after transport endpoint shutdown.
    ESHUTDOWN,
    /// Too many references: cannot splice.
    ETOOMANYREFS,
    /// Connection timed out.
    ETIMEDOUT,
    /// Connection refused.
    ECONNREFUSED,
    /// Host is down.
    EHOSTDOWN,
    /// No route to host.
    EHOSTUNREACH,
    /// Operation already in progress.
    EALREADY,
    /// Operation now in progress.
    EINPROGRESS,
    /// Stale file handle.
    ESTALE,
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
    /// Quota exceeded.
    EDQUOT,
    /// No medium found.
    ENOMEDIUM,
    /// Wrong medium type.
    EMEDIUMTYPE,
    /// Operation Canceled.
    ECANCELED,
    /// Required key not available.
    ENOKEY,
    /// Key has expired.
    EKEYEXPIRED,
    /// Key has been revoked.
    EKEYREVOKED,
    /// Key was rejected by service.
    EKEYREJECTED,
    /// Owner died.
    EOWNERDEAD,
    /// State not recoverable.
    ENOTRECOVERABLE,
    /// Operation not possible due to RF-kill.
    ERFKILL,
    /// Memory page has hardware error.
    EHWPOISON,
}
/// Error returned from calls to the system's libc.
#[cfg(all(
    any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
    ),
    target_os = "linux"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to `match` an error against `Other`; `match` on `_` instead.
    #[doc(hidden)]
    Other,
    /// Operation not permitted.
    EPERM,
    /// No such file or directory.
    ENOENT,
    /// No such process.
    ESRCH,
    /// Interrupted system call.
    EINTR,
    /// I/O error.
    EIO,
    /// No such device or address.
    ENXIO,
    /// Argument list too long.
    E2BIG,
    /// Exec format error.
    ENOEXEC,
    /// Bad file number.
    EBADF,
    /// No child processes.
    ECHILD,
    /// Operation would block.
    EWOULDBLOCK,
    /// Out of memory.
    ENOMEM,
    /// Permission denied.
    EACCES,
    /// Bad address.
    EFAULT,
    /// Block device required.
    ENOTBLK,
    /// Device or resource busy.
    EBUSY,
    /// File exists.
    EEXIST,
    /// Cross-device link.
    EXDEV,
    /// No such device.
    ENODEV,
    /// Not a directory.
    ENOTDIR,
    /// Is a directory.
    EISDIR,
    /// Invalid argument.
    EINVAL,
    /// File table overflow.
    ENFILE,
    /// Too many open files.
    EMFILE,
    /// Not a typewriter.
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
    /// Math argument out of domain of func.
    EDOM,
    /// Math result not representable.
    ERANGE,
    /// No message of desired type.
    ENOMSG,
    /// Identifier removed.
    EIDRM,
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
    /// Resource deadlock would occur.
    EDEADLK,
    /// No record locks available.
    ENOLCK,
    /// Invalid exchange.
    EBADE = 50,
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
    /// File locking deadlock error.
    EDEADLOCK,
    /// Bad font file format.
    EBFONT = 59,
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
    /// Object is remote.
    EREMOTE,
    /// Link has been severed.
    ENOLINK,
    /// Advertise error.
    EADV,
    /// Srmount error.
    ESRMNT,
    /// Communication error on send.
    ECOMM,
    /// Protocol error.
    EPROTO,
    /// RFS specific error.
    EDOTDOT = 73,
    /// Multihop attempted.
    EMULTIHOP,
    /// Not a data message.
    EBADMSG = 77,
    /// File name too long.
    ENAMETOOLONG,
    /// Value too large for defined data type.
    EOVERFLOW,
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
    /// Illegal byte sequence.
    EILSEQ,
    /// Function not implemented.
    ENOSYS,
    /// Too many symbolic links encountered.
    ELOOP,
    /// Interrupted system call should be restarted.
    ERESTART,
    /// Streams pipe error.
    ESTRPIPE,
    /// Directory not empty.
    ENOTEMPTY,
    /// Too many users.
    EUSERS,
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
    EPROTONOSUPPORT = 120,
    /// Socket type not supported.
    ESOCKTNOSUPPORT,
    /// Operation not supported on transport endpoint.
    EOPNOTSUPP,
    /// Protocol family not supported.
    EPFNOSUPPORT,
    /// Address family not supported by protocol.
    EAFNOSUPPORT,
    /// Address already in use.
    EADDRINUSE,
    /// Cannot assign requested address.
    EADDRNOTAVAIL,
    /// Network is down.
    ENETDOWN,
    /// Network is unreachable.
    ENETUNREACH,
    /// Network dropped connection because of reset.
    ENETRESET,
    /// Software caused connection abort.
    ECONNABORTED,
    /// Connection reset by peer.
    ECONNRESET,
    /// No buffer space available.
    ENOBUFS,
    /// Transport endpoint is already connected.
    EISCONN,
    /// Transport endpoint is not connected.
    ENOTCONN,
    /// Structure needs cleaning.
    EUCLEAN,
    /// Not a XENIX named type file.
    ENOTNAM = 137,
    /// No XENIX semaphores available.
    ENAVAIL,
    /// Is a named type file.
    EISNAM,
    /// Remote I/O error.
    EREMOTEIO,
    /// Reserved.
    EINIT,
    /// Error 142.
    EREMDEV,
    /// Cannot send after transport endpoint shutdown.
    ESHUTDOWN,
    /// Too many references: cannot splice.
    ETOOMANYREFS,
    /// Connection timed out.
    ETIMEDOUT,
    /// Connection refused.
    ECONNREFUSED,
    /// Host is down.
    EHOSTDOWN,
    /// No route to host.
    EHOSTUNREACH,
    /// Operation already in progress.
    EALREADY,
    /// Operation now in progress.
    EINPROGRESS,
    /// Stale file handle.
    ESTALE,
    /// AIO operation canceled.
    ECANCELED = 158,
    /// No medium found.
    ENOMEDIUM,
    /// Wrong medium type.
    EMEDIUMTYPE,
    /// Required key not available.
    ENOKEY,
    /// Key has expired.
    EKEYEXPIRED,
    /// Key has been revoked.
    EKEYREVOKED,
    /// Key was rejected by service.
    EKEYREJECTED,
    /// Owner died.
    EOWNERDEAD,
    /// State not recoverable.
    ENOTRECOVERABLE,
    /// Operation not possible due to RF-kill.
    ERFKILL,
    /// Memory page has hardware error.
    EHWPOISON,
    /// Quota exceeded.
    EDQUOT = 1133,
}
/// Error returned from calls to the system's libc.
#[cfg(all(
    any(target_arch = "sparc", target_arch = "sparc64"),
    target_os = "linux"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to `match` an error against `Other`; `match` on `_` instead.
    #[doc(hidden)]
    Other,
    /// Operation not permitted.
    EPERM,
    /// No such file or directory.
    ENOENT,
    /// No such process.
    ESRCH,
    /// Interrupted system call.
    EINTR,
    /// I/O error.
    EIO,
    /// No such device or address.
    ENXIO,
    /// Argument list too long.
    E2BIG,
    /// Exec format error.
    ENOEXEC,
    /// Bad file number.
    EBADF,
    /// No child processes.
    ECHILD,
    /// Operation would block.
    EWOULDBLOCK,
    /// Out of memory.
    ENOMEM,
    /// Permission denied.
    EACCES,
    /// Bad address.
    EFAULT,
    /// Block device required.
    ENOTBLK,
    /// Device or resource busy.
    EBUSY,
    /// File exists.
    EEXIST,
    /// Cross-device link.
    EXDEV,
    /// No such device.
    ENODEV,
    /// Not a directory.
    ENOTDIR,
    /// Is a directory.
    EISDIR,
    /// Invalid argument.
    EINVAL,
    /// File table overflow.
    ENFILE,
    /// Too many open files.
    EMFILE,
    /// Not a typewriter.
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
    /// Math argument out of domain of func.
    EDOM,
    /// Math result not representable.
    ERANGE,
    /// Operation now in progress.
    EINPROGRESS = 36,
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
    /// Op not supported on transport endpoint.
    EOPNOTSUPP,
    /// Protocol family not supported.
    EPFNOSUPPORT,
    /// Address family not supported by protocol.
    EAFNOSUPPORT,
    /// Address already in use.
    EADDRINUSE,
    /// Cannot assign requested address.
    EADDRNOTAVAIL,
    /// Network is down.
    ENETDOWN,
    /// Network is unreachable.
    ENETUNREACH,
    /// Net dropped connection because of reset.
    ENETRESET,
    /// Software caused connection abort.
    ECONNABORTED,
    /// Connection reset by peer.
    ECONNRESET,
    /// No buffer space available.
    ENOBUFS,
    /// Transport endpoint is already connected.
    EISCONN,
    /// Transport endpoint is not connected.
    ENOTCONN,
    /// No send after transport endpoint shutdown.
    ESHUTDOWN,
    /// Too many references: cannot splice.
    ETOOMANYREFS,
    /// Connection timed out.
    ETIMEDOUT,
    /// Connection refused.
    ECONNREFUSED,
    /// Too many symbolic links encountered.
    ELOOP,
    /// File name too long.
    ENAMETOOLONG,
    /// Host is down.
    EHOSTDOWN,
    /// No route to host.
    EHOSTUNREACH,
    /// Directory not empty.
    ENOTEMPTY,
    /// SUNOS: Too many processes.
    EPROCLIM,
    /// Too many users.
    EUSERS,
    /// Quota exceeded.
    EDQUOT,
    /// Stale file handle.
    ESTALE,
    /// Object is remote.
    EREMOTE,
    /// Device not a stream.
    ENOSTR,
    /// Timer expired.
    ETIME,
    /// Out of streams resources.
    ENOSR,
    /// No message of desired type.
    ENOMSG,
    /// Not a data message.
    EBADMSG,
    /// Identifier removed.
    EIDRM,
    /// Resource deadlock would occur.
    EDEADLK,
    /// No record locks available.
    ENOLCK,
    /// Machine is not on the network.
    ENONET,
    /// SunOS: Too many lvls of remote in path.
    #[expect(clippy::doc_markdown, reason = "false positive")]
    ERREMOTE,
    /// Link has been severed.
    ENOLINK,
    /// Advertise error.
    EADV,
    /// Srmount error.
    ESRMNT,
    /// Communication error on send.
    ECOMM,
    /// Protocol error.
    EPROTO,
    /// Multihop attempted.
    EMULTIHOP,
    /// RFS specific error.
    EDOTDOT,
    /// Remote address changed.
    EREMCHG,
    /// Function not implemented.
    ENOSYS,
    /// Streams pipe error.
    ESTRPIPE,
    /// Value too large for defined data type.
    EOVERFLOW,
    /// File descriptor in bad state.
    EBADFD,
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
    /// File locking deadlock error.
    EDEADLOCK,
    /// Bad font file format.
    EBFONT,
    /// Cannot exec a shared library directly.
    ELIBEXEC,
    /// No data available.
    ENODATA,
    /// Accessing a corrupted shared library.
    ELIBBAD,
    /// Package not installed.
    ENOPKG,
    /// Can not access a needed shared library.
    ELIBACC,
    /// Name not unique on network.
    ENOTUNIQ,
    /// Interrupted syscall should be restarted.
    ERESTART,
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
    /// Illegal byte sequence.
    EILSEQ,
    /// Atmpt to link in too many shared libs.
    ELIBMAX,
    /// .lib section in a.out corrupted.
    ELIBSCN,
    /// No medium found.
    ENOMEDIUM,
    /// Wrong medium type.
    EMEDIUMTYPE,
    /// Operation Cancelled.
    ECANCELED,
    /// Required key not available.
    ENOKEY,
    /// Key has expired.
    EKEYEXPIRED,
    /// Key has been revoked.
    EKEYREVOKED,
    /// Key was rejected by service.
    EKEYREJECTED,
    /// Owner died.
    EOWNERDEAD,
    /// State not recoverable.
    ENOTRECOVERABLE,
    /// Operation not possible due to RF-kill.
    ERFKILL,
    /// Memory page has hardware error.
    EHWPOISON,
}
/// Error returned from calls to the system's libc.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to `match` an error against `Other`; `match` on `_` instead.
    #[doc(hidden)]
    Other,
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
    /// Device / Resource busy.
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
    /// Operation not supported on socket.
    ENOTSUP,
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
    /// Disc quota exceeded.
    EDQUOT,
    /// Stale NFS file handle.
    ESTALE,
    /// Too many levels of remote in path.
    EREMOTE,
    /// RPC struct is bad.
    EBADRPC,
    /// RPC version wrong.
    ERPCMISMATCH,
    /// RPC prog. not avail.
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
    /// Device power is off.
    EPWROFF,
    /// Device error, e.g. paper out.
    EDEVERR,
    /// Value too large to be stored in data type.
    EOVERFLOW,
    /// Bad executable.
    EBADEXEC,
    /// Bad CPU type in executable.
    EBADARCH,
    /// Shared library version mismatch.
    ESHLIBVERS,
    /// Malformed Macho file.
    EBADMACHO,
    /// Operation canceled.
    ECANCELED,
    /// Identifier removed.
    EIDRM,
    /// No message of desired type.
    ENOMSG,
    /// Illegal byte sequence.
    EILSEQ,
    /// Attribute not found.
    ENOATTR,
    /// Bad message.
    EBADMSG,
    /// Reserved.
    EMULTIHOP,
    /// No message available on STREAM.
    ENODATA,
    /// Reserved.
    ENOLINK,
    /// No STREAM resources.
    ENOSR,
    /// Not a STREAM.
    ENOSTR,
    /// Protocol error.
    EPROTO,
    /// STREAM ioctl timeout.
    ETIME,
    /// Operation not supported on socket.
    EOPNOTSUPP,
    /// No such policy registered.
    ENOPOLICY,
    /// State not recoverable.
    ENOTRECOVERABLE,
    /// Previous owner died.
    EOWNERDEAD,
    /// Interface output queue is full.
    EQFULL,
    /// Capabilities insufficient.
    ENOTCAPABLE,
}
/// Error returned from calls to the system's libc.
#[cfg(target_os = "netbsd")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to `match` an error against `Other`; `match` on `_` instead.
    #[doc(hidden)]
    Other,
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
    /// Result too large or too small.
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
    /// Protocol option not available.
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
    /// Disc quota exceeded.
    EDQUOT,
    /// Stale NFS file handle.
    ESTALE,
    /// Too many levels of remote in path.
    EREMOTE,
    /// RPC struct is bad.
    EBADRPC,
    /// RPC version wrong.
    ERPCMISMATCH,
    /// RPC prog. not avail.
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
    /// Identifier removed.
    EIDRM,
    /// No message of desired type.
    ENOMSG,
    /// Value too large to be stored in data type.
    EOVERFLOW,
    /// Illegal byte sequence.
    EILSEQ,
    /// Not supported.
    ENOTSUP,
    /// Operation canceled.
    ECANCELED,
    /// Bad or Corrupt message.
    EBADMSG,
    /// No message available.
    ENODATA,
    /// No STREAM resources.
    ENOSR,
    /// Not a STREAM.
    ENOSTR,
    /// STREAM ioctl timeout.
    ETIME,
    /// Attribute not found.
    ENOATTR,
    /// Multihop attempted.
    EMULTIHOP,
    /// Link has been severed.
    ENOLINK,
    /// Protocol error.
    EPROTO,
    /// Previous owner died.
    EOWNERDEAD,
    /// State not recoverable.
    ENOTRECOVERABLE,
}
/// Error returned from calls to the system's libc.
#[cfg(target_os = "openbsd")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(i32)]
pub enum Errno {
    /// All other error codes.
    ///
    /// It is not recommended to `match` an error against `Other`; `match` on `_` instead.
    #[doc(hidden)]
    Other,
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
}
impl Errno {
    /// Resource temporarily unavailable.
    pub const EAGAIN: Self = Self::EWOULDBLOCK;
    /// Operation not supported.
    #[cfg_attr(docsrs, doc(cfg(any(target_os = "dragonfly", target_os = "freebsd"))))]
    #[cfg(any(target_os = "dragonfly", target_os = "freebsd"))]
    pub const ENOTSUP: Self = Self::EOPNOTSUPP;
    /// Must be equal to largest `Errno`.
    #[cfg_attr(docsrs, doc(cfg(target_os = "dragonfly")))]
    #[cfg(target_os = "dragonfly")]
    pub const LAST: Self = Self::EASYNC;
    /// Must be equal to largest `Errno`.
    #[cfg_attr(docsrs, doc(cfg(target_os = "freebsd")))]
    #[cfg(target_os = "freebsd")]
    pub const LAST: Self = Self::EINTEGRITY;
    /// Resource deadlock would occur.
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            not(any(
                target_arch = "mips",
                target_arch = "mips32r6",
                target_arch = "mips64",
                target_arch = "mips64r6",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "sparc",
                target_arch = "sparc64"
            )),
            target_os = "linux"
        )))
    )]
    #[cfg(all(
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64",
        )),
        target_os = "linux"
    ))]
    pub const EDEADLOCK: Self = Self::EDEADLK;
    /// Must be equal to largest `Errno`.
    #[cfg_attr(docsrs, doc(cfg(target_os = "macos")))]
    #[cfg(target_os = "macos")]
    pub const LAST: Self = Self::ENOTCAPABLE;
    /// Must be equal to largest `Errno`.
    #[cfg_attr(docsrs, doc(cfg(target_os = "netbsd")))]
    #[cfg(target_os = "netbsd")]
    pub const LAST: Self = Self::ENOTRECOVERABLE;
    /// Must be equal to largest `Errno`.
    #[cfg_attr(docsrs, doc(cfg(target_os = "openbsd")))]
    #[cfg(target_os = "openbsd")]
    pub const LAST: Self = Self::EPROTO;
    /// Returns a `Self` equivalent to `code`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Errno;
    /// assert_eq!(Errno::from_raw(1), Errno::EPERM);
    /// ```
    #[expect(unsafe_code, reason = "comment justifies correctness")]
    #[inline]
    #[must_use]
    pub const fn from_raw(code: i32) -> Self {
        match code {
            #[cfg(target_os = "dragonfly")]
            ..=0 | 96..=98 | 100.. => Self::Other,
            #[cfg(target_os = "freebsd")]
            ..=0 | 98.. => Self::Other,
            #[cfg(all(
                not(any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                    target_arch = "powerpc",
                    target_arch = "powerpc64",
                    target_arch = "sparc",
                    target_arch = "sparc64",
                )),
                target_os = "linux"
            ))]
            ..=0 | 41 | 58 | 134.. => Self::Other,
            #[cfg(all(
                any(
                    target_arch = "mips",
                    target_arch = "mips32r6",
                    target_arch = "mips64",
                    target_arch = "mips64r6",
                ),
                target_os = "linux"
            ))]
            ..=0
            | 47..=49
            | 57..=58
            | 72
            | 75..=76
            | 100..=119
            | 136
            | 152..=157
            | 169..=1132
            | 1134.. => Self::Other,
            #[cfg(all(
                any(target_arch = "powerpc", target_arch = "powerpc64",),
                target_os = "linux"
            ))]
            ..=0 | 41 | 134.. => Self::Other,
            #[cfg(all(
                any(target_arch = "sparc", target_arch = "sparc64"),
                target_os = "linux"
            ))]
            ..=0 | 35 | 136.. => Self::Other,
            #[cfg(target_os = "macos")]
            ..=0 | 108.. => Self::Other,
            #[cfg(target_os = "netbsd")]
            ..=0 | 99.. => Self::Other,
            #[cfg(target_os = "openbsd")]
            ..=0 | 96.. => Self::Other,
            _ => {
                // SAFETY:
                // `Self` is `repr(i32)`, and we verified `code` is in-range.
                unsafe { mem::transmute::<i32, Self>(code) }
            }
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
    #[expect(clippy::as_conversions, reason = "comment justifies correctness")]
    #[inline]
    #[must_use]
    pub const fn into_raw(self) -> i32 {
        // This is fine since `Self` is `repr(i32)` and has inclusive range 0 to 133.
        self as i32
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
    /// Returns the current raw error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Errno;
    /// Errno::EPERM.set();
    /// assert_eq!(Errno::last_raw(), Errno::EPERM.into_raw());
    /// ```
    #[expect(unsafe_code, reason = "safety comment justifies correctness")]
    #[inline]
    #[must_use]
    pub fn last_raw() -> i32 {
        let ptr = Self::get_raw_err_ptr();
        debug_assert!(
            !ptr.is_null() && ptr.is_aligned(),
            "libc errno returned a pointer that was either null or not aligned. Something is terribly wrong with your system"
        );
        // SAFETY:
        // Verified above that `ptr` is not null and aligned. Note while we only verify
        // this on non-release builds, the situation is so dire that one could argue we are
        // already in "undefined" territory.
        unsafe { *ptr }
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
    #[inline]
    #[must_use]
    pub fn last() -> Self {
        Self::from_raw(Self::last_raw())
    }
    /// Clears any error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use priv_sep::Errno;
    /// Errno::clear();
    /// assert_eq!(Errno::last().into_raw(), 0);
    /// ```
    #[inline]
    pub fn clear() {
        Self::Other.set();
    }
}
impl From<Errno> for i32 {
    #[inline]
    fn from(value: Errno) -> Self {
        value.into_raw()
    }
}
impl From<i32> for Errno {
    #[inline]
    fn from(value: i32) -> Self {
        Self::from_raw(value)
    }
}
impl Error for Errno {}
#[cfg(target_os = "dragonfly")]
impl Display for Errno {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "Input/output error",
            Self::ENXIO => "Device not configured",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file descriptor",
            Self::ECHILD => "No child processes",
            Self::EDEADLK => "Resource deadlock avoided",
            Self::ENOMEM => "Cannot allocate memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "Operation not supported by device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "Too many open files in system",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Inappropriate ioctl for device",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only filesystem",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Numerical argument out of domain",
            Self::ERANGE => "Result too large",
            Self::EWOULDBLOCK => "Operation would block",
            Self::EINPROGRESS => "Operation now in progress",
            Self::EALREADY => "Operation already in progress",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::EOPNOTSUPP => "Operation not supported",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol family",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Can't assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Network dropped connection on reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Socket is already connected",
            Self::ENOTCONN => "Socket is not connected",
            Self::ESHUTDOWN => "Can't send after socket shutdown",
            Self::ETOOMANYREFS => "Too many references: can't splice",
            Self::ETIMEDOUT => "Operation timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::ELOOP => "Too many levels of symbolic links",
            Self::ENAMETOOLONG => "File name too long",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::ENOTEMPTY => "Directory not empty",
            Self::EPROCLIM => "Too many processes",
            Self::EUSERS => "Too many users",
            Self::EDQUOT => "Disc quota exceeded",
            Self::ESTALE => "Stale NFS file handle",
            Self::EREMOTE => "Too many levels of remote in path",
            Self::EBADRPC => "RPC struct is bad",
            Self::ERPCMISMATCH => "RPC version wrong",
            Self::EPROGUNAVAIL => "RPC prog. not avail",
            Self::EPROGMISMATCH => "Program version wrong",
            Self::EPROCUNAVAIL => "Bad procedure for program",
            Self::ENOLCK => "No locks available",
            Self::ENOSYS => "Function not implemented",
            Self::EFTYPE => "Inappropriate file type or format",
            Self::EAUTH => "Authentication error",
            Self::ENEEDAUTH => "Need authenticator",
            Self::EIDRM => "Identifier removed",
            Self::ENOMSG => "No message of desired type",
            Self::EOVERFLOW => "Value too large to be stored in data type",
            Self::ECANCELED => "Operation canceled",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ENOATTR => "Attribute not found",
            Self::EDOOFUS => "Programming error",
            Self::EBADMSG => "Bad message",
            Self::EMULTIHOP => "Multihop attempted",
            Self::ENOLINK => "Link has been severed",
            Self::EPROTO => "Protocol error",
            Self::ENOMEDIUM => "Linux",
            Self::ENOTRECOVERABLE => "State not recoverable",
            Self::EOWNERDEAD => "Previous owner died",
            Self::EASYNC => "XXX",
        })
    }
}
#[cfg(target_os = "freebsd")]
impl Display for Errno {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "Input/output error",
            Self::ENXIO => "Device not configured",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file descriptor",
            Self::ECHILD => "No child processes",
            Self::EDEADLK => "Resource deadlock avoided",
            Self::ENOMEM => "Cannot allocate memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "Operation not supported by device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "Too many open files in system",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Inappropriate ioctl for device",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only filesystem",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Numerical argument out of domain",
            Self::ERANGE => "Result too large",
            Self::EWOULDBLOCK => "Operation would block",
            Self::EINPROGRESS => "Operation now in progress",
            Self::EALREADY => "Operation already in progress",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::EOPNOTSUPP => "Operation not supported",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol family",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Can't assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Network dropped connection on reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Socket is already connected",
            Self::ENOTCONN => "Socket is not connected",
            Self::ESHUTDOWN => "Can't send after socket shutdown",
            Self::ETOOMANYREFS => "Too many references: can't splice",
            Self::ETIMEDOUT => "Operation timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::ELOOP => "Too many levels of symbolic links",
            Self::ENAMETOOLONG => "File name too long",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::ENOTEMPTY => "Directory not empty",
            Self::EPROCLIM => "Too many processes",
            Self::EUSERS => "Too many users",
            Self::EDQUOT => "Disc quota exceeded",
            Self::ESTALE => "Stale NFS file handle",
            Self::EREMOTE => "Too many levels of remote in path",
            Self::EBADRPC => "RPC struct is bad",
            Self::ERPCMISMATCH => "RPC version wrong",
            Self::EPROGUNAVAIL => "RPC prog. not avail",
            Self::EPROGMISMATCH => "Program version wrong",
            Self::EPROCUNAVAIL => "Bad procedure for program",
            Self::ENOLCK => "No locks available",
            Self::ENOSYS => "Function not implemented",
            Self::EFTYPE => "Inappropriate file type or format",
            Self::EAUTH => "Authentication error",
            Self::ENEEDAUTH => "Need authenticator",
            Self::EIDRM => "Identifier removed",
            Self::ENOMSG => "No message of desired type",
            Self::EOVERFLOW => "Value too large to be stored in data type",
            Self::ECANCELED => "Operation canceled",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ENOATTR => "Attribute not found",
            Self::EDOOFUS => "Programming error",
            Self::EBADMSG => "Bad message",
            Self::EMULTIHOP => "Multihop attempted",
            Self::ENOLINK => "Link has been severed",
            Self::EPROTO => "Protocol error",
            Self::ENOTCAPABLE => "Capabilities insufficient",
            Self::ECAPMODE => "Not permitted in capability mode",
            Self::ENOTRECOVERABLE => "State not recoverable",
            Self::EOWNERDEAD => "Previous owner died",
            Self::EINTEGRITY => "Integrity check failed",
        })
    }
}
#[cfg(all(
    not(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64",
    )),
    target_os = "linux"
))]
impl Display for Errno {
    #[expect(clippy::too_many_lines, reason = "large match expression")]
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "I/O error",
            Self::ENXIO => "No such device or address",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file number",
            Self::ECHILD => "No child processes",
            Self::EWOULDBLOCK => "Operation would block",
            Self::ENOMEM => "Out of memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device or resource busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "No such device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "File table overflow",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Not a typewriter",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only file system",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Math argument out of domain of func",
            Self::ERANGE => "Math result not representable",
            Self::EDEADLK => "Resource deadlock would occur",
            Self::ENAMETOOLONG => "File name too long",
            Self::ENOLCK => "No record locks available",
            Self::ENOSYS => "Invalid system call number",
            Self::ENOTEMPTY => "Directory not empty",
            Self::ELOOP => "Too many symbolic links encountered",
            Self::ENOMSG => "No message of desired type",
            Self::EIDRM => "Identifier removed",
            Self::ECHRNG => "Channel number out of range",
            Self::EL2NSYNC => "Level 2 not synchronized",
            Self::EL3HLT => "Level 3 halted",
            Self::EL3RST => "Level 3 reset",
            Self::ELNRNG => "Link number out of range",
            Self::EUNATCH => "Protocol driver not attached",
            Self::ENOCSI => "No CSI structure available",
            Self::EL2HLT => "Level 2 halted",
            Self::EBADE => "Invalid exchange",
            Self::EBADR => "Invalid request descriptor",
            Self::EXFULL => "Exchange full",
            Self::ENOANO => "No anode",
            Self::EBADRQC => "Invalid request code",
            Self::EBADSLT => "Invalid slot",
            #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
            Self::EDEADLOCK => "File locking deadlock error",
            Self::EBFONT => "Bad font file format",
            Self::ENOSTR => "Device not a stream",
            Self::ENODATA => "No data available",
            Self::ETIME => "Timer expired",
            Self::ENOSR => "Out of streams resources",
            Self::ENONET => "Machine is not on the network",
            Self::ENOPKG => "Package not installed",
            Self::EREMOTE => "Object is remote",
            Self::ENOLINK => "Link has been severed",
            Self::EADV => "Advertise error",
            Self::ESRMNT => "Srmount error",
            Self::ECOMM => "Communication error on send",
            Self::EPROTO => "Protocol error",
            Self::EMULTIHOP => "Multihop attempted",
            Self::EDOTDOT => "RFS specific error",
            Self::EBADMSG => "Not a data message",
            Self::EOVERFLOW => "Value too large for defined data type",
            Self::ENOTUNIQ => "Name not unique on network",
            Self::EBADFD => "File descriptor in bad state",
            Self::EREMCHG => "Remote address changed",
            Self::ELIBACC => "Can not access a needed shared library",
            Self::ELIBBAD => "Accessing a corrupted shared library",
            Self::ELIBSCN => ".lib section in a.out corrupted",
            Self::ELIBMAX => "Attempting to link in too many shared libraries",
            Self::ELIBEXEC => "Cannot exec a shared library directly",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ERESTART => "Interrupted system call should be restarted",
            Self::ESTRPIPE => "Streams pipe error",
            Self::EUSERS => "Too many users",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::EOPNOTSUPP => "Operation not supported on transport endpoint",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Cannot assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Network dropped connection because of reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Transport endpoint is already connected",
            Self::ENOTCONN => "Transport endpoint is not connected",
            Self::ESHUTDOWN => "Cannot send after transport endpoint shutdown",
            Self::ETOOMANYREFS => "Too many references: cannot splice",
            Self::ETIMEDOUT => "Connection timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::EALREADY => "Operation already in progress",
            Self::EINPROGRESS => "Operation now in progress",
            Self::ESTALE => "Stale file handle",
            Self::EUCLEAN => "Structure needs cleaning",
            Self::ENOTNAM => "Not a XENIX named type file",
            Self::ENAVAIL => "No XENIX semaphores available",
            Self::EISNAM => "Is a named type file",
            Self::EREMOTEIO => "Remote I/O error",
            Self::EDQUOT => "Quota exceeded",
            Self::ENOMEDIUM => "No medium found",
            Self::EMEDIUMTYPE => "Wrong medium type",
            Self::ECANCELED => "Operation Canceled",
            Self::ENOKEY => "Required key not available",
            Self::EKEYEXPIRED => "Key has expired",
            Self::EKEYREVOKED => "Key has been revoked",
            Self::EKEYREJECTED => "Key was rejected by service",
            Self::EOWNERDEAD => "Owner died",
            Self::ENOTRECOVERABLE => "State not recoverable",
            Self::ERFKILL => "Operation not possible due to RF-kill",
            Self::EHWPOISON => "Memory page has hardware error",
        })
    }
}
#[cfg(all(
    any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
    ),
    target_os = "linux"
))]
impl Display for Errno {
    #[expect(clippy::too_many_lines, reason = "large match expression")]
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "I/O error",
            Self::ENXIO => "No such device or address",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file number",
            Self::ECHILD => "No child processes",
            Self::EWOULDBLOCK => "Operation would block",
            Self::ENOMEM => "Out of memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device or resource busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "No such device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "File table overflow",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Not a typewriter",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only file system",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Math argument out of domain of func",
            Self::ERANGE => "Math result not representable",
            Self::ENOMSG => "No message of desired type",
            Self::EIDRM => "Identifier removed",
            Self::ECHRNG => "Channel number out of range",
            Self::EL2NSYNC => "Level 2 not synchronized",
            Self::EL3HLT => "Level 3 halted",
            Self::EL3RST => "Level 3 reset",
            Self::ELNRNG => "Link number out of range",
            Self::EUNATCH => "Protocol driver not attached",
            Self::ENOCSI => "No CSI structure available",
            Self::EL2HLT => "Level 2 halted",
            Self::EDEADLK => "Resource deadlock would occur",
            Self::ENOLCK => "No record locks available",
            Self::EBADE => "Invalid exchange",
            Self::EBADR => "Invalid request descriptor",
            Self::EXFULL => "Exchange full",
            Self::ENOANO => "No anode",
            Self::EBADRQC => "Invalid request code",
            Self::EBADSLT => "Invalid slot",
            Self::EDEADLOCK => "File locking deadlock error",
            Self::EBFONT => "Bad font file format",
            Self::ENOSTR => "Device not a stream",
            Self::ENODATA => "No data available",
            Self::ETIME => "Timer expired",
            Self::ENOSR => "Out of streams resources",
            Self::ENONET => "Machine is not on the network",
            Self::ENOPKG => "Package not installed",
            Self::EREMOTE => "Object is remote",
            Self::ENOLINK => "Link has been severed",
            Self::EADV => "Advertise error",
            Self::ESRMNT => "Srmount error",
            Self::ECOMM => "Communication error on send",
            Self::EPROTO => "Protocol error",
            Self::EDOTDOT => "RFS specific error",
            Self::EMULTIHOP => "Multihop attempted",
            Self::EBADMSG => "Not a data message",
            Self::ENAMETOOLONG => "File name too long",
            Self::EOVERFLOW => "Value too large for defined data type",
            Self::ENOTUNIQ => "Name not unique on network",
            Self::EBADFD => "File descriptor in bad state",
            Self::EREMCHG => "Remote address changed",
            Self::ELIBACC => "Can not access a needed shared library",
            Self::ELIBBAD => "Accessing a corrupted shared library",
            Self::ELIBSCN => ".lib section in a.out corrupted",
            Self::ELIBMAX => "Attempting to link in too many shared libraries",
            Self::ELIBEXEC => "Cannot exec a shared library directly",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ENOSYS => "Function not implemented",
            Self::ELOOP => "Too many symbolic links encountered",
            Self::ERESTART => "Interrupted system call should be restarted",
            Self::ESTRPIPE => "Streams pipe error",
            Self::ENOTEMPTY => "Directory not empty",
            Self::EUSERS => "Too many users",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::EOPNOTSUPP => "Operation not supported on transport endpoint",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Cannot assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Network dropped connection because of reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Transport endpoint is already connected",
            Self::ENOTCONN => "Transport endpoint is not connected",
            Self::EUCLEAN => "Structure needs cleaning",
            Self::ENOTNAM => "Not a XENIX named type file",
            Self::ENAVAIL => "No XENIX semaphores available",
            Self::EISNAM => "Is a named type file",
            Self::EREMOTEIO => "Remote I/O error",
            Self::EINIT => "Reserved",
            Self::EREMDEV => "Error 142",
            Self::ESHUTDOWN => "Cannot send after transport endpoint shutdown",
            Self::ETOOMANYREFS => "Too many references: cannot splice",
            Self::ETIMEDOUT => "Connection timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::EALREADY => "Operation already in progress",
            Self::EINPROGRESS => "Operation now in progress",
            Self::ESTALE => "Stale file handle",
            Self::ECANCELED => "AIO operation canceled",
            Self::ENOMEDIUM => "No medium found",
            Self::EMEDIUMTYPE => "Wrong medium type",
            Self::ENOKEY => "Required key not available",
            Self::EKEYEXPIRED => "Key has expired",
            Self::EKEYREVOKED => "Key has been revoked",
            Self::EKEYREJECTED => "Key was rejected by service",
            Self::EOWNERDEAD => "Owner died",
            Self::ENOTRECOVERABLE => "State not recoverable",
            Self::ERFKILL => "Operation not possible due to RF-kill",
            Self::EHWPOISON => "Memory page has hardware error",
            Self::EDQUOT => "Quota exceeded",
        })
    }
}
#[cfg(all(
    any(target_arch = "sparc", target_arch = "sparc64"),
    target_os = "linux"
))]
impl Display for Errno {
    #[expect(clippy::too_many_lines, reason = "large match expression")]
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "I/O error",
            Self::ENXIO => "No such device or address",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file number",
            Self::ECHILD => "No child processes",
            Self::EWOULDBLOCK => "Operation would block",
            Self::ENOMEM => "Out of memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device or resource busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "No such device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "File table overflow",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Not a typewriter",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only file system",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Math argument out of domain of func",
            Self::ERANGE => "Math result not representable",
            Self::EINPROGRESS => "Operation now in progress",
            Self::EALREADY => "Operation already in progress",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::EOPNOTSUPP => "Op not supported on transport endpoint",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Cannot assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Net dropped connection because of reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Transport endpoint is already connected",
            Self::ENOTCONN => "Transport endpoint is not connected",
            Self::ESHUTDOWN => "No send after transport endpoint shutdown",
            Self::ETOOMANYREFS => "Too many references: cannot splice",
            Self::ETIMEDOUT => "Connection timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::ELOOP => "Too many symbolic links encountered",
            Self::ENAMETOOLONG => "File name too long",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::ENOTEMPTY => "Directory not empty",
            Self::EPROCLIM => "SUNOS: Too many processes",
            Self::EUSERS => "Too many users",
            Self::EDQUOT => "Quota exceeded",
            Self::ESTALE => "Stale file handle",
            Self::EREMOTE => "Object is remote",
            Self::ENOSTR => "Device not a stream",
            Self::ETIME => "Timer expired",
            Self::ENOSR => "Out of streams resources",
            Self::ENOMSG => "No message of desired type",
            Self::EBADMSG => "Not a data message",
            Self::EIDRM => "Identifier removed",
            Self::EDEADLK => "Resource deadlock would occur",
            Self::ENOLCK => "No record locks available",
            Self::ENONET => "Machine is not on the network",
            Self::ERREMOTE => "SunOS: Too many lvls of remote in path",
            Self::ENOLINK => "Link has been severed",
            Self::EADV => "Advertise error",
            Self::ESRMNT => "Srmount error",
            Self::ECOMM => "Communication error on send",
            Self::EPROTO => "Protocol error",
            Self::EMULTIHOP => "Multihop attempted",
            Self::EDOTDOT => "RFS specific error",
            Self::EREMCHG => "Remote address changed",
            Self::ENOSYS => "Function not implemented",
            Self::ESTRPIPE => "Streams pipe error",
            Self::EOVERFLOW => "Value too large for defined data type",
            Self::EBADFD => "File descriptor in bad state",
            Self::ECHRNG => "Channel number out of range",
            Self::EL2NSYNC => "Level 2 not synchronized",
            Self::EL3HLT => "Level 3 halted",
            Self::EL3RST => "Level 3 reset",
            Self::ELNRNG => "Link number out of range",
            Self::EUNATCH => "Protocol driver not attached",
            Self::ENOCSI => "No CSI structure available",
            Self::EL2HLT => "Level 2 halted",
            Self::EBADE => "Invalid exchange",
            Self::EBADR => "Invalid request descriptor",
            Self::EXFULL => "Exchange full",
            Self::ENOANO => "No anode",
            Self::EBADRQC => "Invalid request code",
            Self::EBADSLT => "Invalid slot",
            Self::EDEADLOCK => "File locking deadlock error",
            Self::EBFONT => "Bad font file format",
            Self::ELIBEXEC => "Cannot exec a shared library directly",
            Self::ENODATA => "No data available",
            Self::ELIBBAD => "Accessing a corrupted shared library",
            Self::ENOPKG => "Package not installed",
            Self::ELIBACC => "Can not access a needed shared library",
            Self::ENOTUNIQ => "Name not unique on network",
            Self::ERESTART => "Interrupted syscall should be restarted",
            Self::EUCLEAN => "Structure needs cleaning",
            Self::ENOTNAM => "Not a XENIX named type file",
            Self::ENAVAIL => "No XENIX semaphores available",
            Self::EISNAM => "Is a named type file",
            Self::EREMOTEIO => "Remote I/O error",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ELIBMAX => "Atmpt to link in too many shared libs",
            Self::ELIBSCN => ".lib section in a.out corrupted",
            Self::ENOMEDIUM => "No medium found",
            Self::EMEDIUMTYPE => "Wrong medium type",
            Self::ECANCELED => "Operation Cancelled",
            Self::ENOKEY => "Required key not available",
            Self::EKEYEXPIRED => "Key has expired",
            Self::EKEYREVOKED => "Key has been revoked",
            Self::EKEYREJECTED => "Key was rejected by service",
            Self::EOWNERDEAD => "Owner died",
            Self::ENOTRECOVERABLE => "State not recoverable",
            Self::ERFKILL => "Operation not possible due to RF-kill",
            Self::EHWPOISON => "Memory page has hardware error",
        })
    }
}
#[cfg(target_os = "macos")]
impl Display for Errno {
    #[expect(clippy::too_many_lines, reason = "large match expression")]
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "Input/output error",
            Self::ENXIO => "Device not configured",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file descriptor",
            Self::ECHILD => "No child processes",
            Self::EDEADLK => "Resource deadlock avoided",
            Self::ENOMEM => "Cannot allocate memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device / Resource busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "Operation not supported by device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "Too many open files in system",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Inappropriate ioctl for device",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only file system",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Numerical argument out of domain",
            Self::ERANGE => "Result too large",
            Self::EWOULDBLOCK => "Operation would block",
            Self::EINPROGRESS => "Operation now in progress",
            Self::EALREADY => "Operation already in progress",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::ENOTSUP | Self::EOPNOTSUPP => "Operation not supported on socket",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol family",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Can't assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Network dropped connection on reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Socket is already connected",
            Self::ENOTCONN => "Socket is not connected",
            Self::ESHUTDOWN => "Can't send after socket shutdown",
            Self::ETOOMANYREFS => "Too many references: can't splice",
            Self::ETIMEDOUT => "Operation timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::ELOOP => "Too many levels of symbolic links",
            Self::ENAMETOOLONG => "File name too long",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::ENOTEMPTY => "Directory not empty",
            Self::EPROCLIM => "Too many processes",
            Self::EUSERS => "Too many users",
            Self::EDQUOT => "Disc quota exceeded",
            Self::ESTALE => "Stale NFS file handle",
            Self::EREMOTE => "Too many levels of remote in path",
            Self::EBADRPC => "RPC struct is bad",
            Self::ERPCMISMATCH => "RPC version wrong",
            Self::EPROGUNAVAIL => "RPC prog. not avail",
            Self::EPROGMISMATCH => "Program version wrong",
            Self::EPROCUNAVAIL => "Bad procedure for program",
            Self::ENOLCK => "No locks available",
            Self::ENOSYS => "Function not implemented",
            Self::EFTYPE => "Inappropriate file type or format",
            Self::EAUTH => "Authentication error",
            Self::ENEEDAUTH => "Need authenticator",
            Self::EPWROFF => "Device power is off",
            Self::EDEVERR => "Device error, e.g. paper out",
            Self::EOVERFLOW => "Value too large to be stored in data type",
            Self::EBADEXEC => "Bad executable",
            Self::EBADARCH => "Bad CPU type in executable",
            Self::ESHLIBVERS => "Shared library version mismatch",
            Self::EBADMACHO => "Malformed Macho file",
            Self::ECANCELED => "Operation canceled",
            Self::EIDRM => "Identifier removed",
            Self::ENOMSG => "No message of desired type",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ENOATTR => "Attribute not found",
            Self::EBADMSG => "Bad message",
            Self::EMULTIHOP | Self::ENOLINK => "Reserved",
            Self::ENODATA => "No message available on STREAM",
            Self::ENOSR => "No STREAM resources",
            Self::ENOSTR => "Not a STREAM",
            Self::EPROTO => "Protocol error",
            Self::ETIME => "STREAM ioctl timeout",
            Self::ENOPOLICY => "No such policy registered",
            Self::ENOTRECOVERABLE => "State not recoverable",
            Self::EOWNERDEAD => "Previous owner died",
            Self::EQFULL => "Interface output queue is full",
            Self::ENOTCAPABLE => "Capabilities insufficient",
        })
    }
}
#[cfg(target_os = "netbsd")]
impl Display for Errno {
    #[expect(clippy::too_many_lines, reason = "large match expression")]
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "Input/output error",
            Self::ENXIO => "Device not configured",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file descriptor",
            Self::ECHILD => "No child processes",
            Self::EDEADLK => "Resource deadlock avoided",
            Self::ENOMEM => "Cannot allocate memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "Operation not supported by device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "Too many open files in system",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Inappropriate ioctl for device",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only file system",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Numerical argument out of domain",
            Self::ERANGE => "Result too large or too small",
            Self::EWOULDBLOCK => "Operation would block",
            Self::EINPROGRESS => "Operation now in progress",
            Self::EALREADY => "Operation already in progress",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol option not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::EOPNOTSUPP => "Operation not supported",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol family",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Can't assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Network dropped connection on reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Socket is already connected",
            Self::ENOTCONN => "Socket is not connected",
            Self::ESHUTDOWN => "Can't send after socket shutdown",
            Self::ETOOMANYREFS => "Too many references: can't splice",
            Self::ETIMEDOUT => "Operation timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::ELOOP => "Too many levels of symbolic links",
            Self::ENAMETOOLONG => "File name too long",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::ENOTEMPTY => "Directory not empty",
            Self::EPROCLIM => "Too many processes",
            Self::EUSERS => "Too many users",
            Self::EDQUOT => "Disc quota exceeded",
            Self::ESTALE => "Stale NFS file handle",
            Self::EREMOTE => "Too many levels of remote in path",
            Self::EBADRPC => "RPC struct is bad",
            Self::ERPCMISMATCH => "RPC version wrong",
            Self::EPROGUNAVAIL => "RPC prog. not avail",
            Self::EPROGMISMATCH => "Program version wrong",
            Self::EPROCUNAVAIL => "Bad procedure for program",
            Self::ENOLCK => "No locks available",
            Self::ENOSYS => "Function not implemented",
            Self::EFTYPE => "Inappropriate file type or format",
            Self::EAUTH => "Authentication error",
            Self::ENEEDAUTH => "Need authenticator",
            Self::EIDRM => "Identifier removed",
            Self::ENOMSG => "No message of desired type",
            Self::EOVERFLOW => "Value too large to be stored in data type",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ENOTSUP => "Not supported",
            Self::ECANCELED => "Operation canceled",
            Self::EBADMSG => "Bad or Corrupt message",
            Self::ENODATA => "No message available",
            Self::ENOSR => "No STREAM resources",
            Self::ENOSTR => "Not a STREAM",
            Self::ETIME => "STREAM ioctl timeout",
            Self::ENOATTR => "Attribute not found",
            Self::EMULTIHOP => "Multihop attempted",
            Self::ENOLINK => "Link has been severed",
            Self::EPROTO => "Protocol error",
            Self::EOWNERDEAD => "Previous owner died",
            Self::ENOTRECOVERABLE => "State not recoverable",
        })
    }
}
#[cfg(target_os = "openbsd")]
impl Display for Errno {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Other => "Unknown error",
            Self::EPERM => "Operation not permitted",
            Self::ENOENT => "No such file or directory",
            Self::ESRCH => "No such process",
            Self::EINTR => "Interrupted system call",
            Self::EIO => "Input/output error",
            Self::ENXIO => "Device not configured",
            Self::E2BIG => "Argument list too long",
            Self::ENOEXEC => "Exec format error",
            Self::EBADF => "Bad file descriptor",
            Self::ECHILD => "No child processes",
            Self::EDEADLK => "Resource deadlock avoided",
            Self::ENOMEM => "Cannot allocate memory",
            Self::EACCES => "Permission denied",
            Self::EFAULT => "Bad address",
            Self::ENOTBLK => "Block device required",
            Self::EBUSY => "Device busy",
            Self::EEXIST => "File exists",
            Self::EXDEV => "Cross-device link",
            Self::ENODEV => "Operation not supported by device",
            Self::ENOTDIR => "Not a directory",
            Self::EISDIR => "Is a directory",
            Self::EINVAL => "Invalid argument",
            Self::ENFILE => "Too many open files in system",
            Self::EMFILE => "Too many open files",
            Self::ENOTTY => "Inappropriate ioctl for device",
            Self::ETXTBSY => "Text file busy",
            Self::EFBIG => "File too large",
            Self::ENOSPC => "No space left on device",
            Self::ESPIPE => "Illegal seek",
            Self::EROFS => "Read-only file system",
            Self::EMLINK => "Too many links",
            Self::EPIPE => "Broken pipe",
            Self::EDOM => "Numerical argument out of domain",
            Self::ERANGE => "Result too large",
            Self::EWOULDBLOCK => "Operation would block",
            Self::EINPROGRESS => "Operation now in progress",
            Self::EALREADY => "Operation already in progress",
            Self::ENOTSOCK => "Socket operation on non-socket",
            Self::EDESTADDRREQ => "Destination address required",
            Self::EMSGSIZE => "Message too long",
            Self::EPROTOTYPE => "Protocol wrong type for socket",
            Self::ENOPROTOOPT => "Protocol not available",
            Self::EPROTONOSUPPORT => "Protocol not supported",
            Self::ESOCKTNOSUPPORT => "Socket type not supported",
            Self::EOPNOTSUPP => "Operation not supported",
            Self::EPFNOSUPPORT => "Protocol family not supported",
            Self::EAFNOSUPPORT => "Address family not supported by protocol family",
            Self::EADDRINUSE => "Address already in use",
            Self::EADDRNOTAVAIL => "Can't assign requested address",
            Self::ENETDOWN => "Network is down",
            Self::ENETUNREACH => "Network is unreachable",
            Self::ENETRESET => "Network dropped connection on reset",
            Self::ECONNABORTED => "Software caused connection abort",
            Self::ECONNRESET => "Connection reset by peer",
            Self::ENOBUFS => "No buffer space available",
            Self::EISCONN => "Socket is already connected",
            Self::ENOTCONN => "Socket is not connected",
            Self::ESHUTDOWN => "Can't send after socket shutdown",
            Self::ETOOMANYREFS => "Too many references: can't splice",
            Self::ETIMEDOUT => "Operation timed out",
            Self::ECONNREFUSED => "Connection refused",
            Self::ELOOP => "Too many levels of symbolic links",
            Self::ENAMETOOLONG => "File name too long",
            Self::EHOSTDOWN => "Host is down",
            Self::EHOSTUNREACH => "No route to host",
            Self::ENOTEMPTY => "Directory not empty",
            Self::EPROCLIM => "Too many processes",
            Self::EUSERS => "Too many users",
            Self::EDQUOT => "Disk quota exceeded",
            Self::ESTALE => "Stale NFS file handle",
            Self::EREMOTE => "Too many levels of remote in path",
            Self::EBADRPC => "RPC struct is bad",
            Self::ERPCMISMATCH => "RPC version wrong",
            Self::EPROGUNAVAIL => "RPC program not available",
            Self::EPROGMISMATCH => "Program version wrong",
            Self::EPROCUNAVAIL => "Bad procedure for program",
            Self::ENOLCK => "No locks available",
            Self::ENOSYS => "Function not implemented",
            Self::EFTYPE => "Inappropriate file type or format",
            Self::EAUTH => "Authentication error",
            Self::ENEEDAUTH => "Need authenticator",
            Self::EIPSEC => "IPsec processing failure",
            Self::ENOATTR => "Attribute not found",
            Self::EILSEQ => "Illegal byte sequence",
            Self::ENOMEDIUM => "No medium found",
            Self::EMEDIUMTYPE => "Wrong medium type",
            Self::EOVERFLOW => "Value too large to be stored in data type",
            Self::ECANCELED => "Operation canceled",
            Self::EIDRM => "Identifier removed",
            Self::ENOMSG => "No message of desired type",
            Self::ENOTSUP => "Not supported",
            Self::EBADMSG => "Bad message",
            Self::ENOTRECOVERABLE => "State not recoverable",
            Self::EOWNERDEAD => "Previous owner died",
            Self::EPROTO => "Protocol error",
        })
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl From<Errno> for StdErr {
    #[inline]
    fn from(value: Errno) -> Self {
        // We only support platforms where `errno` is a `c_int` and `c_int` is an `i32`. This won't compile if one
        // of those isn't true.
        Self::from_raw_os_error(value.into_raw())
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl TryFrom<StdErr> for Errno {
    type Error = StdErr;
    #[inline]
    fn try_from(value: StdErr) -> Result<Self, Self::Error> {
        // We only support platforms where `errno` is a `c_int` and `c_int` is an `i32`. This won't compile if one
        // of those isn't true.
        value.raw_os_error().ok_or(value).map(Self::from_raw)
    }
}
