# Rust OpenBSD

Rust bindings for the security facilities that are unique to
[OpenBSD](https://www.openbsd.org/), plus the privilege-separation practice
common to OpenBSD daemons.

The crate can only be built and used on OpenBSD; it fails at compile time on
other platforms.

## What's implemented

| Facility | Module | Restricts/provides |
| --- | --- | --- |
| [`pledge(2)`](https://man.openbsd.org/pledge.2) | [`pledge`](https://docs.rs/rust-openbsd/latest/rust_openbsd/pledge/index.html) | which system operations the process may perform |
| [`unveil(2)`](https://man.openbsd.org/unveil.2) | [`unveil`](https://docs.rs/rust-openbsd/latest/rust_openbsd/unveil/index.html) | which filesystem paths the process may access |
| Privilege dropping | [`privileges`](https://docs.rs/rust-openbsd/latest/rust_openbsd/privileges/index.html) | the credentials (UID/GID/groups) of the process |
| [`chroot(2)`](https://man.openbsd.org/chroot.2) | [`chroot`](https://docs.rs/rust-openbsd/latest/rust_openbsd/chroot/index.html) | the filesystem root for pathname resolution |
| [`issetugid(2)`](https://man.openbsd.org/issetugid.2), [`getpeereid(3)`](https://man.openbsd.org/getpeereid.3) | [`credentials`](https://docs.rs/rust-openbsd/latest/rust_openbsd/credentials/index.html) | set-ID execution taint; Unix-domain peer credentials |
| [`setproctitle(3)`](https://man.openbsd.org/setproctitle.3), daemonization | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | process titles; background detachment |
| [`arc4random(3)`](https://man.openbsd.org/arc4random.3), [`getentropy(2)`](https://man.openbsd.org/getentropy.2) | [`random`](https://docs.rs/rust-openbsd/latest/rust_openbsd/random/index.html) | cryptographically strong random values; kernel entropy |
| [`getrtable(2)`](https://man.openbsd.org/getrtable.2), [`setrtable(2)`](https://man.openbsd.org/setrtable.2) | [`rtable`](https://docs.rs/rust-openbsd/latest/rust_openbsd/rtable/index.html) | routing domains |
| [`mimmutable(2)`](https://man.openbsd.org/mimmutable.2), [`explicit_bzero(3)`](https://man.openbsd.org/explicit_bzero.3), [`freezero(3)`](https://man.openbsd.org/freezero.3), [`timingsafe_bcmp(3)`](https://man.openbsd.org/timingsafe_bcmp.3), [`timingsafe_memcmp(3)`](https://man.openbsd.org/timingsafe_memcmp.3) | [`memory`](https://docs.rs/rust-openbsd/latest/rust_openbsd/memory/index.html) | memory protection, secure erasure, constant-time comparison |
| [`crypt_checkpass(3)`](https://man.openbsd.org/crypt_checkpass.3), [`crypt_newhash(3)`](https://man.openbsd.org/crypt_newhash.3), [`bcrypt_pbkdf(3)`](https://man.openbsd.org/bcrypt_pbkdf.3) | [`authentication`](https://docs.rs/rust-openbsd/latest/rust_openbsd/authentication/index.html) | password hashing and key derivation |
| [`closefrom(2)`](https://man.openbsd.org/closefrom.2), [`getdtablecount(2)`](https://man.openbsd.org/getdtablecount.2), [`setprogname(3)`](https://man.openbsd.org/setprogname.3) | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | descriptor hygiene; program name |
| [`getexecpath(3)`](https://man.openbsd.org/getexecpath.3) *(OpenBSD 8.0)* | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | canonical pathname of the running executable |

These mechanisms restrict *different dimensions* of process authority and are
normally complementary: a typical OpenBSD daemon uses several of them. They are
not interchangeable.

## pledge

[`pledge(2)`](https://man.openbsd.org/pledge.2) partitions the POSIX feature set
into subsystems called *promises*. After a `pledge()` call, using an operation
outside the declared promises aborts the process with an uncatchable `SIGABRT`.

```rust
use rust_openbsd::{pledge, Promise, Promises};

fn main() -> Result<(), rust_openbsd::Errno> {
    // privileged initialization (bind sockets, open logs, ...)
    pledge(&Promises::new([Promise::Stdio, Promise::Rpath, Promise::Inet, Promise::Dns]))?;
    // main loop: any other operation now aborts the process
    serve();
    Ok(())
}

fn serve() {}
```

Calls are monotonic: a later call may only *reduce* the promise set. An attempt
to increase it fails with [`Errno::EPERM`]. Once a promise has been removed it
can never be regained.

### Exec promises

The second argument of `pledge(2)` restricts programs executed later via
`execve(2)`:

```rust
use rust_openbsd::{pledge_both, pledge_child, Promise, Promises};

fn main() -> Result<(), rust_openbsd::Errno> {
    // Children may only use stdio. Legacy kernels require Exec to execute.
    let current = Promises::new([Promise::Stdio, Promise::Rpath, Promise::Proc]);
    #[cfg(not(feature = "openbsd-8-0"))]
    let current = current.with(Promise::Exec);
    pledge_both(
        &current,
        &Promises::new([Promise::Stdio]),
    )?;

    // or set the exec promises only, leaving the current process alone
    pledge_child(&Promises::new([Promise::Stdio]))?;
    Ok(())
}
```

A child that is started with exec promises in place runs pledged from its first
instruction, unless the executed file has setuid/setgid bits, in which case
execution is blocked with `EACCES`.

### `NULL` versus empty string

`pledge_parts` is the full typed interface to
`int pledge(const char *promises, const char *execpromises)`:

| Argument | Value | Meaning |
| --- | --- | --- |
| `promises` | `None` | `NULL` — do not change this value |
| `promises` | `Some(&Promises::NONE)` | `""` — restrict to `_exit(2)` only |
| `promises` | `Some(set)` | set this value to `set` |

The same mapping applies to `execpromises`, with one important difference in
wording: `Some(&Promises::NONE)` there means that *future executed programs*
start with no promises (the `_exit(2)`-only state), not that the current process
becomes `_exit`-only. `pledge`, `pledge_child`, and `pledge_both` are
conveniences over `pledge_parts`; `pledge_raw` exposes the raw
`Option<&CStr>` form.

### Forking and pledge

The supported model for a fork/exec child is to configure the exec-promise
ceiling in the parent and then exec:

```text
parent
    -> pledge_child(child_promises)     (exec ceiling, parent-side)
    -> fork(2) + execve                (the child does nothing else)
    -> the new image starts under child_promises
```

OpenBSD copies the exec-promise state across `fork(2)` and applies it when a
descendant executes a new image, so the child needs no pledge call of its own.
`fork_exec_pledged` implements exactly this pattern; `exec_pledged` replaces the
current image under an exec ceiling. Plain `fork_exec` sets no policy of its
own, and none of these helpers run crate code in the post-fork child.

Do not apply major current-process pledge reductions in a live multithreaded
child. Reducing the current promise set to an extreme restriction (in
particular [`pledge`] with an empty promise set, the `_exit(2)`-only state) makes
the kernel unwind sibling runtime threads while cleaning up unveil state, and
the resumed threads then perform syscalls forbidden by the fresh restriction, so
the kernel aborts the process. The empty promise set is valid OpenBSD and is
verified by a single-threaded native probe in the test suite.

Setting exec promises in the parent is monotonic and affects every future exec
from that process and its descendants: use it when those descendants share a
common promise ceiling. Independent per-child policies require a fresh-process
boundary (for example a minimal native launcher), which this crate does not
provide.

### Notes

* Without `openbsd-8-0`, the [`Promise::Error`] promise changes violations
  from aborting the process to returning `ENOSYS`; promise increases are
  then silently ignored.
* The `tmppath` promise has been removed from OpenBSD (`pledge(2)` returns
  `EINVAL` for it) and is deliberately not exposed. Use `rpath`, `wpath`, and
  `cpath` together with an `unveil` rule instead.
* The [`Promise`] enumeration matches the promise list accepted by the kernel on
  OpenBSD 7.9; the OpenBSD 8.0 option excludes `exec` and `error`.

With `openbsd-8-0` enabled, the typed pledge inventory excludes `exec` and
`error`. Without that option, both legacy promises remain available. Raw
pledge interfaces continue to pass strings to the kernel without filtering.

Excluding these names from the typed API is a crate-level decision; it does not
establish that the target kernel rejects or accepts them. Verify the target
kernel's promise table before relying on either behavior. On kernels that
require `exec`, a process pledged without it cannot execute another program;
use `pledge_raw` if the name must be passed through. The execution-promises
examples require that kernel capability and are not a replacement for it.


## unveil

[`unveil(2)`](https://man.openbsd.org/unveil.2) restricts the filesystem view of
the process. The first call removes visibility of the entire filesystem except
for explicitly unveiled paths.

```rust
use rust_openbsd::{unveil_and_lock, Permission, Permissions};

fn main() -> Result<(), rust_openbsd::Errno> {
    let read = Permissions::READ;
    let read_write_create = Permissions::READ
        .enable(Permission::Write)
        .enable(Permission::Create);

    unveil_and_lock([
        ("/", read),
        ("/var/www", read),
        ("/var/log/myapp", read_write_create),
    ])?;
    Ok(())
}
```

* [`unveil`] adds a single rule.
* [`unveil_paths`] adds several rules.
* [`lock_unveil`] is `unveil(NULL, NULL)`: it permanently locks the
  configuration. OpenBSD strongly recommends locking unveil once all rules are
  installed; after locking, further `unveil` calls fail with `EPERM`.
* [`unveil_and_lock`] installs the rules and locks.

Permissions are `r`, `w`, `x`, `c` ([`Permission::Read`], [`Permission::Write`],
[`Permission::Execute`], [`Permission::Create`]). The empty permission set is
valid and unveils a path without permitting any operation on it. Paths are
accepted through [`CStrHelper`], so they may be `Path`, `OsStr`, `str`, or raw
byte slices and need not be valid UTF-8; interior NUL bytes are rejected. A
later call for a path that is already unveiled replaces that path's permissions;
unlike pledge promises, unveil permissions are not monotonic and may be both
widened and narrowed.

If the process is pledged, `unveil(2)` itself requires the `unveil` promise.
Conversely, a `pledge(2)` call that removes all path-accessing promises destroys
the unveil state.

## Privilege dropping

[`privileges`] implements the privilege-dropping sequence used by OpenBSD
base-system daemons such as [`httpd(8)`](https://man.openbsd.org/httpd.8),
[`unwind(8)`](https://man.openbsd.org/unwind.8), and
[`smtpd(8)`](https://man.openbsd.org/smtpd.8):

1. resolve the target account while still privileged;
2. reduce supplementary groups while still privileged;
3. drop the real, effective, and saved GIDs (`setresgid(2)`);
4. drop the real, effective, and saved UIDs last (`setresuid(2)`).

This ordering matters: `setgroups(2)` requires privilege, and once root is gone
the saved IDs must not allow the process to regain it.

```rust
use rust_openbsd::drop_privileges;

fn main() -> Result<(), rust_openbsd::PrivDropError> {
    // privileged initialization
    drop_privileges("_mydaemon")?;
    // irreversibly unprivileged from here on
    Ok(())
}
```

[`drop_privileges`] resolves the account to its UID and primary GID and drops all
three UID and GID flavors to those values. By default it replaces the
supplementary group list with *only* the primary GID (`setgroups(1, &gid)`),
which is the restrictive daemon-style behaviour and never accidentally retains
root's supplementary groups; this policy is [`GroupPolicy::PrimaryGroupOnly`].

[`drop_privileges_with`] takes an explicit [`GroupPolicy`]:
[`GroupPolicy::Initgroups`] adopts all supplementary groups of the account via
`initgroups(3)` instead; this is login-style behaviour for processes that
genuinely need the account's group memberships. [`account_by_name`] resolves a
user to an [`Account`], and [`drop_privileges_to`] applies either policy to an
account resolved earlier, which is useful when the account must be looked up
before `chroot(2)` hides the password database. [`drop_supplementary_groups`]
is the explicit `setgroups(0, NULL)` helper.

After the drop, the library verifies that the real, effective, and saved
UIDs/GIDs are the expected values. For
[`GroupPolicy::PrimaryGroupOnly`] it also verifies that the supplementary group
list is exactly the primary GID; for [`GroupPolicy::Initgroups`] it compares the
observed list with the membership reported by `getgrouplist(3)`, ignoring order.
On failure the library returns a [`PrivDropError`] naming the failing step; each
step's error preserves the underlying [`Errno`] where one exists (typically
`EPERM` if the process is not root). After a partial failure the process may
already have reduced privileges, so callers must treat any error as fatal for the
current process.

[`drop_privileges`] and [`drop_privileges_with`] refuse an account whose UID is
root **or whose primary GID is root**. [`drop_privileges_to`] is the mechanism
form and deliberately does not apply that policy.

### Why not `setusercontext(3)`?

`setusercontext(3)` applies a full login class from
[`login.conf(5)`](https://man.openbsd.org/login.conf.5) (resource limits, umask,
priority, environment, `initgroups(3)`, ...). OpenBSD uses it in login programs
such as [`login(1)`](https://man.openbsd.org/login.1) and
[`su(1)`](https://man.openbsd.org/su.1); native daemons deliberately do not use
it for privilege separation — they perform the explicit sequence above. This
crate therefore binds the explicit sequence and leaves login-session management
to `setusercontext(3)` users.

## Interaction between pledge and privilege dropping

The `id` pledge promise covers the identity-changing calls (`setuid`, `seteuid`,
`setreuid`, `setresuid`, `setgid`, `setegid`, `setregid`, `setresgid`,
`setgroups`), and the `getpw` promise is needed to resolve account names. An
application that pledges before dropping privileges must keep `id` (and `getpw`
for name resolution) until the drop is complete, then pledge again without them:

```text
start privileged
    |
    +-- resolve the destination account (account_by_name) while passwd(5) is reachable
    |
    +-- perform privileged initialization
    |
    +-- chroot / enter_chroot, if wanted (before pledge)
    |
    +-- pledge including "id" and "getpw" if pledge is already enabled
    |
    +-- drop privileges (drop_privileges_to with the resolved account after chroot)
    |
    +-- pledge again without "id" and "getpw"
    |
    +-- continue as unprivileged process
```

Resolve the account before the chroot: `drop_privileges` and
`account_by_name` read the password database, which the new root may not contain.
`GroupPolicy::Initgroups` also reads the group database at drop time; after a
chroot that does not provide it, use `GroupPolicy::PrimaryGroupOnly` or drop
before entering the new root.

```rust
use rust_openbsd::{drop_privileges, pledge, Promise, Promises};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pledge(&Promises::new([
        Promise::Stdio,
        Promise::Rpath,
        Promise::Getpw,
        Promise::Id,
    ]))?;
    drop_privileges("_mydaemon")?;
    pledge(&Promises::new([Promise::Stdio, Promise::Rpath]))?;
    Ok(())
}
```

This crate never adds promises behind the application's back.

## Complete example

A daemon combining all three mechanisms:

```rust
use rust_openbsd::{
    drop_privileges, pledge, unveil_and_lock, Permission, Permissions, Promise, Promises,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. privileged initialization: bind port 80, open log files,
    //    parse configuration, resolve the target account

    // 2. restrict the filesystem view
    unveil_and_lock([
        ("/", Permissions::READ.enable(Permission::Execute)),
        ("/var/www", Permissions::READ),
        (
            "/var/log/myapp",
            Permissions::READ
                .enable(Permission::Write)
                .enable(Permission::Create),
        ),
    ])?;

    // 3. restrict system calls, keeping what the drop still needs
    pledge(&Promises::new([
        Promise::Stdio,
        Promise::Rpath,
        Promise::Inet,
        Promise::Unix,
        Promise::Getpw,
        Promise::Id,
    ]))?;

    // 4. drop credentials irreversibly
    drop_privileges("_mydaemon")?;

    // 5. remove the identity-changing promises
    pledge(&Promises::new([
        Promise::Stdio,
        Promise::Rpath,
        Promise::Inet,
        Promise::Unix,
    ]))?;

    // 6. main service loop
    serve();
    Ok(())
}

fn serve() {}
```

## Errors

* Failing `pledge(2)`, `unveil(2)`, `chroot(2)`, and `rtable` calls return
  [`Errno`], the error reported by the kernel (`EPERM`, `EINVAL`, `ENOENT`, ...).
* `pledge(2)` violations do not return an error: the kernel aborts the process
  with an uncatchable `SIGABRT` unless the `error` promise is active.
* `unveil(2)` denials surface later as `EACCES`/`ENOENT` errors at the filesystem
  call site.
* Strings and paths converted through [`CStrHelper`] must not contain embedded
  `NUL` bytes; the library rejects them explicitly instead of letting C string
  conversion truncate them. `bcrypt_pbkdf` and `bcrypt_pbkdf_into` are
  length-delimited byte-string APIs and accept `NUL` bytes by design.
* With the `std` feature, [`Errno`] converts to [`std::io::Error`] infallibly;
  the reverse conversion is a lossy `TryFrom` that rejects errors without a raw
  OS code and maps unknown codes to `Errno::Other`.

## chroot

[`chroot`] binds `chroot(2)`:

```rust
use rust_openbsd::enter_chroot;

fn main() -> Result<(), rust_openbsd::Errno> {
    enter_chroot("/var/empty")?;   // chroot(path) followed by chdir("/")
    Ok(())
}
```

* [`chroot`] is the exact native call: it changes pathname resolution but does
  not change the working directory.
* [`enter_chroot`] performs `chroot(path)` then `chdir("/")` as one fail-closed
  transition — the recommended security-sensitive form.

`chroot(2)` is not a complete sandbox: it requires root, does not replace
pledge/unveil/privilege dropping, cannot confine an already-root process
reliably, and open descriptors keep access to resources outside the new root. It
is not permitted at all once the process has called `pledge(2)`, so chroot
before pledging. Resolve the account to which privileges will later be dropped
*before* entering the new root, because the password database may no longer be
reachable; `Account` is inline and `Copy`, so it can be passed to
`drop_privileges_to` afterward.

## Credentials

[`credentials`] provides two credential queries:

```rust
use std::os::fd::AsRawFd;

use rust_openbsd::{get_peer_credentials, is_setugid};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tainted = is_setugid(); // issetugid(2)

    let (client, _server) = std::os::unix::net::UnixStream::pair()?;
    let (uid, gid) = get_peer_credentials(client.as_raw_fd())?; // getpeereid(3)
    let _ = (tainted, uid, gid);
    Ok(())
}
```

`is_setugid` reports whether the process image was tainted by set-ID execution
(or by exec while real/effective/saved IDs were mismatched). It is not a UID/GID
comparison and is not affected by later ID changes.

`get_peer_credentials` returns the effective UID and GID of the peer of a
connected Unix-domain `SOCK_STREAM`/`SOCK_SEQPACKET` socket. It supplies facts
for an authorization decision; it is not authentication by itself.
`getpeereid(3)` is implemented with `getsockopt(2)` (`SO_PEERCRED`), so on
current OpenBSD it needs the `stdio` promise plus one of `unix`, `inet`, or
`dns`; with only `stdio` it takes the pledge-violation path. Calling it before
pledging is the conservative, version-independent choice.

## Process titles and daemonization

The [`process`] module:

```rust
use rust_openbsd::{close_from, dtable_count, reset_proctitle, set_proctitle};

fn main() -> Result<(), rust_openbsd::Errno> {
    set_proctitle("mydaemon: serving")?; // setproctitle("%s", title)
    reset_proctitle(); // setproctitle(NULL)
    let open_descriptors = dtable_count(); // getdtablecount(2)
    close_from(3)?; // closefrom(2)
    let _ = open_descriptors;
    Ok(())
}
```

Titles are passed to `setproctitle(3)` only as data through a fixed `"%s"`
format literal, so user-controlled strings can never become format strings.
Titles are limited to [`PROCTITLE_MAX`] bytes and work under the `stdio` promise.
The native implementation performs the truncation; without the `alloc` feature,
`CStrHelper` rejects a title of 1024 bytes or more with `ERANGE` before the
native call instead of truncating it.

`set_progname` and `progname` expose `setprogname(3)`/`getprogname(3)`; the name
is stored by pointer by the native implementation, so `set_progname` requires a
`'static` reference.

`exec_pledged` sets the execution promises and then replaces the current image;
`fork_exec` and `fork_exec_pledged` spawn a child, the latter after setting the
promise ceiling in the parent. These build on [`std::process::Command`] and never
run crate code in the post-fork child. A `pre_exec` closure installed by the
caller is caller code and does run there, so it must also obey the post-fork
rules. If an exec helper fails after `pledge_child` succeeded, the execution
ceiling is not rolled back.

`daemonize` and `daemonize_with` detach from the controlling terminal, taking
[`DaemonOptions`] with positively named fields
([`DaemonOptions::change_directory_to_root`],
[`DaemonOptions::redirect_standard_streams`]) instead of the inverted
`nochdir`/`noclose` integers of `daemon(3)`. On success they do not return (the
parent exits and the body runs in the detached child); the single return path is
a failed `fork(2)`, reported as `Err`. Daemonization is explicit and never
automatic: foreground operation (preferred under modern service supervision such
as rc.d) is fully supported. This is the one raw-`fork(2)` facility in the
crate, and it documents the usual post-fork hazards: in a multithreaded process
only async-signal-safe operations are reliable in the child.

## Random

[`random`] binds the `arc4random(3)` family:

```rust
use rust_openbsd::{arc4_random, arc4_random_bytes, arc4_random_uniform, get_entropy};

fn main() -> Result<(), rust_openbsd::Errno> {
    let value = arc4_random(); // arc4random()
    let bytes = arc4_random_bytes(32); // arc4random_buf()
    let die = arc4_random_uniform(6); // arc4random_uniform(6)
    let mut entropy = [0u8; 256];
    get_entropy(&mut entropy)?; // getentropy(2), at most 256 bytes
    let _ = (value, bytes, die, entropy);
    Ok(())
}
```

Prefer [`arc4_random_uniform`] over `arc4_random() % n`: the native function
avoids modulo bias when the bound is not a power of two. The API name is
historical; the implementation is ChaCha20-based and re-seeded from
`getentropy(2)`. It works inside `chroot(2)` and under the `stdio` pledge
promise.

## Routing domains

[`rtable`] exposes OpenBSD routing domains, which isolate the routing state of a
process:

```rust
use rust_openbsd::{Rtable, get_rtable, set_rtable};

fn main() -> Result<(), rust_openbsd::Errno> {
    let current = get_rtable()?;
    if current == Rtable::DEFAULT {
        set_rtable(Rtable::new(0))?;
    }
    Ok(())
}
```

Reading the domain is allowed under the `stdio` promise; changing it requires
the `id` promise and, once the domain is non-zero, superuser privileges. These
are process-wide settings but not monotonic restrictions.

## Memory

[`memory`] provides the memory-handling extensions:

```rust
use rust_openbsd::{explicit_bzero, timingsafe_bcmp, timingsafe_memcmp};

fn main() {
    let mut secret = *b"hunter2";
    explicit_bzero(&mut secret); // explicit_bzero(3), not optimized away

    let equal = timingsafe_bcmp(b"hash-a", b"hash-b"); // constant-time equality
    let order = timingsafe_memcmp(b"hash-a", b"hash-b"); // constant-time ordering
    let _ = (equal, order);
}
```

[`mimmutable`] permanently forbids future changes to the protection or mapping
of a memory region. It is `unsafe`: the kernel rounds the range outward to whole
pages, so the caller must guarantee that every affected page belongs to a
dedicated mapping rather than an ordinary Rust allocation. Pages that are
unmapped at the time of the call are skipped and do not become immutable if they
are mapped later, and an empty slice is a no-op. Because the wrapper takes a
slice, a range containing an unmapped hole can only be exercised with the raw
syscall, not by constructing an invalid slice. [`freezero`] zeroes and releases
a `malloc(3)` allocation and is `unsafe` because ownership transfers to it; `len`
must not exceed the allocation size. The constant-time comparisons are the
recommended interfaces for comparing secrets such as hashes and MACs; do not
reimplement them with an early-exiting comparison.

## Authentication

[`authentication`] binds OpenBSD's password-hashing facilities:

```rust
use rust_openbsd::{bcrypt_pbkdf, crypt_checkpass, crypt_newhash};

fn main() -> Result<(), rust_openbsd::Errno> {
    let hash = crypt_newhash(&b"correct horse"[..], "bcrypt,4")?;
    assert!(crypt_checkpass(&b"correct horse"[..], hash.as_slice())?);

    let key = bcrypt_pbkdf(&b"password"[..], &b"salt"[..], /*rounds*/ 4, 32)?;
    let _ = key;
    Ok(())
}
```

These call OpenBSD's implementations directly; no cryptographic code lives in
this crate. `crypt_checkpass` and `crypt_newhash` pass their arguments through
`CStrHelper` and reject embedded `NUL` bytes rather than silently truncating
them; `bcrypt_pbkdf` and `bcrypt_pbkdf_into` are length-delimited and accept
`NUL` bytes. Passwords and hashes are never logged or embedded in error values.
Two unavoidable limitations of a managed runtime apply: the crate's own
`CStrHelper` conversion may leave a transient copy in a stack buffer or heap
`CString`, and password buffers cannot be guaranteed to be erased in place (use
[`explicit_bzero`] on explicit native buffers if that matters). The comparison
itself is performed by the native constant-time implementation.

## Scope

`rust-openbsd` provides Rust interfaces to useful OpenBSD-specific system and
library facilities that are not covered by the Rust standard library. General
POSIX functionality remains the responsibility of
[`std`](https://doc.rust-lang.org/stable/std/) and is reused rather than
rebound. See the coverage table below for the audited API surface and the
precise reasons behind deferred facilities.

The crate is a set of primitives, not a framework: it introduces no daemon, no
command-line interface, and no unrelated functionality.

## API coverage

| OpenBSD facility | Rust module | Status |
| --- | --- | --- |
| `pledge(2)` | [`pledge`](https://docs.rs/rust-openbsd/latest/rust_openbsd/pledge/index.html) | supported (typed promises, NULL/empty distinction, execpromises) |
| `unveil(2)` | [`unveil`](https://docs.rs/rust-openbsd/latest/rust_openbsd/unveil/index.html) | supported (rules, locking, empty permissions) |
| privilege dropping | [`privileges`](https://docs.rs/rust-openbsd/latest/rust_openbsd/privileges/index.html) | supported (daemon sequence, verification, two group policies) |
| `chroot(2)` | [`chroot`](https://docs.rs/rust-openbsd/latest/rust_openbsd/chroot/index.html) | supported (`chroot`, `enter_chroot`) |
| `issetugid(2)`, `getpeereid(3)` | [`credentials`](https://docs.rs/rust-openbsd/latest/rust_openbsd/credentials/index.html) | supported |
| `setproctitle(3)`, `getprogname(3)`/`setprogname(3)` | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | supported (format-safe) |
| `daemon(3)` | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | supported (`daemonize`, documented fork hazards) |
| fork/exec + execpromises | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | supported (`fork_exec`, `fork_exec_pledged`, `exec_pledged`) |
| `closefrom(2)`, `getdtablecount(2)` | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | supported |
| `getexecpath(3)` | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | supported behind the `openbsd-8-0` feature (first appeared in OpenBSD 8.0) |
| `arc4random(3)` family | [`random`](https://docs.rs/rust-openbsd/latest/rust_openbsd/random/index.html) | supported |
| `getentropy(2)` | [`random`](https://docs.rs/rust-openbsd/latest/rust_openbsd/random/index.html) | supported (native 256-byte limit) |
| `getrtable(2)`/`setrtable(2)` | [`rtable`](https://docs.rs/rust-openbsd/latest/rust_openbsd/rtable/index.html) | supported |
| `mimmutable(2)` | [`memory`](https://docs.rs/rust-openbsd/latest/rust_openbsd/memory/index.html) | supported (`unsafe`; the caller guarantees a dedicated mapping) |
| `explicit_bzero(3)`, `freezero(3)` | [`memory`](https://docs.rs/rust-openbsd/latest/rust_openbsd/memory/index.html) | supported (explicit native memory only) |
| `timingsafe_bcmp(3)`, `timingsafe_memcmp(3)` | [`memory`](https://docs.rs/rust-openbsd/latest/rust_openbsd/memory/index.html) | supported |
| `crypt_checkpass(3)`, `crypt_newhash(3)` | [`authentication`](https://docs.rs/rust-openbsd/latest/rust_openbsd/authentication/index.html) | supported |
| `bcrypt_pbkdf(3)` | [`authentication`](https://docs.rs/rust-openbsd/latest/rust_openbsd/authentication/index.html) | supported |
| `imsg(3)`/`ibuf(3)` | — | deferred: substantial IPC abstraction with descriptor-passing ownership; cannot be runtime-validated before shipping; `std` `sendmsg`/`recvmsg` with `SCM_RIGHTS` covers the primitive mechanism |
| `kqueue(2)`/`kevent(2)` | — | deferred: general event facility with existing ecosystem crates; not OpenBSD-security-specific |
| `setusercontext(3)`/`login_cap(3)` | — | deferred: login-session policy framework; the daemon privilege-drop sequence remains the supported policy |
| `pidfile(3)` | — | deferred: the only public OpenBSD API is `atexit`-based with `/var/run`-only naming, weaker than a few lines of explicit `std` code |
| `posix_spawn(3)` | — | deferred: no demonstrated need over the validated fork/exec architecture |
| `sysctl(2)` | — | deferred: broad surface better handled per use case |
| `fsync_range(2)`, `revoke(2)` | — | deferred: niche facilities with little demand from daemons |
| `getpwnam_shadow(3)` | — | deferred: `crypt_checkpass` covers authentication; direct shadow reads are niche |
| `readpassphrase(3)` | — | deferred: interactive tty handling, marginal for daemons |
| `reallocarray(3)`/`recallocarray(3)`, `strlcpy(3)`/`strlcat(3)`, `strtonum(3)`, `fmt_scaled(3)`, `fparseln(3)`, `ohash(3)`, `getbsize(3)`, `opendev(3)` | — | not useful from Rust: C allocation/parsing helpers with existing equivalents |
| `pinsyscalls(2)`, `kbind(2)`, `__tfork(2)`, `__thrsleep(2)`, `futex(2)`, `__get_tcb(2)`, `__pledge_open(2)`, `utrace(2)`, `syscall(2)` | — | internal kernel/libc interfaces, not application APIs |
| `skey(3)` | — | obsolete |

Facilities above are audited against OpenBSD 7.9, OpenBSD 8.0, and
OpenBSD-current; the CI matrix currently executes only on OpenBSD 8.0.

## Supported OpenBSD versions

* Targets **OpenBSD 7.9**, **OpenBSD 8.0**, and **OpenBSD-current**.
* Interfaces that first appeared in OpenBSD 8.0 are gated behind the
  `openbsd-8-0` Cargo feature, so the default build keeps working on 7.9.
* The typed pledge inventory has 35 promises by default and 33 with
  `openbsd-8-0`, which excludes the legacy `exec` and `error` names. The
  kernel's own `pledgereq` table is version-dependent: verify it for the target
  kernel (see
  [`sys/kern/kern_pledge.c`](https://github.com/openbsd/src/blob/master/sys/kern/kern_pledge.c))
  instead of assuming that a name is accepted or rejected. `tmppath` is removed
  from current kernels and is deliberately not exposed; `disklabel`, `drm`, and
  `vmm` are included.
* Unveil permissions were verified against `sys/kern/kern_unveil.c`:
  `r`, `w`, `x`, `c`, with the empty permission set valid.
* The [`Errno`] values were verified against `sys/sys/errno.h`: valid codes are
  `1..=95` (`EPROTO` is `ELAST`).
* Login-name and group limits are taken from OpenBSD's `LOGIN_NAME_MAX` (32) and
  `NGROUPS_MAX` (16). The Rust constants are `LOGIN_NAME_MAX`, `NGROUPS_MAX`,
  `PASSWORD_LEN` (128, the native `_PASSWORD_LEN`), `PROCTITLE_MAX` (2048, the
  native `MAX_PROCTITLE`), `PATH_MAX` (1024), and `MAX_ENTROPY` (256).

### Language standards

The language baseline is declared explicitly in `Cargo.toml`, so the build does
not depend on the compiler default:

* **Rust 2024 edition**, with a minimum supported Rust version of **1.85.0**, the
  edition-2024 minimum. Upstream `priv_sep` declared a newer MSRV that does not
  exist on OpenBSD 7.9, which ships Rust 1.94.1.
* No C shim is used. The only variadic native interfaces,
  `setproctitle(3)` and `open(2)`, are called through Rust's variadic FFI with
  fixed literals, so building the crate is pure Rust and needs no C compiler.
  The test suite optionally compiles small C probes at test time (see
  [Testing](#testing)); a missing `cc` makes those tests skip, it does not
  affect the library build.

### Cargo features

The crate is `no_std` and has no dependencies. `alloc` adds the functions that
return owned buffers and lets `CStrHelper` convert inputs of 1024 bytes or more
through a heap `CString`; `std` (the default, and implying `alloc`) adds the exec
helpers built on [`std::process::Command`] and the [`Errno`]/[`std::io::Error`]
conversions. Everything else, including pledge, unveil, and privilege dropping,
works without either, subject to the 1023-byte `CStrHelper` input limit when
`alloc` is disabled.

`openbsd-8-0` (off by default) adds the interfaces that first appeared in
OpenBSD 8.0 — currently `getexecpath(3)` via [`get_execpath`] — whose symbols do
not exist in 7.9's libc. Enabling it makes the crate require OpenBSD 8.0 or
later, and removes the legacy `Promise::Exec` and `Promise::Error` variants from
the typed inventory.

## Testing

```console
cargo test --all-features   # on OpenBSD 8.0
cargo test                  # on OpenBSD 7.9, or when omitting the 8.0 API
```

Runtime tests exercise the real kernel interfaces in process-isolated child
programs (the test binary is re-executed with `--exact --ignored`). Tests that
require root (privilege dropping, the `id`-promise lifecycle, and the
`enter_chroot` confinement test) are skipped cleanly when the test runner is not
root; tests that must not run as root (the unprivileged `chroot`, unprivileged
drop, and `rtable` cases) skip with a different message when it is. Some pledge
tests expect the child process to die with `SIGABRT`, which is normal and part of
the test; they inspect the child's termination status instead of letting the
suite crash. The `_exit`-only (empty promise set) state and the exec-promise
probes are verified by small single-threaded C programs compiled at test time,
skipped when `cc` cannot be started or fails to compile/link.

The integration tests compile Rust code that uses the default feature set, so
`cargo test --no-default-features` is not a supported test configuration; the
feature combinations without `std`/`alloc` are build-checked instead.

The descriptor and credential contracts (`closefrom(2)` error behavior and
`getpeereid(3)` under different promise sets), the `mimmutable(2)` hole
behavior, and the `Initgroups` membership comparison are covered by isolated
kernel tests. CI executes them on OpenBSD 8.0 for amd64 and arm64; OpenBSD 7.9 is
not in the matrix and must be checked manually on that release.

## Continuous integration

GitHub Actions boots a real OpenBSD 8.0 virtual machine
(`vmactions/openbsd-vm`), on both amd64 and arm64, for every push to `main` and
every pull request, and runs the full validation inside it:

* installs the native OpenBSD Rust toolchain with `pkg_add`;
* `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  and `cargo test --all-features`, executed as an unprivileged `builder` user;
* `cargo check --all-targets` for the default (7.9-compatible) surface, and
  `cargo build` for `--no-default-features`, `--no-default-features --features alloc`,
  and `--features openbsd-8-0`;
* `cargo check --all-features`, `cargo doc --no-deps --all-features`, and
  `cargo package --allow-dirty`;
* runs the test suite again as `root`, and fails if tests report
  `requires root privileges` or do not pass, so the real, effective and saved
  UID/GID drops and the inability to regain root are exercised against the actual
  kernel.

The test suite is run with `--all-features`, which enables `openbsd-8-0` and
therefore exercises the 33-promise typed inventory and the `getexecpath(3)`
tests against the real kernel. OpenBSD 7.9 and the declared MSRV are not part of
the CI matrix; verify them explicitly when changing version-sensitive code.

Every third-party action is pinned to a full commit hash and GitHub token
permissions are minimal.

## Licensing and attribution

Licensed under the [Apache License, Version 2.0](LICENSE-APACHE).

This project is a fork of [`priv_sep`](https://git.philomathiclife.com/repos/priv_sep)
by **Zack Newman**, which is dual-licensed under MIT and Apache-2.0. The original
copyright notices are preserved, and this project is distributed under the terms
of the Apache License, Version 2.0. Large parts of the FFI structure,
the typed `Promises`/`Permissions` sets, the `CStrHelper` path conversion, and the
OpenBSD `errno` table originate from that project and are retained here.

The [Haskell `openbsd` package](https://github.com/daviduhden/haskell-openbsd) by
**James Hobson** and **David Uhden Collado** (BSD-3-Clause) is the functional
reference: its public API, documented semantics, and kernel-tested behavior are
the feature-parity baseline. No Haskell source code is reused; it is treated as a
behavioral specification.

This is a fork, not an independent clean-room implementation, and it does not
represent the original upstream work as new.

[`Promise`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Promise.html
[`Promise::Error`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Promise.html
[`Promises`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/struct.Promises.html
[`pledge`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.pledge.html
[`pledge_child`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.pledge_child.html
[`pledge_parts`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.pledge_parts.html
[`pledge_raw`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.pledge_raw.html
[`privileges`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/privileges/index.html
[`credentials`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/credentials/index.html
[`process`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html
[`random`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/random/index.html
[`rtable`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/rtable/index.html
[`memory`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/memory/index.html
[`authentication`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/authentication/index.html
[`unveil`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.unveil.html
[`unveil_paths`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.unveil_paths.html
[`lock_unveil`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.lock_unveil.html
[`unveil_and_lock`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.unveil_and_lock.html
[`CStrHelper`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/trait.CStrHelper.html
[`Permission::Read`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Permission.html
[`Permission::Write`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Permission.html
[`Permission::Execute`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Permission.html
[`Permission::Create`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Permission.html
[`Account`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/struct.Account.html
[`account_by_name`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.account_by_name.html
[`drop_privileges`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.drop_privileges.html
[`drop_privileges_with`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.drop_privileges_with.html
[`drop_privileges_to`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.drop_privileges_to.html
[`drop_supplementary_groups`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.drop_supplementary_groups.html
[`GroupPolicy`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.GroupPolicy.html
[`GroupPolicy::PrimaryGroupOnly`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.GroupPolicy.html
[`GroupPolicy::Initgroups`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.GroupPolicy.html
[`PrivDropError`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.PrivDropError.html
[`Errno`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Errno.html
[`chroot`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.chroot.html
[`enter_chroot`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.enter_chroot.html
[`PROCTITLE_MAX`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/constant.PROCTITLE_MAX.html
[`arc4_random_uniform`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.arc4_random_uniform.html
[`mimmutable`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.mimmutable.html
[`freezero`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.freezero.html
[`explicit_bzero`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.explicit_bzero.html
[`daemonize`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.daemonize.html
[`DaemonOptions`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/struct.DaemonOptions.html
[`DaemonOptions::change_directory_to_root`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/struct.DaemonOptions.html
[`DaemonOptions::redirect_standard_streams`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/struct.DaemonOptions.html
[`std::process::Command`]: https://doc.rust-lang.org/stable/std/process/struct.Command.html
[`std::io::Error`]: https://doc.rust-lang.org/stable/std/io/struct.Error.html
[`get_execpath`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.get_execpath.html
