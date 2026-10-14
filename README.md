# Rust OpenBSD

Idiomatic, OpenBSD-only Rust bindings for the security facilities that are
unique to [OpenBSD](https://www.openbsd.org/):

| Facility | Module | Restricts/provides |
| --- | --- | --- |
| [`pledge(2)`](https://man.openbsd.org/pledge.2) | [`pledge`](https://docs.rs/rust-openbsd/latest/rust_openbsd/pledge/index.html) | which system operations the process may perform |
| [`unveil(2)`](https://man.openbsd.org/unveil.2) | [`unveil`](https://docs.rs/rust-openbsd/latest/rust_openbsd/unveil/index.html) | which filesystem paths the process may access |
| privilege dropping | [`privileges`](https://docs.rs/rust-openbsd/latest/rust_openbsd/privileges/index.html) | the credentials (UID/GID/groups) of the process |
| [`chroot(2)`](https://man.openbsd.org/chroot.2) | [`chroot`](https://docs.rs/rust-openbsd/latest/rust_openbsd/chroot/index.html) | the filesystem root for pathname resolution |
| [`issetugid(2)`](https://man.openbsd.org/issetugid.2), [`getpeereid(3)`](https://man.openbsd.org/getpeereid.3) | [`credentials`](https://docs.rs/rust-openbsd/latest/rust_openbsd/credentials/index.html) | set-ID execution taint; Unix-domain peer credentials |
| [`setproctitle(3)`](https://man.openbsd.org/setproctitle.3), exec, daemonization, [`closefrom(2)`](https://man.openbsd.org/closefrom.2) | [`process`](https://docs.rs/rust-openbsd/latest/rust_openbsd/process/index.html) | process titles, exec under a pledge ceiling, descriptor hygiene |
| [`arc4random(3)`](https://man.openbsd.org/arc4random.3), [`getentropy(2)`](https://man.openbsd.org/getentropy.2) | [`random`](https://docs.rs/rust-openbsd/latest/rust_openbsd/random/index.html) | cryptographically strong random values; kernel entropy |
| [`getrtable(2)`](https://man.openbsd.org/getrtable.2), [`setrtable(2)`](https://man.openbsd.org/setrtable.2) | [`rtable`](https://docs.rs/rust-openbsd/latest/rust_openbsd/rtable/index.html) | routing domains |
| [`mimmutable(2)`](https://man.openbsd.org/mimmutable.2), [`explicit_bzero(3)`](https://man.openbsd.org/explicit_bzero.3), [`freezero(3)`](https://man.openbsd.org/freezero.3), [`timingsafe_bcmp(3)`](https://man.openbsd.org/timingsafe_bcmp.3) | [`memory`](https://docs.rs/rust-openbsd/latest/rust_openbsd/memory/index.html) | memory immutability, secure erasure, constant-time comparison |
| [`crypt_checkpass(3)`](https://man.openbsd.org/crypt_checkpass.3), [`crypt_newhash(3)`](https://man.openbsd.org/crypt_newhash.3), [`bcrypt_pbkdf(3)`](https://man.openbsd.org/bcrypt_pbkdf.3) | [`authentication`](https://docs.rs/rust-openbsd/latest/rust_openbsd/authentication/index.html) | password hashing and key derivation |

These mechanisms restrict *different dimensions* of process authority and are
normally complementary: a typical OpenBSD daemon uses several of them. They are
not interchangeable.

## Scope

This crate is deliberately **OpenBSD-only**. Building it for any other operating
system fails with a clear compile-time error; there are no stub
implementations, no fallback behavior, and no portability abstractions. The only
exception is documentation builds (`cargo doc`, which sets `cfg(doc)`), so that
the API can be rendered from any host.

The crate provides OpenBSD-specific primitives; general POSIX functionality
belongs to [`std`](https://doc.rust-lang.org/stable/std/) and is not rebound.
It is intentionally **not** a sandbox framework, daemon, or command-line tool.
Its single `fork`-based facility, [`daemonize`](https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.daemonize.html),
documents the usual post-`fork(2)` hazards; the exec helpers use
[`std::process::Command`](https://doc.rust-lang.org/stable/std/process/struct.Command.html)
and never run caller code in the post-fork child.

## Supported OpenBSD versions

* Targets **OpenBSD 7.9** and **OpenBSD-current**.
* The [`Promise`] list is verified against the kernel's `pledgereq` table in
  [`sys/kern/kern_pledge.c`](https://github.com/openbsd/src/blob/master/sys/kern/kern_pledge.c)
  (35 promises; `tmppath` removed; `disklabel`, `drm`, and `vmm` included).
* Unveil permissions are verified against
  [`sys/kern/kern_unveil.c`](https://github.com/openbsd/src/blob/master/sys/kern/kern_unveil.c):
  `r`, `w`, `x`, `c`, with the empty permission set valid.
* Login-name and group limits are taken from OpenBSD's `LOGIN_NAME_MAX` (32) and
  `NGROUPS_MAX` (16).

[`Promise`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Promise.html

## Installation

```console
cargo add rust-openbsd
```

or, in `Cargo.toml`:

```toml
[dependencies]
rust-openbsd = "0.1"
```

The crate has **no runtime dependencies**. `no_std` is supported with optional
`alloc` and `std` features (`std` is on by default).

## API overview

### `pledge(2)`

[`Promise`] is the typed promise enumeration; [`Promises`] is a set of promises
that can only be reduced. The native call has two independent arguments —
`promises` and `execpromises` — and both are exposed.

```rust
use rust_openbsd::{pledge, Promise, Promises};

let promises = Promises::new([Promise::Stdio, Promise::Rpath]);
pledge(&promises)?;                        // pledge(promises, NULL)
# Ok::<(), rust_openbsd::Errno>(())
```

Calls are monotonic: a later call may only *reduce* the set, and an attempt to
increase it fails with `EPERM`. A `SIGABRT` (uncatchable) is raised if the
process performs an operation outside the declared promises. The `error`
promise changes that to `ENOSYS` and makes promise increases silently ignored.

#### Execution promises

`execpromises` restrict programs started later with `execve(2)`:

```rust
use rust_openbsd::{pledge_both, pledge_child, Promise, Promises};

// Set both parts atomically: keep stdio/rpath/proc/exec now, and force any
// future executed program to start with only stdio.
pledge_both(
    &Promises::new([Promise::Stdio, Promise::Rpath, Promise::Proc, Promise::Exec]),
    &Promises::new([Promise::Stdio]),
)?;

// Or restrict only future executions, leaving the current process alone.
pledge_child(&Promises::new([Promise::Stdio]))?;
# Ok::<(), rust_openbsd::Errno>(())
```

Exec promises are inherited across `fork(2)`, so the recommended way to configure
the policy of a fork/exec child is to call [`pledge_child`] in the parent before
forking. When `execpromises` is left unset, restrictions do **not** automatically
carry across `execve(2)`; the new image starts unpledged.

#### `NULL` versus the empty string

[`pledge_parts`] is the full typed interface to
`int pledge(const char *promises, const char *execpromises)`:

| Argument | Value | Meaning |
| --- | --- | --- |
| `promises` | `None` | `NULL`: do not change the current promises |
| `promises` | `Some(&Promises::NONE)` | `""`: restrict the process to `_exit(2)` only |
| `promises` | `Some(set)` | set the current promises to `set` |
| `execpromises` | `None` | `NULL`: do not change the exec promises |
| `execpromises` | `Some(&Promises::NONE)` | `""`: future execs start with no promises |

[`pledge_raw`] exposes the raw `Option<&CStr>` form when the promise list is only
known at runtime.

### `unveil(2)`

```rust
use rust_openbsd::{unveil_and_lock, Permission, Permissions};

let read = Permissions::READ;
let read_write_create = Permissions::READ
    .enable(Permission::Write)
    .enable(Permission::Create);

unveil_and_lock([
    ("/", read),
    ("/var/www", read),
    ("/var/log/myapp", read_write_create),
])?;
# Ok::<(), rust_openbsd::Errno>(())
```

* [`unveil`] adds a single rule; [`unveil_paths`] adds several.
* [`lock_unveil`] is `unveil(NULL, NULL)` and permanently locks the
  configuration; [`unveil_and_lock`] installs rules and locks.
* Paths are accepted through [`CStrHelper`], so they may be `Path`, `OsStr`,
  `str`, or raw byte slices and need not be valid UTF-8. Interior NUL bytes are
  rejected.

Denied access surfaces later as `EACCES`/`ENOENT` at the filesystem call site,
not as an error from this crate.

### Privilege dropping

```rust
use rust_openbsd::{drop_privileges, GroupPolicy};

// Privileged initialization happens first (bind sockets, open logs, ...).
drop_privileges("_mydaemon")?;                     // restrictive daemon policy

// Or choose the login-style supplementary-group policy explicitly.
drop_privileges_with(GroupPolicy::Initgroups, "_mydaemon")?;
# Ok::<(), rust_openbsd::PrivDropError>(())
```

[`drop_privileges`] resolves the account and performs the sequence used by
OpenBSD base-system daemons:

1. resolve the destination account while still privileged;
2. set the supplementary groups while still privileged;
3. [`setresgid(2)`](https://man.openbsd.org/setresgid.2) for the real, effective,
   and saved GIDs;
4. [`setresuid(2)`](https://man.openbsd.org/setresuid.2) for the real, effective,
   and saved UIDs;
5. verify the resulting credentials.

The [`Account`] type stores the login name inline (bounded by `LOGIN_NAME_MAX`),
so [`drop_privileges_to`] can resolve the account before, for example,
[`chroot()`] makes the password database unreachable.

Two supplementary-group policies are supported:

* `GroupPolicy::PrimaryGroupOnly` (the default): keep only the destination
  primary GID — the restrictive daemon policy (`setgroups(1, &gid)`).
* `GroupPolicy::Initgroups`: adopt the account's supplementary groups through
  `initgroups(3)` — login-style behavior.

A failed step returns a [`PrivDropError`] that identifies the failing operation
and preserves the underlying [`Errno`]. **Credential changes are not
reversible**: after a partial failure the process may already have reduced
privileges and must not continue normal service execution. The library never
pretends that a failed drop restored the original identity and provides no
privilege-restoration API.

### `chroot(2)`

```rust
use rust_openbsd::enter_chroot;

enter_chroot("/var/empty")?;   // chroot(path) followed by chdir("/")
# Ok::<(), rust_openbsd::Errno>(())
```

[`chroot`] is the raw call; [`enter_chroot`] performs `chroot(path)` then
`chdir("/")` to close the classic `".."` escape. `chroot(2)` requires root, is
not covered by any pledge promise (do it *before* pledging), and is not a
substitute for `pledge(2)`, `unveil(2)`, or privilege dropping.

### Recommended order

```
privileged initialization
    -> set_process_title
    -> chroot
    -> unveil + lock
    -> initial pledge (still including "id" and, if needed, "getpw")
    -> drop privileges
    -> final pledge (without "id")
    -> optional pledge_child for future execs
    -> service loop
```

### Credentials

```rust
use rust_openbsd::{get_peer_credentials, is_setugid};

// Was this image tainted by set-ID execution?
let tainted = is_setugid();

// Who is on the other end of a Unix-domain socket?
let (uid, gid) = get_peer_credentials(fd)?;
# Ok::<(), rust_openbsd::Errno>(())
```

`is_setugid` is not a UID/GID comparison and is not affected by later ID
changes. `get_peer_credentials` is not covered by any pledge promise, so call it
before pledging.

### Random

```rust
use rust_openbsd::{arc4_random, arc4_random_bytes, arc4_random_uniform, get_entropy};

let value = arc4_random();
let bytes = arc4_random_bytes(32);
let die = arc4_random_uniform(6);   // unbiased; prefer over `% 6`
let mut entropy = [0_u8; 256];
get_entropy(&mut entropy)?;         // getentropy(2), at most 256 bytes
# Ok::<(), rust_openbsd::Errno>(())
```

### Routing domains

```rust
use rust_openbsd::{Rtable, get_rtable, set_rtable};

let table = get_rtable()?;
if table == Rtable::DEFAULT {
    set_rtable(Rtable::new(0))?;
}
# Ok::<(), rust_openbsd::Errno>(())
```

### Memory

```rust
use rust_openbsd::{explicit_bzero, timingsafe_bcmp, timingsafe_memcmp};

let mut secret = *b"hunter2";
explicit_bzero(&mut secret);            // not optimized away

let equal = timingsafe_bcmp(a, b);      // constant time, same length required
let order = timingsafe_memcmp(a, b);    // constant time, tie-broken by length
```

`mimmutable` freezes a mapped region; `freezero` is `unsafe` because it takes
ownership of a `malloc(3)` allocation.

### Authentication

```rust
use rust_openbsd::{bcrypt_pbkdf, crypt_checkpass, crypt_newhash};

let hash = crypt_newhash(&b"correct horse"[..], "bcrypt,4")?;
assert!(crypt_checkpass(&b"correct horse"[..], hash.as_slice())?);

let key = bcrypt_pbkdf(&b"password"[..], &b"salt"[..], /*rounds*/ 4, 32)?;
# Ok::<(), rust_openbsd::Errno>(())
```

No cryptographic code lives in this crate; these call OpenBSD's implementations.
Interior NUL bytes in password or hash inputs are rejected with `EINVAL` rather
than silently truncating.

### Process

```rust
use rust_openbsd::{close_from, dtable_count, set_proctitle};

set_proctitle("mydaemon: serving")?;    // fixed "%s" format, title is data
let open_descriptors = dtable_count();
close_from(3);                          // descriptor-leak prevention
# Ok::<(), rust_openbsd::Errno>(())
```

`exec_pledged` sets the execution promises and then replaces the image;
`fork_exec_pledged` sets them and spawns, which caps every future exec of the
caller (monotonic). `daemonize` detaches from the controlling terminal and
carries the documented post-`fork(2)` hazards.

## Error semantics

* Failing `pledge(2)`, `unveil(2)`, and `chroot(2)` calls return [`Errno`], the
  error reported by the kernel (`EPERM`, `EINVAL`, `ENOENT`, ...).
* `pledge(2)` violations do not return an error: the kernel aborts the process
  with an uncatchable `SIGABRT` unless the `error` promise is active.
* `unveil(2)` denials surface later as `EACCES`/`ENOENT` at the filesystem call
  site.
* [`Errno`] implements [`core::error::Error`] and, with the `std` feature,
  converts to and from [`std::io::Error`].
* Strings that cross the FFI boundary are rejected if they contain embedded NUL
  bytes rather than being silently truncated.

## Security limitations

* Applying pledge restrictions to a process that has already started threads, an
  asynchronous runtime, or libraries that need further system calls can abort the
  process. The kernel unwinds sibling threads while cleaning up unveil state, and
  the resumed threads then perform syscalls the fresh restriction forbids.
* `chroot(2)` is not a sandbox: a root process may escape it, and open file
  descriptors keep access to resources outside the new root.
* `unveil(2)` restrictions are process-wide and, once locked, cannot be changed.
* Privilege dropping is irreversible. Treat any [`PrivDropError`] as fatal.
* [`daemonize`](https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.daemonize.html)
  runs a caller closure after a raw `fork(2)`; in a multithreaded process only
  async-signal-safe operations are reliable in the child, so call it before
  spawning threads or accept the documented risk.
* [`timingsafe_bcmp`] and [`timingsafe_memcmp`] compare byte slices in constant
  time, but comparing *different lengths* reveals the length; lengths are not
  treated as secret.
* This crate provides primitives, not a sandbox. Correctness depends on the
  caller performing the transitions in the documented order.

## Feature gating

The crate is `no_std` by default. The `alloc` feature adds the functions that
return owned buffers ([`arc4_random_bytes`], [`get_entropy_bytes`],
[`crypt_newhash`], [`bcrypt_pbkdf`]); the `std` feature (on by default, and
implying `alloc`) adds the exec helpers that build on [`std::process::Command`]
and the conversions between [`Errno`] and [`std::io::Error`]. Everything else,
including the pledge, unveil, and privilege-dropping interfaces, works without
either.

## Testing

The unit tests cover pure serialization and set logic and run anywhere the crate
compiles. The integration tests exercise the real OpenBSD kernel and **must run
on OpenBSD**:

```console
cargo test
```

Every destructive or irreversible test runs in an isolated child process, so the
test runner never loses privileges or has its authority restricted. Tests that
trigger `SIGABRT` inspect the child's termination status. Tests that require root
skip cleanly when the runner is not root; run them separately as root:

```console
doas cargo test -- --nocapture
```

A passing unprivileged run does **not** prove that privilege dropping works; the
privileged stage must be executed as root. Some exec-promise tests compile a
small C probe with the system compiler and skip when `cc` is unavailable. The
`_exit`-only (empty promise set) state is verified by a single-threaded native
probe rather than from the multithreaded test runner: reducing a threaded
process to that state makes the kernel unwind sibling threads, whose resumed
system calls are then forbidden and abort the process.

## Minimum supported Rust version

**Rust 1.85.0** (the edition-2024 minimum). Upstream `priv_sep` declared a newer
MSRV that does not exist on OpenBSD 7.9, which ships Rust 1.94.1; 1.85.0 is the
lowest toolchain that provides every language feature used here.

## Licensing and attribution

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

This project is a fork of [`priv_sep`](https://git.philomathiclife.com/repos/priv_sep)
by **Zack Newman**, which is dual-licensed under MIT and Apache-2.0. The original
copyright notices and licenses are preserved. Large parts of the FFI structure,
the typed `Promises`/`Permissions` sets, the `CStrHelper` path conversion, and the
OpenBSD `errno` table originate from that project and are retained here.

The [Haskell `openbsd` package](https://github.com/daviduhden/haskell-openbsd) by
**James Hobson** and **David Uhden Collado** (BSD-3-Clause) is used as the
functional reference: its public API, documented semantics, and kernel-tested
behavior are the feature-parity baseline. No Haskell source code is reused; it is
treated as a behavioral specification.

This is a fork, not an independent clean-room implementation, and it does not
represent the original upstream work as new.

[`Promise`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Promise.html
[`Promises`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/struct.Promises.html
[`pledge_child`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.pledge_child.html
[`pledge_parts`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.pledge_parts.html
[`pledge_raw`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.pledge_raw.html
[`unveil`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.unveil.html
[`unveil_paths`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.unveil_paths.html
[`lock_unveil`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.lock_unveil.html
[`unveil_and_lock`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.unveil_and_lock.html
[`CStrHelper`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/trait.CStrHelper.html
[`drop_privileges`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.drop_privileges.html
[`drop_privileges_to`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.drop_privileges_to.html
[`Account`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/struct.Account.html
[`chroot`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.chroot.html
[`chroot()`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.chroot.html
[`enter_chroot`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.enter_chroot.html
[`PrivDropError`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.PrivDropError.html
[`Errno`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/enum.Errno.html
[`timingsafe_bcmp`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.timingsafe_bcmp.html
[`timingsafe_memcmp`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.timingsafe_memcmp.html
[`arc4_random_bytes`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.arc4_random_bytes.html
[`get_entropy_bytes`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.get_entropy_bytes.html
[`crypt_newhash`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.crypt_newhash.html
[`bcrypt_pbkdf`]: https://docs.rs/rust-openbsd/latest/rust_openbsd/fn.bcrypt_pbkdf.html
[`std::process::Command`]: https://doc.rust-lang.org/stable/std/process/struct.Command.html
[`std::io::Error`]: https://doc.rust-lang.org/stable/std/io/struct.Error.html
