# Crate architecture

This file describes the repository as it is implemented in `src/` and `tests/`.
It is intentionally readable as plain Markdown; opening the Rust source files is
sufficient to follow any component in detail.

## Repository and build surface

The repository contains one Cargo library crate, `rust-openbsd`. `src/lib.rs` is
its crate root and public API façade. It sets `#![no_std]`, rejects targets other
than OpenBSD, declares the internal conversion and FFI modules, exposes the
facility modules, and re-exports commonly used APIs. The `cfg(doc)` exception
permits API documentation builds on non-OpenBSD hosts; it does not add a
portable implementation.

Features add capabilities in layers:

| Feature | Effect |
| --- | --- |
| default `std` | Enables `alloc`, standard-library path and OS-string inputs, `std::io::Error` conversions, and process `Command` helpers. |
| `alloc` | Enables allocation-backed C strings, account lookup buffers, random byte vectors, and owned hash/key results. |
| `openbsd-8-0` | Enables the OpenBSD 8.0 `getexecpath(3)` binding and selects the crate's newer typed pledge inventory. |

There are no Cargo dependencies. Native facilities are provided by the OpenBSD C library and kernel.

## Ownership boundaries

The crate keeps each native boundary in one place and gives each facility one owning module:

```text
public users
    |
    v
src/lib.rs  -- public module tree, re-exports, features, OpenBSD target gate
    |
    +--> facility modules -- validate/convert inputs, call native API, map errors
    |       |
    |       +--> src/cstr.rs -- callback-scoped C-string conversion
    |       +--> src/error.rs -- OpenBSD errno values and thread-local errno
    |       +--> src/ffi.rs -- C ABI declarations and passwd structure layout
    |
    +--> src/tests.rs -- pure tests for representation and decision logic
            tests/*.rs -- kernel behavior in isolated child processes
```

`src/ffi.rs` owns raw declarations and the `#[repr(C)]` `Passwd` structure. A native symbol is declared there once; wrappers belong in the module for that facility. Wrappers return Rust values and `Result<_, Errno>` rather than exposing raw pointers. `Errno::last()` reads thread-local `errno` immediately after a native failure in the same thread.

## Module map

| Source | Responsibility | Main relationships |
| --- | --- | --- |
| `src/pledge.rs` | Typed promise inventory, bit-set representation, native string encoding, and `pledge(2)` calls. | Uses `CStrHelper` for raw string inputs and `Errno` for failures; process helpers use exec promises. |
| `src/unveil.rs` | Permission flags, canonical permission encoding, path rules, and permanent locking. | Uses `CStrHelper`; pledge can restrict whether unveil calls remain available. |
| `src/privileges.rs` | UID/GID wrappers, account lookup, supplementary groups, ordered credential drop, and post-drop verification. | Uses `Passwd` through FFI, `CStrHelper`, and `Errno`; account lookup must precede a chroot that hides the databases. |
| `src/chroot.rs` | `chroot(2)`, `chdir(2)`, and the combined `enter_chroot` transition. | Uses `CStrHelper`; callers normally resolve accounts before the root change and pledge afterward. |
| `src/credentials.rs` | Set-ID execution taint and connected Unix-socket peer credentials. | Returns the `Uid` and `Gid` value types from `privileges.rs`. |
| `src/process.rs` | Process titles and names, descriptor operations, exec helpers, daemonization, and the 8.0 executable-path query. | Exec helpers combine `std::process::Command` with pledge's child promise ceiling. |
| `src/random.rs` | OpenBSD random-number APIs and bounded kernel entropy requests. | Allocation-backed vector helpers are gated by `alloc`. |
| `src/rtable.rs` | Routing-domain ID and get/set operations. | Native validation and privilege rules remain kernel decisions. |
| `src/memory.rs` | Immutable mappings, explicit erasure, allocator-aware release, and timing-safe comparisons. | `mimmutable` and `freezero` expose caller obligations in `unsafe` contracts. |
| `src/authentication.rs` | Password verification/hash generation and bcrypt PBKDF. | Calls libc implementations; it does not implement cryptographic algorithms. |
| `src/cstr.rs` | `CStrHelper` and stack/heap conversion paths for strings and paths. | Shared input boundary for APIs taking native C strings. |
| `src/error.rs` | OpenBSD `Errno`, raw conversion, thread-local access, and optional `std` conversion. | Native wrappers use it to preserve operating-system failures. |
| `src/ffi.rs` | Minimal C declarations, ABI types, and `Passwd`. | Called only by owning wrappers and test probes. |
| `src/tests.rs` | Host-independent representation, conversion, and decision-logic tests. | Does not call kernel security operations. |
| `tests/common/mod.rs` | Re-exec harness and shared child assertions for integration tests. | Kernel tests isolate irreversible process state from the main test runner. |
| `tests/*.rs` | Per-facility OpenBSD integration coverage. | Run on the OpenBSD CI VMs; several cases require root or a child process. |

## Important data and error paths

### Rust strings and paths to native strings

Native interfaces receive `CStr` pointers only for the duration of the `CStrHelper::convert_then_apply` callback. Existing `CStr` values are borrowed directly. Inputs shorter than 1024 bytes are copied into a fixed stack buffer and terminated; interior NUL bytes fail with `EINVAL`. At 1024 bytes and above, `alloc` builds a `CString`; without `alloc`, conversion returns `ERANGE`. This callback design prevents a temporary stack-backed `CStr` from escaping its valid lifetime.

### Typed promise encoding

`Promise` names are the native textual names. `Promises` stores membership in a `u64` bit set for inexpensive set operations, but the kernel never receives that bit pattern. Encoding walks `Promise::ALL` in its stable order, writes native names separated by spaces, and replaces the last separator with NUL. An empty typed set is encoded as an empty C string; `None` is encoded as a null pointer, preserving the kernel's distinct “leave unchanged” meaning.

### Credential drop and verification

The mechanism applies the supplementary-group policy first, then sets real/effective/saved GIDs, then real/effective/saved UIDs, and finally reads the credentials back. The order preserves the ability to set groups before losing privilege and removes saved root IDs. Failure after any successful step can leave a partial drop, so the returned error identifies the failing phase but does not roll back earlier changes. `Initgroups` verification resolves expected membership with `getgrouplist(3)` and compares group sets without depending on order.

### Native calls and `errno`

Each wrapper follows its native return convention: most calls use zero for success and `-1` for failure; `getpwnam_r(3)` returns an error number directly; `getrtable(2)` accepts zero as a valid routing-domain ID; and `fork(2)` distinguishes parent, child, and error by positive, zero, and negative values. Wrappers must not apply one generic interpretation to all of them.

## Security-state relationships

The crate exposes mechanisms that constrain separate dimensions of process authority:

- `pledge(2)` limits classes of system operations and is monotonic.
- `unveil(2)` limits filesystem path visibility; repeated rules for a path replace its permission set, and locking is permanent.
- `chroot(2)` changes pathname resolution but does not revoke already-open descriptors or replace the other controls.
- UID/GID/group changes alter credentials and are not a syscall sandbox.
- Routing domains select routing state; they are not a pledge-like monotonic restriction.

A typical daemon resolves its account while databases are available, performs any required chroot, installs and locks unveil rules, keeps the needed `id`/`getpw` promises during the drop, verifies credentials, and then reduces promises for the service loop. The exact order depends on which native operations the application still needs.

## Unsafe boundary

The crate denies unsafe code by default and locally opts in only around the native operations that require it. Each call site documents pointer validity, extent, mutability, and lifetime. The highest-impact caller obligations are:

- `mimmutable` can freeze pages outside the supplied slice after the kernel rounds the range outward; only use it on a dedicated mapping.
- `freezero` consumes a `malloc(3)`-compatible allocation, not Rust-allocator, stack, static, or `mmap` memory.
- `fork` requires callers to respect the post-fork restrictions of a multithreaded process; the crate's `Command` helpers avoid running crate Rust code in that window.
- `set_progname` requires a `'static` `CStr` because libc retains the pointer.

These APIs document their obligations in source; this summary does not make an unsafe call safe by itself.

## Tests and evidence

`src/tests.rs` tests pure data transformations and policy decisions on any host. Integration files under `tests/` call the real OpenBSD APIs. Tests that change credentials, pledge/unveil state, chroot, descriptors, or process metadata run in a re-executed child test binary; root-sensitive cases explicitly skip or are checked by the privileged CI stage. Compilation and static analysis are not evidence that kernel enforcement behaves correctly. The tested VM matrix is recorded in `AGENTS.md` and
`.github/workflows/ci.yml`.

For direct source reading, start at `src/lib.rs`, then follow the facility module named in the table above. No generated site or external documentation service is needed to consult this architecture map.
