# AGENTS.md

Permanent instructions for AI agents working on `rust-openbsd`.

## Purpose and scope

`rust-openbsd` provides idiomatic Rust interfaces to OpenBSD-specific system and
library facilities: `pledge(2)`, `unveil(2)`, `chroot(2)`, the daemon
privilege-dropping sequence, process and descriptor control, OpenBSD random and
password-hashing functions, routing domains, and OpenBSD memory-protection
helpers.

The crate is deliberately **OpenBSD-only**. Non-OpenBSD targets fail with a
single `compile_error!`. `cargo doc` is the only exception: `cfg(doc)` lets the
API be documented on any host. Do not add Linux, FreeBSD, macOS, or Windows
stubs, fallbacks, or portability abstractions that pretend to offer equivalent
security guarantees. Do not weaken or remove the `cfg(doc)` escape hatch.

Architecture:

| Path | Responsibility |
| --- | --- |
| `src/ffi.rs` | Minimal `unsafe extern "C"` declarations and the `Passwd` ABI |
| `src/cstr.rs` | `CStrHelper` conversion for strings, paths, and byte slices |
| `src/error.rs` | OpenBSD `errno` enum and thread-local `errno` access |
| `src/pledge.rs` | Typed promises, `pledge(2)`, exec promises |
| `src/unveil.rs` | Typed permissions, `unveil(2)`, locking |
| `src/privileges.rs` | Account lookup and the `setgroups`/`setresgid`/`setresuid` drop |
| `src/chroot.rs` | `chroot(2)`, `chdir(2)`, `enter_chroot` |
| `src/credentials.rs` | `issetugid(2)`, `getpeereid(3)` |
| `src/process.rs` | Titles, `closefrom`, exec helpers, daemonization |
| `src/random.rs` | `arc4random(3)` family, `getentropy(2)` |
| `src/rtable.rs` | Routing domains |
| `src/memory.rs` | `mimmutable`, `explicit_bzero`, `freezero`, timing-safe comparisons |
| `src/authentication.rs` | `crypt_checkpass`, `crypt_newhash`, `bcrypt_pbkdf` |
| `tests/` | Kernel-dependent integration tests in isolated child processes |
| `src/tests.rs` | Pure unit tests that must run on any host |

Ownership layers: `ffi.rs` owns the raw ABI; each module owns exactly one
native facility and converts `errno` into `Errno`; `lib.rs` owns the public
surface and feature gates. Do not add a second binding for a symbol already
declared in `ffi.rs`, and do not expose raw pointers publicly.

## Non-negotiable invariants

1. A safe public function must not require hidden invariants that only the
   caller can satisfy. Use `unsafe fn` and a `# Safety` section when it does.
2. Every `unsafe` operation needs a concrete, verifiable justification. The
   crate denies `unsafe_code`, `undocumented_unsafe_blocks`, and
   `multiple_unsafe_ops_per_block`; use one unsafe operation per block and a
   `// SAFETY:` comment.
3. FFI declarations must match OpenBSD's types, sizes, alignment, ABI, and
   return conventions exactly. Do not copy Linux or FreeBSD signatures.
4. Never return a Rust reference to memory whose lifetime is not guaranteed.
5. Never turn an FFI failure into a silent success. Propagate `errno` or return
   an explicit error type.
6. Respect irreversible kernel operations. `pledge`, `unveil` locking,
   `chroot`, and credential drops cannot be undone.
7. `pledge`, `unveil`, `chroot`, and UID/GID changes restrict different
   dimensions of authority. They are complementary, not interchangeable.
8. Do not run arbitrary Rust code between `fork()` and `execve()` in a
   multithreaded process. Prefer `std::process::Command`; treat caller-installed
   `pre_exec` closures as dangerous caller code.
9. Preserve `no_std`. `alloc` and `std` are additive features; shared code must
   stay core-only.
10. Do not add runtime dependencies, or implement cryptography yourself, when
    the OpenBSD C library already provides the operation.
11. Treat the public API as stable. Evaluate source and behavioral compatibility
    before changing a signature, error, or feature gate.
12. Never present a partial restriction as complete isolation. Say what a
    mechanism does not cover.

## Rust and Cargo conventions

- Rust Edition 2024; MSRV **1.85.0** as declared in `Cargo.toml`. Do not raise
  it without explicit authorization.
- `#![no_std]`, zero dependencies. `default = ["std"]`, `std = ["alloc"]`,
  `alloc = []`, `openbsd-8-0 = []`.
- Use `core` and `alloc` imports; gate `std`-only code with
  `#[cfg(feature = "std")]`.
- Idiomatic Rust, minimal allocation, existing naming and documentation style.
- Every public item needs documentation (`missing_docs` is denied). Every
  fallible operation returns `Result`; document `# Errors`, `# Safety`, and
  `# Pledge` where relevant.
- Do not silence lints to make a change pass. The lint policy in `Cargo.toml`
  is part of the project contract.
- New `.rs` files start with the Apache-2.0 header used by every existing file.
- License: **Apache-2.0 only** (`LICENSE`). MIT appears only as upstream
  provenance in the README.

## FFI, memory, and error rules

- Prefer `safe fn` in `unsafe extern "C"` only for functions with no pointer
  argument and no memory-safety precondition. Credential-changing calls can be
  safe; `fork` stays `unsafe`.
- Match each native return convention: `0`/`-1`, counts, `getrtable` where `0`
  is valid, `fork` where `0` is the child, and `getpwnam_r` which returns an
  error number directly.
- Read `errno` immediately, in the same thread, through `Errno::last()`; never
  cache `__errno()`.
- Keep `Errno` discriminants contiguous `1..=95` (`EPROTO == ELAST`). The
  `from_raw` transmute depends on that layout.
- `CStrHelper` rejects interior NUL bytes with `EINVAL`. Without `alloc`, inputs
  of 1024 bytes or more fail with `ERANGE`; with `alloc` they use a `CString`.
- `mimmutable` is for dedicated mappings only. The kernel rounds outward and
  skips unmapped pages; an empty slice is a no-op.
- `freezero` requires a `malloc(3)`-compatible allocation; `len` must not exceed
  the allocation size. Never pass Rust-allocator, stack, static, or `mmap`
  memory.
- Constant-time comparisons must not exit early. `timingsafe_bcmp` treats
  unequal lengths as unequal without comparing; do not treat lengths as secret.
- Never log passwords, hashes, derived keys, or other secrets, and never embed
  them in error values.

## Process and security model

The recommended daemon transition is:

1. privileged initialization;
2. resolve the destination account while `passwd(5)` is reachable;
3. `chroot`/`enter_chroot` (before pledge);
4. install and lock `unveil` rules;
5. initial `pledge` including `id` and, if needed, `getpw`;
6. `drop_privileges_to` with the resolved `Account`;
7. final `pledge` without identity-changing promises;
8. optional `pledge_child` for future execs;
9. unprivileged service loop.

`chroot(2)` has no pledge promise, so it must happen before pledging.
`chdir(2)` after pledge needs `rpath`. `getpeereid(3)` is a `getsockopt(2)`
wrapper on current OpenBSD; calling it before pledging is the conservative,
version-independent rule. Exec promises are process-global and monotonic across
`fork(2)`; they are never rolled back if a later exec fails.

## Testing policy

- Tests that change credentials, kernel restrictions, filesystem roots, process
  titles, or descriptors must run in an isolated child process. Use the existing
  `tests/common/mod.rs` re-exec pattern; never restrict the main test runner.
- A pledge violation is expected to terminate the child with `SIGABRT`; assert
  the child's termination status, not a returned error.
- Privileged tests run only as root and must use `skip_without_root` so CI can
  detect accidental skips. Tests that must not run as root skip explicitly.
- Do not run privileged or irreversible tests on the agent host. Use an
  OpenBSD VM or a disposable environment.
- `cargo check`, Clippy, and static analysis do **not** prove a security
  mechanism works. Distinguish static validation, compilation, unit tests,
  kernel integration tests, privileged tests, and other-version verification.
- `cargo test` with default features is only valid on OpenBSD 7.9; CI runs
  `cargo test --all-features` on OpenBSD 8.0.

## OpenBSD-current research

When a native interface may have changed, consult, in order:

1. the OpenBSD manual page for the exact target version;
2. the installed headers (`/usr/include`);
3. libc and kernel sources under `sys/` and `lib/libc/`;
4. CVS history for the relevant file;
5. the crate's tests and CI target.

Pay particular attention to the pledge promise inventory, `execpromises`
semantics, unveil limits, `getexecpath` availability, `errno` values, ABI types
and constants, and syscall-specific restrictions. Do not assume that a guarantee
from one OpenBSD release still holds in another. When versions differ, document
the difference and state which crate configuration applies.

## Subagents

Use subagents when available to audit a native contract, review memory safety,
compare documentation with code, analyze a regression, or evaluate OpenBSD
version compatibility. The main agent integrates the findings, resolves
contradictions, and verifies the result. Do not accept a subagent claim about a
kernel contract without checking a primary source or the repository's verified
tests.

## Skill routing

Load the matching skill before changing the corresponding area:

| Work area | Skill |
| --- | --- |
| FFI declarations, `unsafe`, ABI, `CStr`, `errno` | [`rust-openbsd-ffi`](.agents/skills/rust-openbsd-ffi/SKILL.md) |
| `pledge(2)`, promises, exec promises | [`rust-openbsd-pledge`](.agents/skills/rust-openbsd-pledge/SKILL.md) |
| `unveil(2)`, paths, permissions | [`rust-openbsd-unveil`](.agents/skills/rust-openbsd-unveil/SKILL.md) |
| UID/GID, groups, account lookup, `chroot` | [`rust-openbsd-privileges`](.agents/skills/rust-openbsd-privileges/SKILL.md) |
| fork/exec, daemonize, descriptors, titles | [`rust-openbsd-process`](.agents/skills/rust-openbsd-process/SKILL.md) |
| `mimmutable`, zeroing, constant-time comparison | [`rust-openbsd-memory`](.agents/skills/rust-openbsd-memory/SKILL.md) |
| random, hashing, password authentication | [`rust-openbsd-crypto-auth`](.agents/skills/rust-openbsd-crypto-auth/SKILL.md) |
| versions, features, MSRV, `no_std`, Cargo | [`rust-openbsd-platform`](.agents/skills/rust-openbsd-platform/SKILL.md) |
| kernel tests, child isolation, CI | [`rust-openbsd-testing`](.agents/skills/rust-openbsd-testing/SKILL.md) |
| README, Rustdoc, API policy, releases | [`rust-openbsd-documentation`](.agents/skills/rust-openbsd-documentation/SKILL.md) |

## Validation commands

Run on OpenBSD unless noted. `cargo fmt` and `cargo doc` also work elsewhere.

```sh
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps --all-features
cargo build --no-default-features
cargo build --no-default-features --features alloc
cargo build --features openbsd-8-0
```

Do not modify lints, features, dependencies, or code merely to make an unrelated
validation pass. Do not run destructive tests during documentation-only work.

## Maintenance

- Architecture or module changes: update this file.
- FFI or module contract changes: update the specialized skill.
- Security-guarantee changes: re-check the contracts and tests in every affected
  skill.
- New OpenBSD APIs: extend an existing skill or add a narrowly scoped one.
- Feature, MSRV, or version-support changes: update the platform skill and its
  reference matrix.
- Removed functionality: delete obsolete instructions rather than keeping a
  changelog.
- Keep documentation minimal and synchronized with code. When code and docs
  disagree, fix the contradiction and record any unresolved kernel-version
  uncertainty explicitly.

## Known constraints to preserve

- `openbsd-8-0` both enables `getexecpath(3)` and removes `Promise::Exec` /
  `Promise::Error` from the typed inventory. This is a crate API decision; the
  target kernel's promise table must still be verified independently.
- `close_from` returns `Result<(), Errno>` so descriptor-hygiene failures are
  observable. `EBADF` means the threshold was negative or above every open
  descriptor; nothing was closed.
- `daemonize_with` fails closed with child exit status 1 if `setsid`, the
  requested `chdir("/")`, or the standard-stream redirection fails.
- `GroupPolicy::Initgroups` verification compares the observed supplementary
  groups with `getgrouplist(3)` membership; it requires the group database to be
  reachable at verification time, just like `initgroups(3)` itself.
- `drop_privileges` and `drop_privileges_with` reject an account whose UID is
  root or whose primary GID is root. `drop_privileges_to` remains a mechanism and
  does not apply that policy.
- The safe `mimmutable` API takes `&[u8]`, so it cannot express a range that
  contains an unmapped hole; the kernel's hole-skipping behavior is tested with
  the raw syscall.
- OpenBSD 7.9 and MSRV 1.85.0 are not in the CI matrix. `closefrom`,
  `getpeereid`-under-pledge, and `mimmutable` hole tests run on 8.0/amd64 and
  8.0/arm64; 7.9 must be verified manually.
