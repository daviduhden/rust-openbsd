---
name: rust-openbsd-unveil
description: Use when working on unveil(2), Permission, Permissions, unveil_paths, unveil_and_lock, or lock_unveil in rust-openbsd. Covers path registration, r/w/x/c permissions, empty sets, locking, non-UTF-8 paths, rule replacement, and pledge interaction.
---

# rust-openbsd unveil

## When to activate

Activate when a task:

- changes `Permission`, `Permissions`, `unveil`, `unveil_paths`, `lock_unveil`,
  `unveil_and_lock`, `permissions_from_str`, or `permissions_from_os`;
- adds or audits path conversion or NUL rejection at the unveil boundary;
- documents symlink, directory, empty-permission, or rule-replacement behavior;
- changes the interaction between unveil and pledge;
- adds a new filesystem restriction mechanism.

## When not to activate

Do not use this skill for `chroot(2)` (load `rust-openbsd-privileges`), for
`pledge(2)` promise semantics (load `rust-openbsd-pledge`), or for general path
handling outside the crate. Do not present unveil as a complete sandbox: it
restricts pathname visibility, not syscalls, credentials, or open descriptors.

## Related files

- `src/unveil.rs` — implementation.
- `src/ffi.rs` — `unveil` declaration.
- `src/cstr.rs` — path conversion.
- `tests/unveil.rs`, `src/tests.rs` — behavior and encoding tests.
- `README.md`, `src/lib.rs` — documentation.

## Invariants

1. Permissions are the native letters `r`, `w`, `x`, `c`; the empty set is valid
   and unveils a path while permitting nothing.
2. A later call for an already-unveiled path **replaces** that path's permission
   set. Permissions are not monotonic: they may be widened or narrowed before
   locking.
3. `lock_unveil()` is `unveil(NULL, NULL)`. It is permanent; later `unveil` calls
   fail with `EPERM`.
4. `unveil_paths` is not atomic. It stops at the first error; earlier rules stay
   installed. `unveil_and_lock` therefore does not lock when a rule fails.
5. Paths are accepted through `CStrHelper`, are not required to be UTF-8, and
   must not contain an interior NUL byte. Non-UTF-8 paths are passed through
   unchanged.
6. The final path component may not exist yet and is remembered by name. A
   missing directory component fails with `ENOENT`.
7. Directories are recorded by vnode; removing and recreating an unveiled
   directory can make it appear not to exist. Non-directories are remembered by
   name and may be created later.
8. If the process is pledged, `unveil(2)` requires the `unveil` promise. A pledge
   that removes every path-accessing promise destroys the unveil state.
9. Denials surface later at the filesystem call as `EACCES` or `ENOENT`, not as
   errors from `unveil`.
10. Per-process limits can produce `E2BIG`; locked configuration produces
    `EPERM`; malformed permissions or interior NUL produce `EINVAL`.

## Safety contracts

The public functions are safe. `unveil` builds a five-byte, NUL-terminated
permission buffer and passes a borrowed `CStr`; both live for the call. The path
conversion rejects interior NULs before the syscall, so C-string truncation
cannot occur. `lock_unveil` passes two null pointers, which the kernel defines as
the lock operation and does not dereference.

## Analysis procedure

1. Read `src/unveil.rs` and identify every public entry point and its
   `Permissions` encoding.
2. Verify permission semantics against `unveil(2)`: `c` also affects `unix`
   socket `connect(2)`; `w` covers `wpath`, `chown`, `fattr`, and `AF_UNIX`
   `connect(2)`; `x` relates to execution.
3. Confirm the empty-permission encoding and its kernel effect.
4. Confirm replacement versus union for repeated paths and for directories.
5. Check path conversion: non-UTF-8, interior NUL, empty path, trailing slash,
   symlink components, and missing components.
6. Check the numeric and semantic error paths: configuration-time versus
   access-time.
7. Check the pledge requirement and what happens when path promises are removed.
8. Check whether the proposed abstraction can be enforced safely; if not,
   document the limitation instead of claiming isolation.

## Implementation procedure

1. Keep `Permissions` a small value type; preserve `NONE`, `ALL`, and the
   single-permission constants.
2. Encode in canonical `rwxc` order and NUL-terminate.
3. Keep path conversion on `CStrHelper`; do not add a UTF-8-only path API.
4. Preserve first-error behavior in `unveil_paths`, or document and test any
   atomicity change.
5. Never widen permissions automatically. Do not add a rule that the caller did
   not request.
6. Keep `lock_unveil` irreversible and separate from rule installation.
7. Document that `unveil_and_lock` does not roll back a partial rule set.
8. Add a unit test for permission encoding and an isolated child test for the
   kernel behavior.

## Testing and acceptance

- Unit: flag mapping, `ALL == "rwxc"`, `READ == "r"`, `NONE == ""`, parser
  behavior.
- Isolated child: read-only enforcement, empty permissions, lock irreversibility,
  replacement narrowing, widening before lock, missing directory `ENOENT`,
  non-UTF-8 path, multi-rule lock, and `SIGABRT` when pledging without `unveil`.
- Never run a restrictive unveil in the shared test process.
- Acceptance requires that configuration errors and post-configuration access
  errors are not conflated in documentation.

## References

- <https://man.openbsd.org/unveil.2>
- <https://man.openbsd.org/pledge.2>
- <https://man.openbsd.org/open.2>
- <https://man.openbsd.org/symlink.7>
- OpenBSD `sys/kern/kern_unveil.c` and the `unveil(2)` manual page for the exact
  target release.
