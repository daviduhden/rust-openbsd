---
name: rust-openbsd-pledge
description: Use when working on pledge(2), typed promises, pledge_parts, pledge_raw, execpromises, pledge_child, or pledge_both in rust-openbsd. Covers the promise inventory, monotonicity, NULL versus empty-string semantics, SIGABRT violations, and OpenBSD version differences.
---

# rust-openbsd pledge

## When to activate

Activate when a task:

- adds, removes, or renames a `Promise` variant;
- changes `Promises`, `pledge`, `pledge_both`, `pledge_child`, `pledge_parts`,
  `pledge_raw`, `promises_from_str`, or the `*_then_pledge` helpers;
- changes the `openbsd-8-0` promise inventory;
- documents, tests, or debugs an execution-promise ceiling;
- investigates a process that aborts with `SIGABRT` after a syscall;
- changes the interaction between pledge and unveil, fork, exec, or privilege
  dropping.

## When not to activate

Do not use this skill to add a general-purpose sandbox abstraction, to introduce
automatic promise widening, or to implement per-child policies for a single
process. Independent per-child promise ceilings require a process boundary. Use
`rust-openbsd-process` for fork/exec mechanics and `rust-openbsd-unveil` for
filesystem rules.

## Related files

- `src/pledge.rs` — implementation.
- `src/ffi.rs` — `pledge` declaration.
- `src/lib.rs` — documentation and re-exports.
- `tests/pledge.rs`, `src/tests.rs`, `tests/common/mod.rs` — tests and probes.
- `Cargo.toml` — `openbsd-8-0` feature.
- Reference: `rust-openbsd-platform/references/version-matrix.md`.

## Invariants

1. Promise sets are monotonic. A later call may only remove promises. An increase
   fails with `EPERM`, except when the legacy `error` promise is active, in which
   case the kernel silently ignores the increase and returns success.
2. `Promises` never grows after a successful pledge. `with` builds a value to
   pass to a future call; it does not grant authority to an already-pledged
   process.
3. `None` and `Some(&Promises::NONE)` are different:
   - `None` passes `NULL`: leave that argument unchanged.
   - `Some(&Promises::NONE)` passes `""`: set the argument to no promises.
   For `execpromises`, the empty string means future images start with no
   promises, not that the current process becomes `_exit`-only.
4. Violations are not recoverable errors. The kernel terminates the process with
   an uncatchable `SIGABRT` (unless the `error` promise returns `ENOSYS`).
5. `Exec` and `Error` are present in the default 35-promise inventory and absent
   from the 33-promise `openbsd-8-0` inventory. This is a crate API decision;
   verify the target kernel's table independently before assuming a name is
   accepted or rejected.
6. `tmppath` is not exposed. Current kernels reject it with `EINVAL`.
7. Exec promises are process-global, monotonic, and inherited across `fork(2)`;
   they apply at the descendant's `execve(2)`. They are not per-child and are not
   rolled back if a later spawn or exec fails.
8. Promise changes are process-wide. Applying a severe reduction to a
   multithreaded process can make the kernel unwind sibling threads while
   cleaning up unveil state, after which those threads perform forbidden
   syscalls and abort. The empty set is verified with a single-threaded native
   probe, not the multithreaded test runner.

## Safety contracts

`pledge_parts` encodes both sets into stack buffers and passes either a null
pointer or a pointer to a NUL-terminated string valid for the call. The buffers
are not shared. `pledge_raw` passes caller-owned `CStr`s unchanged. The crate
does not filter raw names. All public pledge functions are safe; the only
precondition is the process-wide, irreversible nature of the operation, which is
documented rather than encoded in the type system.

## Analysis procedure

1. Read the current `Promise` enum, `Promise::ALL`, `name`, `flag`, and the
   `openbsd-8-0` gates in `src/pledge.rs`.
2. Verify each native name against the target kernel's `pledgereq` table and the
   `pledge(2)` manual page. Check aliases, removed names, and version changes.
3. Confirm the inventory length and the `PLEDGE_BUFFER_LEN` computation.
4. Check `encode` ordering and the empty-set encoding (`b"\0"`).
5. Check the NULL/empty distinction for both arguments.
6. Check whether `*_then_pledge` can leave the tracked set disagreeing with the
   kernel. A bare `remove` does not call the kernel; a later no-op
   `remove_then_pledge` therefore will not synchronize it.
7. Check the effect of `fork`, `execve`, `unveil`, and credential changes on the
   promise state.
8. Check the multithreading hazard before writing an example that applies a
   major reduction.

## Implementation procedure

1. Add a variant only with its exact native name and an internal single-bit flag;
   flags never cross the FFI boundary.
2. Update `ALL`, `name`, `flag`, and the compile-time length.
3. Gate only what the OpenBSD version actually requires. Do not invent an
   `openbsd-X-Y` feature without verifying the symbol or API boundary.
4. Keep `Promises` non-`Copy`; preserve removal-only semantics.
5. Preserve rollback of the tracked set when the syscall fails.
6. Never add promises automatically to make a test or example pass.
7. Document `EPERM`, `EINVAL`, the `error`/`ENOSYS` exception, and the SIGABRT
   consequence.
8. Add a pure unit test for encoding and parsing, and an isolated child test for
   kernel behavior.

## Testing and acceptance

- Unit: inventory length, round-trip names, `tmppath` absence, set operations,
  empty encoding, ordering.
- Kernel, isolated child: valid set, `ALL` accepted, NULL no-op, monotonic
  reduction, exec increase `EPERM`, raw `tmppath` `EINVAL`, exec-promise probes.
- `SIGABRT` expectations use the child's termination status; never let the shared
  runner abort.
- The empty-promise-set and exec-promise probes use a small single-threaded C
  program and skip when `cc` cannot run.
- Run with `--all-features` on OpenBSD 8.0 and with default features on 7.9 when
  that version is available.

## References

- <https://man.openbsd.org/pledge.2>
- <https://man.openbsd.org/execve.2>
- <https://man.openbsd.org/fork.2>
- OpenBSD `sys/kern/kern_pledge.c`, `sys/sys/pledge.h`, and the `pledge(2)`
  manual page for the exact target release.
- <https://doc.rust-lang.org/reference/attributes/codegen.html> for the feature
  and `cfg` mechanics used by the gates.

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/check_agent_maintenance.py --base <base-ref>` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
