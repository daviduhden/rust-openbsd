---
name: rust-openbsd-process
description: Use when working on fork, exec, fork_exec, fork_exec_pledged, exec_pledged, daemonize, DaemonOptions, closefrom, getdtablecount, setproctitle, getprogname, setprogname, getexecpath, or descriptor hygiene in rust-openbsd. Covers post-fork restrictions, exec-promise ceilings, and signal/exit behavior.
---

# rust-openbsd process and descriptors

## When to activate

Activate when a task:

- changes `fork_exec`, `fork_exec_pledged`, `exec_pledged`, or `ForkExecError`;
- changes `daemonize`, `daemonize_with`, `DaemonOptions`, or
  `default_daemon_options`;
- changes `close_from`, `dtable_count`, `set_proctitle`, `reset_proctitle`,
  `set_progname`, `progname`, `get_execpath`, or `execpath`;
- works on `FD_CLOEXEC`, descriptor inheritance, or descriptor-range cleanup;
- changes post-fork or pre-exec behavior, signal handling, or exit status.

## When not to activate

Do not use this skill for `pledge` inventory semantics (load
`rust-openbsd-pledge`) or for credential dropping (load
`rust-openbsd-privileges`). Do not add a raw-`fork` helper for application code
unless the existing `std::process::Command` model cannot express the requirement.

## Related files

- `src/process.rs` — implementation.
- `src/ffi.rs` — `fork`, `setsid`, `dup2`, `close`, `open`, `_exit`,
  `closefrom`, `getdtablecount`, `setproctitle`, `getprogname`, `setprogname`,
  `getexecpath`.
- `tests/process.rs`, `tests/common/mod.rs`, `src/tests.rs`.
- `README.md`, `src/lib.rs`.

## Invariants

1. `fork_exec` only calls `Command::spawn`; it sets no pledge policy.
   `fork_exec_pledged` sets the execution ceiling in the parent and then spawns.
   `exec_pledged` sets the ceiling and replaces the current image without
   forking.
2. The crate runs no code in a `Command`'s post-fork child. A caller-installed
   `pre_exec` closure is caller code and must obey the post-fork rules itself.
3. Exec promises are process-global and monotonic, and are not rolled back if the
   later spawn or exec fails.
4. In a multithreaded process, only async-signal-safe operations are reliable
   after `fork` and before `exec`. No allocation, locks, `std::fs::read_dir`,
   unwinding, or arbitrary Rust in that window.
5. `daemonize`/`daemonize_with` fork once, the parent `_exit(0)`s, the child
   `setsid`s, optionally `chdir("/")`, optionally redirects 0/1/2 to
   `/dev/null`, runs the body, and `_exit(0)`s. On success they never return.
   Only a failed `fork(2)` returns `Err`; a failed `setsid`, requested
   `chdir`, or redirection exits the child with status 1.
6. Daemonizing is explicit, never automatic. Foreground operation is supported
   and preferred under modern service supervision.
7. `close_from` closes every descriptor `>= lowfd`, including the argument and
   runtime-managed descriptors; it now returns `Result<(), Errno>` so failures
   are observable. A negative `lowfd`, or one greater than every open
   descriptor, is `EBADF` and closes nothing. Do not assume descriptors are
   contiguous, and do not confuse `dtable_count` with the highest descriptor.
8. `dtable_count` cannot fail, is a snapshot, and counts 0/1/2 if open. It is not
   a bound for iteration.
9. `set_proctitle` always passes a fixed `"%s"` format and the title as data.
   `reset_proctitle` passes `NULL` with no varargs. `set_progname` takes
   `&'static CStr` because libc stores the pointer.
10. `progname` is process-global, may come from `argv[0]`, and must not be
    trusted in a set-ID program. Use `is_setugid` before relying on it.
11. `get_execpath` is gated behind `openbsd-8-0`; `execpath` additionally needs
    `std`. The buffer should be `PATH_MAX` bytes; the returned length excludes
    the NUL.
12. Descriptor inheritance and `FD_CLOEXEC` are the caller's responsibility when
    using `Command`. Prefer closing or marking descriptors explicitly rather
    than scanning huge ranges.

## Safety contracts

`daemonize_with` is safe but forks and runs a caller closure after `fork`; its
documentation carries the correctness, not memory-safety, obligation. The
crate-side child path is allocation-free and lock-free. `close_from` is a
memory-safe but process-global operation. `setprogname`'s `'static` bound is the
safety invariant that keeps libc's stored pointer valid. `exec_pledged` returns
`std::io::Error` only on failure and is marked `#[must_use]`.

## Analysis procedure

1. Identify whether the code forks, execs, daemonizes, or only changes metadata.
2. For any fork, list exactly what runs in the child before exec and check it
   against the async-signal-safe set.
3. Check whether allocation, locks, locale, stdio, or runtime state can be
   touched in the child.
4. Check descriptor assumptions: 0/1/2 reuse, closing Rust-owned descriptors,
   `FD_CLOEXEC`, and non-contiguous descriptor numbers.
5. Check the interaction with existing exec promises and with a current pledge.
6. Check signal and exit-status behavior. `_exit` is used deliberately; do not
   substitute `std::process::exit`.
7. Check feature gates and `no_std`/`alloc`/`std` availability.

## Implementation procedure

1. Prefer `std::process::Command` over a raw `fork`.
2. If a raw `fork` is unavoidable, keep the child path to async-signal-safe
   syscalls and call `_exit` directly.
3. Never add allocation, logging, `Errno` formatting, or Rust destructors to the
   child path.
4. Preserve the never-returns contract of daemonization and fail closed on a
   partial transition.
5. Keep descriptor cleanup explicit and observable; do not add a scan over an
   assumed dense range.
6. Keep `set_proctitle`'s fixed format string and `set_progname`'s `'static`
   bound.
7. Keep `get_execpath` gated and documented as an 8.0+ symbol.
8. Add isolated child tests for anything that changes process-wide state.

## Testing and acceptance

- Isolated child: titles, program name, `close_from` error contract (negative
  `lowfd` and a high threshold both return `EBADF`), daemonize never returning,
  the `child_transition_permitted` fail-closed decision table, `fork_exec_pledged`,
  `exec_pledged`, and the exec-ceiling violation (`SIGABRT`).
- The syscall-level failure of `chdir("/")` or the `/dev/null` redirection is
  not injected by the normal suite. A true failure test requires a root VM or a
  dedicated fault-injection harness; the decision that turns either failure into
  child exit status 1 is unit-tested.
- Parent tests may query `dtable_count` and `progname` safely.
- `get_execpath` tests require `--features openbsd-8-0` and OpenBSD 8.0+.
- Never run `daemonize` or `exec_pledged` in the shared test process.
- CI runs these tests on OpenBSD 8.0/amd64 and 8.0/arm64; OpenBSD 7.9 is manual.
- Acceptance requires documented post-fork rules, no silent descriptor-hygiene
  failure, and no claim that `fork_exec` sets a policy.

## References

- <https://man.openbsd.org/fork.2>
- <https://man.openbsd.org/execve.2>
- <https://man.openbsd.org/daemon.3>
- <https://man.openbsd.org/setsid.2>
- <https://man.openbsd.org/closefrom.2>
- <https://man.openbsd.org/getdtablecount.2>
- <https://man.openbsd.org/setproctitle.3>
- <https://man.openbsd.org/setprogname.3>
- <https://man.openbsd.org/getprogname.3>
- <https://man.openbsd.org/getexecpath.3>
- <https://man.openbsd.org/_exit.2>
- <https://pubs.opengroup.org/onlinepubs/9699919799/functions/fork.html> for the
  async-signal-safe list.

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/check_agent_maintenance.py --base <base-ref>` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
