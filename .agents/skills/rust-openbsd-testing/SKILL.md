---
name: rust-openbsd-testing
description: Use when adding or changing unit tests, integration tests, isolated child probes, pledge/unveil/credential/chroot tests, feature-matrix checks, Clippy, rustfmt, or kernel compatibility validation in rust-openbsd. Covers SIGABRT expectations, root skips, and the limits of static checks.
---

# rust-openbsd testing

## When to activate

Activate when a task:

- adds or modifies a test in `src/tests.rs` or `tests/`;
- changes `tests/common/mod.rs` or the child-process re-exec pattern;
- adds a privileged, irreversible, or signal-expecting test;
- changes CI commands, feature combinations, or root-stage checks;
- investigates a flaky kernel test, an unexpected `SIGABRT`, or a skipped test.

## When not to activate

Do not use this skill to run destructive tests on a developer or agent host.
Do not use it to replace a missing kernel test with `cargo check` or Clippy. Those
are static checks and cannot prove a security mechanism works.

## Related files

- `src/tests.rs` — pure unit tests, no kernel.
- `tests/*.rs` — one integration binary per module area.
- `tests/common/mod.rs` — child re-exec, signal assertions, root skips, C probes.
- `.github/workflows/ci.yml` — the tested matrix.
- `scripts/check_agent_maintenance.py` — the repository instruction/skill gate; lint
  it with `ruff check` and `ruff format --check` when changing the validator.
- Reference: `references/test-harness.md`.

## Invariants

1. A test that changes credentials, pledge/unveil state, the filesystem root,
   process titles, program name, descriptors, or exec promises must run in an
   isolated child process. Re-exec the test binary with
   `--exact <name> --ignored --test-threads=1`; never restrict the shared runner.
2. Child tests are marked `#[ignore = "isolated child process"]`; a parent test
   runs them through `run_child` and asserts the child's status.
3. A pledge violation is an uncatchable `SIGABRT` (signal 6). Assert the child's
   termination signal with `assert_sigabrt`; never let the parent process abort.
4. Terminate a restricted child with `_exit(2)` (`exit_now`), not
   `std::process::exit`, which performs further syscalls.
5. Tests that require root use `skip_without_root` and print exactly
   `requires root privileges`; CI greps for that string. Tests that must not run
   as root skip with a different, explicit message.
6. Never run a privileged test on a host whose credentials or filesystem you do
   not want to change. Use an OpenBSD VM or a disposable environment.
7. Never run destructive tests while doing documentation-only work.
8. Child processes inherit the parent's working directory and environment;
   probe paths must be unique across threads and processes.
9. The C probes are optional. A missing `cc` or a failed compile/link returns
   `None` and the caller prints a skip. Do not turn that into a panic.
10. Feature-specific tests use `#[cfg(feature = "...")]`; the standard CI run is
    `--all-features`, which changes the pledge inventory.

## Safety contracts

The harness may panic to report a failure and may use raw `_exit`; both are
confined to test code with crate-level allows. Child tests are still real
processes with real kernel state. The harness does not create a container or
namespace: a root-only chroot test uses a directory under `/tmp` and must clean
up even on panic. Keep `catch_unwind` cleanup where it exists.

## Analysis procedure

1. Classify the test: pure unit, unprivileged kernel, privileged kernel, signal
   expectation, feature-gated, or native-probe.
2. Determine whether it modifies process-wide or irreversible state.
3. If it does, route it through `run_child`; if it needs root, add the skip.
4. Check the assertion: exit status, signal, `Errno`, or returned value.
5. Check cleanup, unique paths, and parallel-test safety.
6. Check the feature gate and whether the test compiles under the default
   surface.
7. Check whether the test would still pass if the implementation were inverted.
8. Check the CI stage that will run it and whether a skip would be detected.

## Implementation procedure

1. Add pure logic tests to `src/tests.rs`.
2. Add kernel tests to the matching `tests/*.rs`.
3. Write the child body as an ignored test and the parent as a normal test that
   calls `run_child`.
4. Use `assert_success`, `assert_sigabrt`, or `assert_signal`; print child output
   on failure.
5. Use `skip_without_root` for root-required cases and an explicit
   `running as root` skip for root-forbidden cases.
6. Use unique probe paths based on `process::id()` and a counter.
7. If a native probe is required, compile it with `cc`, link statically when the
   exec-promise ceiling requires it, and return `None` on any spawn or compile
   failure.
8. Keep cleanup best-effort and panic-safe.

## Testing and acceptance

On OpenBSD:

```sh
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --all-features -- --nocapture   # as root, in a disposable VM
cargo doc --no-deps --all-features
cargo build --no-default-features
cargo build --no-default-features --features alloc
cargo build --features openbsd-8-0
```

Classify the result honestly:

1. static analysis;
2. successful compilation;
3. unit tests;
4. kernel integration tests;
5. privileged tests;
6. verified on another OpenBSD release.

Never call a mechanism “tested” when only step 1 or 2 succeeded.

## References

- <https://doc.rust-lang.org/cargo/commands/cargo-test.html>
- <https://doc.rust-lang.org/rustc/tests/index.html>
- <https://doc.rust-lang.org/rustdoc/documentation-tests.html>
- <https://man.openbsd.org/pledge.2>
- <https://man.openbsd.org/unveil.2>
- <https://man.openbsd.org/fork.2>
- <https://man.openbsd.org/sigaction.2>
- `references/test-harness.md` in this skill.

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/check_agent_maintenance.py --base <base-ref>` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
