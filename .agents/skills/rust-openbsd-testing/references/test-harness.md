# Test harness reference

## Layout

- `src/tests.rs`: pure unit tests. Must run on any host; no kernel calls.
- `tests/<area>.rs`: one integration binary per area. Each may declare
  `mod common;`.
- `tests/common/mod.rs`: shared helpers. It is a module, not an integration
  target.

Current integration binaries: `authentication`, `chroot`, `credentials`,
`memory`, `pledge`, `privileges`, `process`, `random`, `rtable`, `unveil`.

## Isolation model

A destructive child test is a normal libtest function marked:

```rust
#[test]
#[ignore = "isolated child process"]
fn child_something() { /* ... */ }
```

A parent test re-executes the same binary:

```rust
Command::new(std::env::current_exe()?)
    .args(["--exact", "child_something", "--ignored", "--nocapture", "--test-threads=1"])
    .output()
```

The child runs exactly one test, single-threaded, so it cannot restrict or
de-privilege the shared runner. Children usually end with `exit_now(0)`.

## Helpers

| Helper | Purpose |
| --- | --- |
| `SIGABRT` | Signal number 6 |
| `exit_now(code)` | Raw `_exit(2)`; required after `_exit`-only pledge |
| `is_root()` | `Uid::geteuid().is_root()` |
| `run_child(name)` | Re-exec the binary for one ignored test |
| `assert_success` | Child exited 0; prints stdout/stderr on failure |
| `assert_signal` | Child died by the expected signal |
| `assert_sigabrt` | Child died by `SIGABRT` |
| `skip_without_root` | Prints `SKIP <name>: requires root privileges` |
| `compile_exec_probe` | Static C probe for exec-promise tests |
| `compile_empty_pledge_probe` | Single-threaded C probe for the empty set |

Both compile helpers return `None` when `cc` cannot be spawned or compilation
fails. A caller prints a skip; it must not panic.

## Root and skip conventions

- Root-required: privilege-drop tests and `enter_chroot_confines_the_process`.
  Use `skip_without_root`; CI fails if the log contains
  `requires root privileges`.
- Root-forbidden: `drop_without_privilege_is_eperm` and
  `an_unknown_domain_is_rejected`. Print `SKIP ...: running as root`.
- `cc`-dependent: empty-promise and exec-promise tests. Print a skip when the
  probe is `None`.

## Signal expectations

A pledge violation is not a returned error. The child is terminated by
`SIGABRT`; the parent checks `ExitStatusExt::signal()`. Never call the violating
operation in the parent. The empty-promise set is exercised by a dedicated
single-threaded C probe because reducing a multithreaded libtest process makes
the kernel unwind sibling threads and produces nondeterministic aborts.

## Feature-specific tests

- `error` promise tests: `#[cfg(not(feature = "openbsd-8-0"))]`.
- `getexecpath` / `execpath`: `#[cfg(feature = "openbsd-8-0")]`.
- `arc4_random_bytes` / `get_entropy_bytes`: `#[cfg(feature = "alloc")]`.
- `ForkExecError` display: `#[cfg(feature = "std")]`.

The standard CI run uses `--all-features`. The default 35-promise test surface
is not run on OpenBSD 8.0; it is only compiled with `cargo check --all-targets`.

## Contract tests for version-sensitive behavior

| Behavior | Test | Notes |
| --- | --- | --- |
| `closefrom(-1)` is `EINVAL` | `child_close_from_error_contract` | High threshold must be `Ok(())`; 8.0 amd64/arm64 CI, 7.9 manual |
| `getpeereid` under `stdio + unix` | `child_peer_credentials_with_unix_promise` | Isolated child |
| `getpeereid` under `stdio` only aborts | `child_peer_credentials_without_socket_promise_aborts` | Expects `SIGABRT` |
| `mimmutable` empty slice is a no-op | `mimmutable_empty_slice_is_a_noop` | Unit-level, safe wrapper |
| `mimmutable` skips an unmapped hole | `mimmutable_skips_unmapped_holes` | Raw syscall; a safe slice cannot span a hole |
| Daemon transition is fail-closed | `daemonize_requires_every_requested_transition` | Decision table; syscall failure needs a root VM |
| `Initgroups` membership is strict | root-only `child_drop_privileges_initgroups` | Uses `getgrouplist(3)` |
| Root primary GID is rejected by named drops | `named_drops_reject_root_identity` | Unit-level policy |

## CI stages

Each of the amd64 and arm64 jobs boots OpenBSD 8.0 and:

1. installs `rust`, `rust-clippy`, `rust-rustfmt`;
2. creates a `builder` user;
3. runs fmt, Clippy, `cargo check --all-targets`, `cargo test --all-features`,
   the no-default/alloc/8.0 builds, `cargo check --all-features`, docs, and
   `cargo package --allow-dirty` as `builder`;
4. runs `cargo test --all-features -- --nocapture` as root;
5. fails if the root log contains `requires root privileges`.

## Known gaps

- No OpenBSD 7.9 job.
- No MSRV 1.85.0 job.
- No `cargo test` for no-default/alloc configurations.
- No timeout per test; only the job timeout.
- Probe source files are left in `/tmp`.
- A root-only chroot test is not namespace-isolated.
- The daemonize `chdir`/redirection failure path has no syscall-failure
  injection; only the fail-closed decision table is unit-tested.
- Run the `closefrom`, `getpeereid`-under-pledge, and `mimmutable` hole tests
  manually on OpenBSD 7.9; CI covers only 8.0 on amd64 and arm64.
