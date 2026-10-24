# Version and feature matrix

This reference records the configuration the repository currently claims and
tests. It is not a substitute for checking the target kernel and libc.

## OpenBSD releases

| Release | `getexecpath(3)` | Typed pledge inventory | Notes |
| --- | --- | --- | --- |
| OpenBSD 7.9 | absent from libc | 35 (default) | Shipped Rust 1.94.1. Default build target. |
| OpenBSD 8.0 | present | 33 with `openbsd-8-0`, 35 without | CI target. `getexecpath` requires the feature. |
| OpenBSD-current | verify per symbol | verify per kernel | Do not assume a name or limit is unchanged. |

The repository's `openbsd-8-0` feature both enables `getexecpath(3)` and removes
`Promise::Exec` / `Promise::Error` from the typed API. The latter is a crate
policy choice; the target kernel's `pledgereq` table must be verified
independently before concluding that the kernel rejects or accepts those names.
`pledge_raw` remains an unfiltered escape hatch.

## Cargo features

| Configuration | Public surface | Requirement |
| --- | --- | --- |
| default (`std` + `alloc`) | Full 7.9-compatible surface, 35 promises | OpenBSD 7.9+ |
| `--no-default-features` | Core-only API, no owned buffers, no exec helpers | OpenBSD 7.9+ |
| `--no-default-features --features alloc` | Core + owned buffers | OpenBSD 7.9+ |
| `--features openbsd-8-0` | Default + `get_execpath`, 33 promises | OpenBSD 8.0+ at link time |
| `--all-features` | `alloc` + `std` + `openbsd-8-0` | OpenBSD 8.0+ |

`std` implies `alloc`. `openbsd-8-0` does not imply either; it can be combined
with any feature set, but the test suite assumes the default surface.

## Item availability

| Item | default (`std`) | `--no-default-features` | `--features openbsd-8-0` |
| --- | --- | --- | --- |
| `pledge`, `unveil`, `chroot`, privileges, credentials | yes | yes | yes |
| `memory` functions | yes | yes | yes |
| `Rtable`, `random` core, `get_entropy` | yes | yes | yes |
| `arc4_random_bytes`, `get_entropy_bytes` | yes | no (needs `alloc`) | yes |
| `crypt_newhash`, `bcrypt_pbkdf` | yes | no (needs `alloc`) | yes |
| `fork_exec`, `fork_exec_pledged`, `exec_pledged`, `ForkExecError` | yes | no (needs `std`) | yes |
| `get_execpath` | no | no (unless the feature is added) | yes |
| `execpath` | no | no (needs `std` + feature) | yes |

`CStrHelper` has no-`alloc` behavior worth remembering: inputs of 1024 bytes or
more return `ERANGE`; with `alloc` they are converted through a `CString`.
Interior NUL bytes always return `EINVAL`.

## MSRV and toolchain

- Edition: 2024.
- `rust-version`: 1.85.0.
- The lint list is chosen for the Rust shipped by OpenBSD 7.9 (1.94.1). Unknown
  lint names are errors because warnings are denied.
- CI runs on OpenBSD 8.0 only. Neither 7.9 nor the MSRV is continuously tested.

## CI matrix

Both jobs run on OpenBSD 8.0, amd64 and arm64:

1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo check --all-targets`
4. `cargo test --all-features` (as `builder`, then as `root`)
5. `cargo build --no-default-features`
6. `cargo build --no-default-features --features alloc`
7. `cargo build --features openbsd-8-0`
8. `cargo check --all-features`
9. `cargo doc --no-deps --all-features`
10. `cargo package --allow-dirty`

The root run fails if the log contains `requires root privileges`, which would
mean a privileged test skipped.

## Known gaps

- No 7.9 job, no MSRV job, no `--no-default-features` test run.
- OpenBSD-current is a research target, not a tested target.
- `.yamllint` exists but is not invoked by the current workflow.
- The default-feature test surface cannot run on OpenBSD 8.0 because the
  35-promise `ALL` includes names the 8.0 inventory excludes.
- Version-sensitive contracts (`closefrom` errors, `getpeereid` under pledge,
  `mimmutable` holes) are asserted in the 8.0/amd64 and 8.0/arm64 CI jobs; run
  the same isolated tests manually on 7.9 before claiming support there.

