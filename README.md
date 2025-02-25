# `priv_sep`

[<img alt="git" src="https://git.philomathiclife.com/badges/priv_sep.svg" height="20">](https://git.philomathiclife.com/priv_sep/log.html)
[<img alt="crates.io" src="https://img.shields.io/crates/v/priv_sep.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/priv_sep)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-priv_sep-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="20">](https://docs.rs/priv_sep/latest/priv_sep/)

`priv_sep` is a library for privilege separation.
It is currently designed around [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) and
[`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) for OpenBSD, but
in the future may contain functionality for Linux's
[`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html).

## Pledge

Calls to `pledge(2)` are done via `Promises::pledge` and `pledge_none`.

Note that since the use of `execpromises` is quite rare, `NULL` is always used for it.

## Unveil

Calls to `unveil(2)` are done via `Permissions::unveil` and `unveil_no_more`.

## Errors

Any error returned from the underlying system call is propagated via `Error`.

## Minimum Supported Rust Version (MSRV)

This will frequently be updated to be the same as stable. Specifically, any time stable is updated and that
update has "useful" features or compilation no longer succeeds (e.g., due to new compiler lints), then MSRV
will be updated.

MSRV changes will correspond to a SemVer minor version bump.

## SemVer Policy

* All on-by-default features of this library are covered by SemVer
* MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](https://www.apache.org/licenses/LICENSE-2.0))
* MIT license ([LICENSE-MIT](https://opensource.org/licenses/MIT))

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

Before any PR is sent, `cargo clippy` and `cargo t` should be run for both `--no-default-features` and
`--all-features`. Additionally `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --all-features` should be run to
ensure documentation can be built.

### Status

This package will be actively maintained to stay in-sync with the latest version of OpenBSD; as a result,
the crate is only tested on the `x86_64-unknown-openbsd` target. While OpenBSD supports both the most recent
-release/-stable release as well as the previous version, only the most recent version will be supported by this
library. If using -stable, it may be necessary to build the
[`rust` port](https://github.com/openbsd/ports/tree/master/lang/rust) from -current.
