# `priv_sep`

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

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0).
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT).

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

### Status

This package will be actively maintained to stay in-sync with the latest version of OpenBSD; as a result,
the crate is only tested on the `x86_64-unknown-openbsd` target. While OpenBSD supports both the most recent
-release/-stable release as well as the previous version, only the most recent version will be supported by this
library. If using -stable, it may be necessary to build the
[`rust` port](https://github.com/openbsd/ports/tree/master/lang/rust) from -current.
