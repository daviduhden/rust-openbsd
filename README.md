# `priv_sep`

[<img alt="git" src="https://git.philomathiclife.com/badges/priv_sep.svg" height="20">](https://git.philomathiclife.com/priv_sep/log.html)
[<img alt="crates.io" src="https://img.shields.io/crates/v/priv_sep.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/priv_sep)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-priv_sep-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="20">](https://docs.rs/priv_sep/latest/priv_sep/)

`priv_sep` is a library that uses the system's libc to perform privilege separation and privilege reduction.

## `priv_sep` in action for OpenBSD

```rust
use core::convert::Infallible;
use priv_sep::{Permissions, PrivDropErr, Promise, Promises};
use std::{
    fs,
    io::Error,
    net::{Ipv6Addr, SocketAddrV6},
};
use tokio::net::TcpListener;
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<Infallible, PrivDropErr<Error>> {
    /// Config file.
    const CONFIG: &str = "config";
    // Get the user ID and group ID for nobody from `passwd(5)`.
    // `chroot(2)` to `/path/chroot/` and `chdir(2)` to `/`.
    // `pledge(2)` `id`, `inet`, `rpath`, `stdio`, and `unveil`.
    // Bind to TCP `[::1]:443` as root.
    // `setresgid(2)` to the group ID associated with nobody.
    // `setresuid(2)` to the user ID associated with nobody.
    // Remove `id` from our `pledge(2)`d promises.
    let (listener, mut promises) = Promises::new_chroot_then_priv_drop_async(
        "nobody",
        "/path/chroot/",
        [Promise::Inet, Promise::Rpath, Promise::Unveil],
        false,
        async || TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await,
    ).await?;
    // At this point, the process is running under nobody.
    // Only allow file system access to `config` and only allow read access to it.
    Permissions::READ.unveil(CONFIG)?;
    // Read `config`.
    // This will of course fail if the file does not exist or nobody does not
    // have read permissions.
    let config = fs::read(CONFIG)?;
    // Remove file system access.
    Permissions::NONE.unveil(CONFIG)?;
    // Remove `rpath` and `unveil` from our `pledge(2)`d promises
    // (i.e., only have `inet` and `stdio` abilities when we begin accepting TCP connections).
    promises.remove_promises_then_pledge([Promise::Rpath, Promise::Unveil])?;
    loop {
        // Handle TCP connections.
        if let Ok((_, ip)) = listener.accept().await {
            assert!(ip.is_ipv6());
        }
    }
}
```

## `priv_sep` in action for Unix-like OSes

```rust
use core::convert::Infallible;
use priv_sep::{UserInfo, PrivDropErr};
use std::{
    io::Error,
    net::{Ipv6Addr, SocketAddrV6},
};
use tokio::net::TcpListener;
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<Infallible, PrivDropErr<Error>> {
    // Get the user ID and group ID for nobody from `passwd(5)`.
    // `chroot(2)` to `/path/chroot/` and `chdir(2)` to `/`.
    // Bind to TCP `[::1]:443` as root.
    // `setresgid(2)` to the group ID associated with nobody.
    // `setresuid(2)` to the user ID associated with nobody.
    let listener = UserInfo::chroot_then_priv_drop_async("nobody", "/path/chroot/", false, async || {
        TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)).await
    }).await?;
    // At this point, the process is running under nobody.
    loop {
        // Handle TCP connections.
        if let Ok((_, ip)) = listener.accept().await {
            assert!(ip.is_ipv6());
        }
    }
}
```

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

Before any PR is sent, `cargo clippy` and `cargo t` should be run. Additionally
`RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --all-features` should be run to ensure documentation can be built.

### Status

The crate is only tested on the `x86_64-unknown-linux-gnu`, `x86_64-unknown-openbsd`, and `aarch64-apple-darwin`
targets; but it should work on most platforms.
