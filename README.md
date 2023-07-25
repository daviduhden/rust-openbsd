# `priv_sep`  
  
[`priv_sep`](https://docs.rs/priv_sep/latest/priv_sep) is a library for privilege separation.
It is currently designed around [`pledge(2)`](https://man.openbsd.org/amd64/pledge.2) and
[`unveil(2)`](https://man.openbsd.org/amd64/unveil.2) for OpenBSD-stable—that is correct, `stable` not `current`—
but in the future may contain functionality for Linux's
[`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html).  
  
## Pledge  
  
It is very rare to use the `execpromises` parameter, so [`pledge`] only relies on [`Promise`]s.
Additionally this function cannot be used to invoke `pledge(2)` with a `promises` value of `""`.  
  
## Unveil  
  
Unlike `pledge(2)` which allows a large quantity of duplicate `promises` to be provided, `unveil(2)` allows a maximum
of four `permissions` to be passed. For this reason, there are dedicated functions for each quantity of
[`Permission`]s.  
  
## Errors  
  
Any error returned from the underlying system call is propagated via
[`c_int`](https://doc.rust-lang.org/core/ffi/type.c_int.html). Note for both `pledge(2)` and `unveil(2)` duplicates
are ignored, so it is not an error to pass in duplicate values for their corresponding functions in this crate.  
  
### Status  
  
This package will be actively maintained to stay in-sync with the latest version of OpenBSD-stable; as a result,
the crate is only tested on the `x86_64-unknown-openbsd` target. While OpenBSD supports both the most recent
`release/stable` release as well as the previous version, only the most recent version will be supported by this
library. For that reason any removal of `promises` in subsequent releases of `pledge(2)` will lead to breaking
changes in this library as the corresponding `Promise` variant will be removed.  
  
### Building and testing  
  
```bash
laptop$ git clone https://git.philomathiclife.com/repos/priv_sep
Cloning into 'priv_sep'...
laptop$ cd priv_sep/
laptop$ cargo build --release
    Updating crates.io index
   Compiling priv_sep v0.1.0 (/home/zack/projects/priv_sep)
    Finished release [optimized] target(s) in 1.35s
laptop$ cargo t
   Compiling priv_sep v0.1.0 (/home/zack/projects/priv_sep)
    Finished test [unoptimized + debuginfo] target(s) in 0.33s
     Running unittests src/lib.rs (target/debug/deps/priv_sep-2b69b951a87c3632)

running 1 test
test tests::test ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests priv_sep

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

```
