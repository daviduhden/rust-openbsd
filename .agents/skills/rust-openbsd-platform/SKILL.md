---
name: rust-openbsd-platform
description: Use when working on OpenBSD version support, Cargo features, openbsd-8-0, MSRV, Edition 2024, no_std, alloc, std, cfg(doc), package metadata, or dependency policy in rust-openbsd. Covers 7.9, 8.0, OpenBSD-current, and the limits of the CI matrix.
---

# rust-openbsd platform and Cargo

## When to activate

Activate when a task:

- adds or changes a Cargo feature or a `cfg` gate;
- changes the supported OpenBSD versions, the MSRV, or the edition;
- introduces a symbol that may be absent from an older libc;
- changes `no_std`, `alloc`, or `std` behavior;
- changes `docs.rs` metadata, `cfg(doc)`, or package metadata;
- evaluates a dependency or a compatibility shim.

## When not to activate

Do not use this skill to add Linux/FreeBSD/macOS/Windows support or an emulation
layer. Do not use it to raise the MSRV without explicit authorization. For the
native contract of a function, load the relevant domain skill as well.

## Related files

- `Cargo.toml` — package, MSRV, features, lints, docs.rs metadata.
- `src/lib.rs` — `#![no_std]`, `cfg(doc)`, `compile_error!`, re-exports.
- `src/pledge.rs`, `src/process.rs` — `openbsd-8-0` gates.
- `.github/workflows/ci.yml` — actual tested matrix.
- `README.md` — advertised support.
- Reference: `references/version-matrix.md`.

## Invariants

1. The crate is OpenBSD-only. Non-OpenBSD builds fail with `compile_error!`
   unless `cfg(doc)` is set. Do not add a fallback that makes a non-OpenBSD build
   appear to provide OpenBSD security guarantees.
2. `cargo doc` is the only cross-host build path. Preserve
   `#[cfg(all(not(target_os = "openbsd"), not(doc)))]` around the error.
3. `#![no_std]` is permanent. `alloc` and `std` are additive; `std` implies
   `alloc`; shared code uses `core`.
4. Edition 2024 and MSRV 1.85.0 are declared in `Cargo.toml`. Do not raise the
   MSRV without authorization. The lint list is tuned for the Rust shipped by
   OpenBSD 7.9 (1.94.1); unknown lints are errors under `warnings = deny`.
5. `openbsd-8-0` has two effects: it enables `getexecpath`/`execpath` and it
   removes `Promise::Exec`/`Promise::Error` from the typed inventory. Enabling it
   requires OpenBSD 8.0+ at link time.
6. The default feature set must remain link-compatible with OpenBSD 7.9. Never
   add an 8.0-only symbol outside a feature gate.
7. Do not add a runtime dependency to emulate a system facility. The crate has
   no dependencies and should stay that way unless a task explicitly authorizes
   an exception with a technical justification.
8. Do not claim CI covers 7.9, the MSRV, or every feature combination. The
   current matrix runs on OpenBSD 8.0 with `--all-features` plus build checks.
9. The `cfg(doc)` path must not accidentally enable runtime behavior. It only
   suppresses the compile error.
10. Removing a feature or an API requires checking every `cfg`, re-export,
    README table, skill, and test that references it.

## Safety contracts

Feature gates are safety-relevant: an 8.0-only symbol in a default build fails
to link on 7.9, and a missing `cfg` can make a security API disappear silently.
`cfg(doc)` must never be used to fake a native implementation. A feature must not
silently widen a promise set, add an unveil rule, or change a credential
operation.

## Analysis procedure

1. Read `Cargo.toml` and `src/lib.rs` for the declared edition, MSRV, features,
   lints, and re-exports.
2. Determine the minimum OpenBSD release that provides every symbol in the
   affected code path.
3. Check the feature graph: default, `alloc`, `std`, `openbsd-8-0`, and their
   combinations.
4. Check every `#[cfg]` in the affected modules and tests.
5. Check the CI workflow to see what is actually exercised.
6. Check the README and Rustdoc claims against the code.
7. For a new symbol, inspect the target's libc and headers; do not infer
   availability from OpenBSD-current alone.
8. For a dependency proposal, check whether the standard library or libc already
   covers the need.

## Implementation procedure

1. Add the feature to `Cargo.toml` with a comment stating the native boundary and
   the resulting OS requirement.
2. Gate the declaration, wrapper, re-export, and tests consistently. Missing one
   layer is the usual bug.
3. Keep the default surface 7.9-compatible.
4. Add `#[cfg_attr(docsrs, doc(cfg(feature = "...")))]` where it helps docs.rs;
   `docsrs` builds with `all-features`.
5. Do not add `build.rs`, a C shim, or a dependency unless the task explicitly
   requires it and the tradeoff is documented.
6. Update the version matrix reference and the README feature section.
7. Verify the no-feature builds separately from the default build.

## Testing and acceptance

On OpenBSD 8.0 (the CI target):

```sh
cargo check --all-targets
cargo build --no-default-features
cargo build --no-default-features --features alloc
cargo build --features openbsd-8-0
cargo check --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps --all-features
```

On OpenBSD 7.9, verify the default build and tests separately; CI does not do it.
`cargo test --no-default-features` is not supported because the integration tests
use the default surface. Acceptance requires that a default build still links on
7.9, that 8.0-only symbols stay gated, and that no feature silently changes a
security guarantee.

## References

- <https://doc.rust-lang.org/cargo/reference/features.html>
- <https://doc.rust-lang.org/reference/conditional-compilation.html>
- <https://doc.rust-lang.org/rustc/platform-support/openbsd.html>
- <https://doc.rust-lang.org/cargo/reference/manifest.html#the-rust-version-field>
- <https://doc.rust-lang.org/nightly/rustdoc/unstable-features.html#doc_cfg>
- <https://www.openbsd.org/faq/faq15.html> for OpenBSD packages.
- OpenBSD release notes and the target's `libc` symbol table.
- `references/version-matrix.md` in this skill.

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/check_agent_maintenance.py --base <base-ref>` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
