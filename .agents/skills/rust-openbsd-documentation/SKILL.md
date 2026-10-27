---
name: rust-openbsd-documentation
description: Use when updating README.md, Rustdoc, module docs, safety sections, examples, the API coverage table, feature documentation, error messages, version policy, licensing notices, or release metadata in rust-openbsd. Ensures documentation matches the native contract and the actual feature set.
---

# rust-openbsd documentation

## When to activate

Activate when a task:

- changes `README.md`, module-level `//!` docs, or item-level `///` docs;
- adds or edits a `# Safety`, `# Errors`, `# Pledge`, or examples section;
- updates the API coverage table, the supported-versions table, or the feature
  guide;
- changes an error message or a public error type;
- prepares a release, `Cargo.toml` metadata, or a crates.io publication;
- updates license or attribution text.

## When not to activate

Do not use this skill to disguise a code change as documentation, to describe a
mechanism as safer than it is, or to document an API that does not exist. Do not
add MIT licensing text: the repository is Apache-2.0 only; MIT is upstream
provenance.

## Related files

- `README.md` — user-facing guide, coverage table, versions, CI, licensing.
- `src/lib.rs` — crate-level guide and feature documentation.
- Every `src/*.rs` module and public item.
- `Cargo.toml` — description, license, MSRV, features, docs.rs metadata.
- `LICENSE`, copyright headers.
- `AGENTS.md` and the skills under `.agents/skills/`.

## Invariants

1. Every public item has documentation. `missing_docs` is denied; rustdoc lints
   are denied.
2. Every `unsafe fn` has a `# Safety` section explaining the caller's
   obligations in concrete terms.
3. Every fallible function documents `# Errors`, including the relevant `Errno`
   values and any non-`errno` failure.
4. Examples must compile under the feature and version configuration they claim.
   Use `no_run` for operations that change process state.
5. Do not describe a mechanism as complete isolation. Say what it does not cover
   (pledge does not restrict filesystem paths, unveil does not restrict syscalls,
   chroot is not a sandbox, privilege dropping does not sandbox).
6. Feature documentation must match `Cargo.toml`. `openbsd-8-0` currently both
   adds `getexecpath` and removes `Promise::Exec`/`Promise::Error` from the typed
   inventory.
7. Version claims must distinguish OpenBSD 7.9, 8.0, and OpenBSD-current. Do not
   imply that a 7.9 build links 8.0 symbols or that CI tests 7.9.
8. Error messages must not contain passwords, hashes, keys, or other secrets.
9. `README.md` and Rustdoc must agree on function names, module names, limits,
   and return types. When they disagree, verify the code and fix the text.
10. The license is Apache-2.0 only. Preserve the upstream attribution and the
    Apache header.
11. Do not turn the README into a changelog. Keep it a guide.
12. Keep intra-doc links valid for `cargo doc --all-features`; do not link to a
    variant removed by `openbsd-8-0` (use a code span instead).

## Safety contracts to document

- `mimmutable`: dedicated mapping, page rounding, permanent freeze, empty-slice
  no-op, and the fact that a safe slice cannot express an unmapped hole.
- `freezero`: `malloc` ownership, `len <= allocation`, no Rust allocator.
- Pledge: monotonicity, SIGABRT, NULL versus empty string, exec-promise
  inheritance.
- Unveil: replacement semantics, lock irreversibility, non-atomic multi-rule
  install, access-time denials.
- Privilege drop: fixed order, partial-failure fatality, saved IDs, root UID and
  root primary GID checks, and strict `Initgroups` membership comparison.
- Process helpers: no crate code in the post-fork child, `pre_exec` is caller
  code, exec promises are not rolled back.
- Daemonize: success never returns, failure exit status, panic hazard in `body`.

## Analysis procedure

1. Read the code and the native manual page for the item being documented.
2. Check the current `Cargo.toml` features and `src/lib.rs` gates.
3. Check every place the item is mentioned: README, crate docs, module docs,
   examples, skills, coverage table.
4. Check the return type and error behavior against the implementation, not
   against memory.
5. Check links and anchors; prefer explicit URLs in the README for module pages.
6. Check examples for feature gates and `no_run` where state changes.
7. Check whether a claim is about the crate policy or the kernel contract; label
   it accordingly.

## Implementation procedure

1. Change the item docs first, then the module guide, then the README table.
2. Use the existing voice and heading structure.
3. Use American English.
4. Add a `# Safety` section only for `unsafe` operations, and make it actionable.
5. Add a `# Pledge` section when a function is allowed or forbidden under a
   promise.
6. Keep examples minimal and use the same public paths as the crate root.
7. Update the coverage table when an API is added, deferred, or removed.
8. Update `AGENTS.md` or a skill when a durable contract changes.
9. Do not edit lints, features, or dependencies to make a doctest pass; fix the
   example or the feature claim.

## Source-first documentation

Keep architecture explanations in repository Markdown when they span multiple
modules, and keep local contracts beside their Rust declarations and
implementations. Use relative source links so a checkout is enough to follow the
explanation. External manual pages may be optional references, but do not make
them necessary to understand the implementation. When a task explicitly
requires self-contained, directly readable documentation or prohibits
documentation generation, do not run `cargo doc`; validate the Markdown, local
paths, comment language, and documentation-only diff directly instead.

## Testing and acceptance

- `cargo doc --no-deps --all-features` on any host (the `cfg(doc)` escape).
- `cargo test --doc` on OpenBSD for examples that compile.
- `cargo fmt --all -- --check`.
- `cargo clippy --all-targets --all-features -- -D warnings`.
- Check that every README module reference has a definition or an explicit URL.
- Acceptance requires no broken intra-doc links, no undocumented public item, no
  false safety claim, and no version claim that contradicts `Cargo.toml` or CI.

## Release checklist

1. Version and description in `Cargo.toml` are current.
2. `README.md` coverage, supported versions, features, testing, and CI match the
   repository.
3. `cargo package --allow-dirty` succeeds (then use a clean tree for the real
   release).
4. `cargo doc --no-deps --all-features` is clean.
5. License and copyright headers are present.
6. No secrets, local paths, or generated artifacts are included.
7. Do not publish, commit, or push without explicit authorization.

## References

- <https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html>
- <https://doc.rust-lang.org/rustdoc/documentation-tests.html>
- <https://doc.rust-lang.org/cargo/reference/manifest.html>
- <https://doc.rust-lang.org/cargo/reference/publishing.html>
- <https://docs.rs/about/metadata>
- <https://www.apache.org/licenses/LICENSE-2.0>
- OpenBSD manual pages for every documented function.

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/check_agent_maintenance.py --base <base-ref>` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
