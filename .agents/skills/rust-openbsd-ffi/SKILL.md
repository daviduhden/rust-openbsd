---
name: rust-openbsd-ffi
description: Use when adding, changing, or auditing any FFI declaration, unsafe block, C string conversion, errno handling, or native ABI mapping in rust-openbsd. Applies to work in src/ffi.rs, src/cstr.rs, src/error.rs, and the unsafe wrappers in every module.
---

# rust-openbsd FFI and unsafe code

## When to activate

Activate when a task:

- adds or changes an `unsafe extern "C"` declaration or a `safe fn` declaration;
- introduces, removes, or reviews an `unsafe` block or `unsafe fn`;
- maps a C type, structure layout, constant, or return convention;
- converts Rust strings, paths, or byte slices to `CStr`;
- handles `errno`, `Errno`, or a native error code;
- changes pointer ownership, lifetimes, aliasing, or thread-safety assumptions;
- adds a `# Safety` contract or a wrapper around a raw native call.

## When not to activate

Do not use this skill for kernel semantics alone: `pledge` promise behavior,
unveil rule interaction, credential ordering, and process policy belong to their
own skills. Use this skill for the *representation and calling convention*, and
load the domain skill for the *native contract*.

## Related files

- `src/ffi.rs` — all extern declarations and `Passwd`.
- `src/cstr.rs` — `CStrHelper` and NUL handling.
- `src/error.rs` — `Errno`, `from_raw`, `into_raw`, `last`, `set`, `clear`.
- `src/credentials.rs`, `src/chroot.rs`, `src/memory.rs`, `src/pledge.rs`,
  `src/privileges.rs`, `src/process.rs`, `src/random.rs`, `src/unveil.rs` —
  unsafe call sites.
- `tests/authentication.rs`, `tests/memory.rs` — NUL and pointer behavior.
- Reference: `references/ffi-surface.md`.

## Invariants

1. A safe public function has no memory-safety precondition. If the caller must
   guarantee a mapping, ownership, alignment, lifetime, or initialized memory,
   the function is `unsafe` and documents a `# Safety` section.
2. Every `unsafe` block performs one operation and carries a nearby
   `// SAFETY:` comment with a concrete argument. The crate denies
   `unsafe_code`, `undocumented_unsafe_blocks`, and
   `multiple_unsafe_ops_per_block`.
3. All pointers passed to C are non-null unless the C contract permits null,
   correctly aligned, valid for the call, and point to initialized memory.
4. Every length argument is the exact byte or element count of the buffer it
   describes. Never pass a capacity as a length or vice versa.
5. A returned pointer is dereferenced only when non-null and only for its
   documented lifetime. Never extend a borrow beyond the native guarantee.
6. `errno` is read immediately in the same thread. Do not cache `__errno()` or
   insert another libc call between the failure and `Errno::last()`.
7. Native return conventions are preserved exactly. Zero is success only where
   the C API says so.
8. No Rust panics or unwinding cross an FFI boundary (`ffi_unwind_calls` is
   denied).

## Safety contracts to check

- `CStr`: the interior-NUL check happens before the syscall. `CStrHelper`
  rejects `NUL` with `EINVAL`; without `alloc`, inputs of 1024 bytes or more fail
  with `ERANGE`.
- `mimmutable`: the caller guarantees a dedicated page-rounded mapping. The
  wrapper treats an empty slice as a no-op. The kernel rounds start down and end
  up and skips unmapped holes.
- `freezero`: ownership transfers; `ptr` must come from a `malloc(3)`-compatible
  allocator and `len` must not exceed the allocation. Never pass Rust heap,
  stack, static, or `mmap` memory.
- `mutable` out-parameters (`getresuid`, `getresgid`, `getgroups`,
  `getpeereid`, `getpwnam_r`, `getexecpath`): every pointer references a live,
  aligned, writable object; initialization happens only after the documented
  success condition.
- `getpwnam_r`: returns an error number directly, not `-1`. `*result == NULL`
  means “no entry”. `pw_name` points into the caller's `buf`.
- `getgrouplist`: `ngroups` is an in/out parameter; initialize it to the buffer
  capacity, treat a negative return as “buffer too small or lookup failed”, and
  never read beyond the reported count.
- Variadic calls: `setproctitle` receives only a fixed `"%s"` plus one string,
  or `NULL` with no varargs. `open` passes `mode_t` only when `O_CREAT` or
  `O_TMPFILE` is used; current code uses the two-argument form.
- `fork`: stays `unsafe`; the caller acknowledges post-fork constraints.
- `closefrom`: returns `Result<(), Errno>`; do not reintroduce silent discard.

## Analysis procedure

1. Locate the exact declaration in `src/ffi.rs` and the wrapper that calls it.
2. Look up the OpenBSD manual page and the installed header for the target
   version. Compare parameter types, return type, nullability, and `errno`
   behavior. Do not copy a Linux or FreeBSD signature.
3. Check the Rust type mapping (`c_int`, `u32` for `uid_t`/`gid_t`, `usize` for
   `size_t`, `i64` for `time_t`, `*mut c_void` for buffers).
4. Verify structure layout field by field. `Passwd` has all ten `<pwd.h>` fields;
   unread fields still count for ABI.
5. Check every pointer argument for nullability, alignment, length,
   initialization, aliasing, and lifetime.
6. Check ownership transfer, double-free, use-after-free, and leak paths.
7. Check the return convention and the exact `errno` read.
8. Check whether a safe wrapper can actually enforce the contract. If not, make
   it `unsafe` or do not add it.

## Implementation procedure

1. Put the declaration in `src/ffi.rs` with a doc link to the manual page.
2. Declare it `safe fn` only if it has no pointer argument and no memory-safety
   precondition; otherwise use a plain `fn` in the `unsafe extern` block.
3. Add the thin wrapper in the owning module, not in `lib.rs`.
4. Use `cfg` and a feature gate for symbols absent from a supported libc.
5. Add `# Errors`, `# Safety`, and `# Pledge` sections as applicable.
6. Use one unsafe operation per block, a `// SAFETY:` comment, and
   `#[expect(unsafe_code, reason = "...")]` on the enclosing item when needed.
7. Avoid `as` casts (`clippy::as_conversions`), indexing
   (`clippy::indexing_slicing`), panics, `unwrap`, `expect`, and unchecked
   arithmetic.
8. Add a unit test for pure conversion logic and a kernel test for runtime
   behavior. Never test a `SIGABRT` case in the shared process.

## Testing and acceptance

- `cargo fmt --all -- --check`
- `cargo check --all-targets`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features` on OpenBSD
- `cargo doc --no-deps --all-features`
- For an ABI change, add a compile-time layout assertion or a native probe and
  verify on the actual target architecture, not only on the host.
- Acceptance requires a documented contract, correct failure propagation, no new
  lint suppressions, and a test that would fail if the contract were inverted.

## References

- <https://doc.rust-lang.org/nomicon/>
- <https://doc.rust-lang.org/reference/type-layout.html>
- <https://doc.rust-lang.org/reference/behavior-considered-undefined.html>
- <https://doc.rust-lang.org/std/ffi/struct.CStr.html>
- OpenBSD manual pages for the specific function, for example
  <https://man.openbsd.org/pledge.2>, <https://man.openbsd.org/getpwnam_r.3>,
  <https://man.openbsd.org/mimmutable.2>, <https://man.openbsd.org/freezero.3>.
- OpenBSD `<pwd.h>`, `<errno.h>`, and `<sys/syslimits.h>` for the target
  release.

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/validate-agent-knowledge.py --scope range --base <base-ref> --head HEAD` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
