---
name: rust-openbsd-memory
description: Use when working on mimmutable, explicit_bzero, freezero, timingsafe_bcmp, timingsafe_memcmp, page rounding, buffer ownership, secret erasure, or constant-time comparison in rust-openbsd. Covers unsafe caller obligations and the limits of zeroization.
---

# rust-openbsd memory safety

## When to activate

Activate when a task:

- changes `mimmutable`, `explicit_bzero`, `freezero`, `timingsafe_bcmp`, or
  `timingsafe_memcmp`;
- changes page alignment, range rounding, mapping ownership, or buffer lifetime;
- changes secret erasure, zeroization, or constant-time comparison;
- adds an `unsafe` memory operation or a raw pointer API;
- investigates a frozen allocator, a failed `mprotect`, or a suspected
  out-of-bounds zero write.

## When not to activate

Do not use this skill to add a general-purpose allocator, a `mmap` wrapper, or a
custom constant-time primitive. Do not use it to claim that Rust values are
securely erased when the compiler may have copied them. For password hashing and
randomness, load `rust-openbsd-crypto-auth`.

## Related files

- `src/memory.rs` — implementation.
- `src/ffi.rs` — `mimmutable`, `explicit_bzero`, `freezero`,
  `timingsafe_bcmp`, `timingsafe_memcmp`.
- `tests/memory.rs` — native mapping and comparison tests.
- `src/tests.rs` — pure tests.
- `README.md`, `src/lib.rs`.

## Invariants

1. `mimmutable` is `unsafe`. The kernel rounds the start down and the end up to
   whole pages; the caller must own every page in the rounded range and must not
   return it to an allocator.
2. Never pass a slice into an ordinary Rust allocation, the stack, static
   storage, or an allocator arena to `mimmutable`. Freezing allocator metadata
   makes later `mprotect`/`munmap` fail permanently.
3. An empty slice is a no-op in this crate and does not enter the kernel. This
   avoids the kernel promoting a zero-length unaligned range to a whole page.
4. Unmapped pages in the range are skipped and do not become immutable if mapped
   later. Out-of-range or clipped ranges may still return success. Because the
   safe wrapper takes `&[u8]`, it cannot describe a range containing an unmapped
   hole; the kernel behavior is tested with the raw syscall. Never construct a
   slice over invalid memory to work around this.
5. The immutable flag protects the mapping, not the contents: reads and writes
   remain allowed; protection and mapping changes fail with `EPERM`.
6. `freezero` is `unsafe`: ownership transfers, the pointer must come from a
   `malloc(3)`-compatible allocator, and `len` must not exceed the allocation
   size. Never pass Rust heap, stack, static, or `mmap` memory.
7. `explicit_bzero` erases only the named region. It cannot erase compiler
   copies, moved values, or other buffers derived from the secret.
8. `timingsafe_bcmp` returns `false` immediately for unequal lengths and does
   not compare bytes. Do not treat lengths as secret.
9. `timingsafe_memcmp` compares the common prefix in constant time and breaks
   ties by length. Do not replace either function with `==`, `memcmp`, or an
   early-exiting loop for secrets.
10. No arithmetic in these wrappers may overflow silently. Page-rounded lengths
    and buffer sizes are checked by the kernel or by the type system; do not add
    unchecked `len + 1` style arithmetic.

## Safety contracts

- `mimmutable(bytes: &[u8])`: caller guarantees a dedicated mapping and accepts
  that pages outside the slice may be frozen.
- `freezero(ptr: *mut u8, len: usize)`: caller guarantees allocator
  compatibility, size, and ownership transfer.
- The comparison functions are safe: they borrow live slices, read only, and do
  not retain pointers.
- `explicit_bzero` is safe: it borrows a writable slice and does not retain it.

## Analysis procedure

1. Determine the ownership and allocator of every pointer or slice.
2. For `mimmutable`, compute the page-rounded range and check whether it crosses
   into metadata, guard pages, or unrelated mappings.
3. Check for a zero-length input and an unaligned pointer.
4. For `freezero`, check the allocation size, the `len`, double-free, and
   use-after-free.
5. For comparison functions, check length handling, early exit, and whether the
   lengths themselves are secret.
6. For zeroization, check every copy the compiler or the crate may create.
7. Check `no_std`; the memory module must remain core-only.

## Implementation procedure

1. Keep `mimmutable` and `freezero` `unsafe` with `# Safety` sections. Do not
   make them safe to simplify an example.
2. Keep the empty-slice early return and document it.
3. Use `.cast::<c_void>()` rather than `as` casts.
4. Use one unsafe operation per block and a concrete `// SAFETY:` comment.
5. Do not add `freezero` support for Rust allocator memory without an explicit
   allocator guarantee.
6. Keep comparisons allocation-free and read-only.
7. Document the limits of erasure rather than promising full secret removal.
8. Add a native test with a dedicated `mmap` for `mimmutable` and a real
   `malloc` for `freezero`.

## Testing and acceptance

- `tests/memory.rs` already verifies constant-time equality and ordering,
  `explicit_bzero`, `freezero` on a `malloc(64)` allocation, `mimmutable`
  freezing an anonymous `mmap` plus blocking `mprotect`, the empty-slice no-op,
  and the kernel skipping an unmapped hole.
- The hole test uses the raw syscall because a safe slice cannot span a hole; it
  must not be rewritten with `slice::from_raw_parts`.
- Never call `mimmutable` on a Rust allocation in a test.
- CI runs these tests on OpenBSD 8.0/amd64 and 8.0/arm64; OpenBSD 7.9 is manual.
- Acceptance requires a documented caller contract, no false zeroization claim,
  and no early-exit comparison for secrets.

## References

- <https://man.openbsd.org/mimmutable.2>
- <https://man.openbsd.org/mprotect.2>
- <https://man.openbsd.org/mmap.2>
- <https://man.openbsd.org/explicit_bzero.3>
- <https://man.openbsd.org/freezero.3>
- <https://man.openbsd.org/timingsafe_bcmp.3>
- <https://man.openbsd.org/timingsafe_memcmp.3>
- OpenBSD `sys/uvm/uvm_mmap.c`, `sys/uvm/uvm_map.c`, and
  `lib/libc/stdlib/malloc.c` for the target release.
- <https://doc.rust-lang.org/nomicon/ffi.html>

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/validate-agent-knowledge.py --scope range --base <base-ref> --head HEAD` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
