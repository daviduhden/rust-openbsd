---
name: rust-openbsd-crypto-auth
description: Use when working on arc4random, arc4random_buf, arc4random_uniform, getentropy, crypt_checkpass, crypt_newhash, bcrypt_pbkdf, PASSWORD_LEN, MAX_ENTROPY, password buffers, or secret handling in rust-openbsd. Covers native limits, parameter validation, and avoiding custom cryptography.
---

# rust-openbsd random and authentication

## When to activate

Activate when a task:

- changes `arc4_random`, `arc4_random_buf`, `arc4_random_uniform`,
  `arc4_random_bytes`, `get_entropy`, `get_entropy_bytes`, or `MAX_ENTROPY`;
- changes `crypt_checkpass`, `crypt_newhash`, `crypt_newhash_into`,
  `bcrypt_pbkdf`, `bcrypt_pbkdf_into`, or `PASSWORD_LEN`;
- handles password, hash, salt, or derived-key buffers;
- changes parameter validation, bias avoidance, or error handling in these
  functions;
- investigates a secret appearing in a log or error message.

## When not to activate

Do not use this skill to implement a cipher, hash, KDF, or RNG. The crate calls
OpenBSD's implementations directly and contains no cryptographic code. Use
`rust-openbsd-memory` for zeroization primitives and
`rust-openbsd-platform` for version/feature gating.

## Related files

- `src/random.rs`, `src/authentication.rs` — implementation.
- `src/ffi.rs` — `arc4random`, `arc4random_buf`, `arc4random_uniform`,
  `getentropy`, `crypt_checkpass`, `crypt_newhash`, `bcrypt_pbkdf`.
- `src/memory.rs` — `explicit_bzero` and timing-safe comparison.
- `tests/random.rs`, `tests/authentication.rs`, `src/tests.rs`.
- `README.md`, `src/lib.rs`.

## Invariants

1. `getentropy(2)` accepts at most 256 bytes per call (`MAX_ENTROPY`). The Rust
   wrapper rejects a larger slice with `EINVAL` before the syscall, and
   `get_entropy_bytes` validates the length before allocating.
2. `getentropy` with an empty buffer is a no-op returning `Ok(())`.
3. `arc4_random_uniform(0)` and `arc4_random_uniform(1)` both return `0`, matching
   the native semantics. Do not add a panic or an error for a zero bound.
4. Prefer `arc4_random_uniform(n)` over `arc4_random() % n`; the native function
   avoids modulo bias.
5. `arc4_random_bytes` is infallible and allocates before filling; allocation
   failure aborts through the global allocator error handler.
6. `crypt_checkpass` returns `Ok(true)` on a match, `Ok(false)` for `EACCES`
   (wrong password or invalid hash), and `Err` for other failures. It rejects
   interior NULs through `CStrHelper`.
7. `crypt_newhash_into` writes a NUL-terminated hash into exactly
   `[u8; PASSWORD_LEN]` and returns the hash length excluding the NUL. The native
   preference string selects the algorithm and cost.
8. `bcrypt_pbkdf_into` takes length-delimited byte slices and accepts NUL bytes.
   An empty key is a no-op that skips native validation. The native function does
   not report a documented `errno`, so failures are mapped to `EINVAL`.
9. `bcrypt_pbkdf` allocates the key buffer before derivation; a very large
   `key_len` can abort on allocation. It does not zeroize the returned key.
10. Passwords, hashes, salts, and derived keys must never be logged, formatted
    into errors, or included in panic messages.
11. Do not add a Rust implementation of bcrypt, PBKDF, or a random generator as a
    fallback. If the native symbol is missing, gate the API or fail to link
    clearly.
12. The crate's `CStrHelper` conversion may leave a transient password copy in a
    stack buffer or heap `CString`; do not claim complete erasure.

## Safety contracts

All public functions are safe. The unsafe blocks only pass live slices and valid
C strings to libc. `crypt_newhash_into`'s output is a fixed-size array, so the
native `buflen` is exact. Empty slices are passed with their dangling-but-aligned
pointer and zero length; the callee must not dereference them. The functions do
not retain pointers.

## Analysis procedure

1. Identify the native function and its documented limits, return convention,
   and `errno` behavior.
2. Check length validation before allocation and before the syscall.
3. Check NUL handling: C-string APIs reject it, length-delimited APIs preserve
   it.
4. Check bias, bound handling, and zero-length behavior.
5. Check buffer sizes: `PASSWORD_LEN`, `MAX_ENTROPY`, hash output, key length.
6. Check whether any error path can include the secret.
7. Check whether the function claims erasure or constant-time behavior it does
   not provide.
8. Check feature gates (`alloc`) and `no_std` availability.

## Implementation procedure

1. Call the native function directly; add no cryptographic logic.
2. Validate lengths before allocating (as `get_entropy_bytes` does).
3. Keep `PASSWORD_LEN` fixed and pass it as the exact buffer size.
4. Keep `crypt_*` on `CStrHelper` and `bcrypt_pbkdf*` on length-delimited
   slices.
5. Map failures to `Errno` without formatting the inputs.
6. Mark infallible helpers `#[must_use]` where appropriate and document
   allocation behavior.
7. Use `explicit_bzero` only on buffers the caller owns; document that the crate
   cannot erase compiler copies.
8. Add deterministic tests with fixed salts and keys, never with real secrets.

## Testing and acceptance

- Random: range behavior, distinct buffers, 256-byte limit, zero length,
  `MAX_ENTROPY + 1` rejection.
- Authentication: bcrypt round trip, wrong password, invalid preference,
  interior-NUL rejection for `crypt_*`, NUL acceptance for `bcrypt_pbkdf`,
  deterministic and salt-sensitive derivation, in-place derivation.
- Never print a password or derived key on failure.
- Acceptance requires native limits, bias avoidance, NUL rules, and secret
  handling to match the documentation.

## References

- <https://man.openbsd.org/arc4random.3>
- <https://man.openbsd.org/getentropy.2>
- <https://man.openbsd.org/crypt_checkpass.3>
- <https://man.openbsd.org/crypt_newhash.3>
- <https://man.openbsd.org/bcrypt_pbkdf.3>
- OpenBSD `lib/libc/crypt/bcrypt.c` and `lib/libc/crypt/arc4random.c` for the
  target release.
- <https://man.openbsd.org/explicit_bzero.3>
- <https://man.openbsd.org/timingsafe_bcmp.3>

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/validate-agent-knowledge.py --scope range --base <base-ref> --head HEAD` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
