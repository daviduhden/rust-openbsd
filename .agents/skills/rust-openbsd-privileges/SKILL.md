---
name: rust-openbsd-privileges
description: Use when working on UID/GID handling, setgroups, initgroups, setresgid, setresuid, Account, GroupPolicy, drop_privileges, drop_privileges_with, drop_privileges_to, chroot, or credential verification in rust-openbsd. Covers privilege-separation ordering, partial failure, saved IDs, and pledge interaction.
---

# rust-openbsd privileges

## When to activate

Activate when a task:

- changes `Uid`, `Gid`, `Groups`, `Account`, `GroupPolicy`, `PrivDropError`,
  `PrivDropStep`, or `Verification`;
- changes `account_by_name`, `set_groups`, `init_groups`, `groups`,
  `set_res_uid`, `set_res_gid`, `get_res_uid`, `get_res_gid`,
  `drop_supplementary_groups`, `drop_privileges`, `drop_privileges_with`, or
  `drop_privileges_to`;
- changes `chroot`, `chdir`, or `enter_chroot`;
- investigates credentials after a drop, saved-ID recovery, or a partial failure;
- documents the interaction between `id`/`getpw` pledges and identity changes.

## When not to activate

Do not use this skill to implement a login session (`setusercontext(3)` and
`login.conf(5)` are deliberately out of scope) or to add a general-purpose
container/sandbox abstraction. For process creation and exec, load
`rust-openbsd-process`; for pledge details, load `rust-openbsd-pledge`.

## Related files

- `src/privileges.rs`, `src/chroot.rs`, `src/credentials.rs`.
- `src/ffi.rs` — `getpwnam_r`, `setgroups`, `getgroups`, `initgroups`,
  `setresuid`, `setresgid`, `getresuid`, `getresgid`, `chroot`, `chdir`.
- `tests/privileges.rs`, `tests/chroot.rs`, `tests/credentials.rs`,
  `tests/common/mod.rs`.
- `README.md`, `src/lib.rs`.

## Invariants

1. The drop order is fixed: supplementary groups, then all three GIDs, then all
   three UIDs, then verification. UIDs are dropped last so the process remains
   privileged long enough to change groups and GIDs.
2. `setresuid` and `setresgid` are called with all three flavors set to the target
   value. Never leave a privileged saved ID behind after a successful drop.
3. `setgroups(2)` requires privilege and rejects more than `NGROUPS_MAX` entries
   with `EINVAL`; it does not truncate.
4. `GroupPolicy::PrimaryGroupOnly` is the default and replaces the supplementary
   list with exactly the primary GID. `GroupPolicy::Initgroups` adopts the
   account's memberships via `initgroups(3)` and is login-style behavior.
5. `Account` is inline, `Copy`, and self-contained; resolve it before a chroot
   that may hide the password database.
6. `GroupPolicy::Initgroups` also needs the group database at drop time. After a
   chroot without that database, use `PrimaryGroupOnly` or drop before the
   chroot.
7. Any `PrivDropError` is fatal for the current process. A partial failure can
   leave lowered privileges or a privileged saved UID; there is no rollback.
8. `drop_privileges` and `drop_privileges_with` reject an account whose UID is
   root **or whose primary GID is root**. `drop_privileges_to` does not; it
   re-applies whatever account it is given. `Account::is_root` checks UID only,
   not GID 0.
9. Verification for `PrimaryGroupOnly` requires exactly `[primary_gid]`.
   Verification for `Initgroups` compares the observed list with the membership
   reported by `getgrouplist(3)` for the account, ignoring order. That lookup
   needs the group database at verification time, just like `initgroups(3)`
   itself; a membership that does not fit in `NGROUPS_MAX` is treated as a
   verification failure rather than silently truncated.
10. `chroot(2)` has no pledge promise and must run before pledging. `chdir(2)`
    after pledge requires `rpath`. `enter_chroot` is `chroot(path)` then
    `chdir("/")`, and its error does not identify which step failed.
11. `getpeereid(3)` returns peer effective credentials and is not authentication.
    Calling it before pledging is the conservative rule; on current OpenBSD it
    uses `getsockopt(2)` and needs `stdio` plus one of `unix`, `inet`, or `dns`.
12. Account lookup errors: a missing entry is `Ok(None)`; a database login name
    longer than `LOGIN_NAME_MAX` is `ENAMETOOLONG`; the longest accepted name is
    31 bytes plus NUL.

## Safety contracts

All public functions in these modules are safe at the Rust memory level. Their
risk is process-wide and irreversible, not memory-unsafety. The wrappers pass
valid `CStr`s and live out-parameters; `getpwnam_r` uses `MaybeUninit` and calls
`assume_init_ref` only after a non-null result. `getgrouplist` receives a live
`NGROUPS_MAX` buffer and an in/out `c_int` count. `Account::name` relies on its
construction invariant (NUL-terminated, no interior NUL, length below the
buffer). Do not weaken these invariants to remove an `unsafe` block.

## Analysis procedure

1. Trace the exact sequence in `drop_privileges_to` and `verify`.
2. Identify every failure point and the credential state it can leave behind.
3. Check whether saved IDs can regain privilege after success and after each
   failure mode.
4. Check the account-resolution path: `getpwnam_r` return convention, buffer
   growth, `ERANGE`, `ENAMETOOLONG`, and the fixed `LOGIN_NAME_MAX`.
5. Check `getgrouplist(3)` usage: buffer size, the `ngroups` in/out value,
   order independence, duplicates, and database availability at verification
   time.
6. Check the chroot/pledge/account-resolution ordering.
7. Check group-list sizes and the `initgroups` database dependency.
8. Check that error values never contain secret data.
9. Check the root and group-root edge cases explicitly.

## Implementation procedure

1. Preserve the sequence and the all-three-flavors calls.
2. Do not add a best-effort recovery path; fail closed and document fatality.
3. Keep `Account` allocation-free and `Copy`.
4. Keep the default group policy restrictive and never retain root's
   supplementary groups by accident.
5. Keep `Initgroups` verification strict: compare against
   `getgrouplist(3)` membership, ignore order, and fail closed if the expected
   list does not fit or cannot be read.
6. Keep `chroot` before pledge and resolve accounts before chroot.
7. Add a test for each new failure branch, using an isolated child.
8. Never add a `setuid`-only shortcut that leaves a saved root ID.

## Testing and acceptance

- Unit: `LOGIN_NAME_MAX` boundary, `Account::new` rejection, root-UID and
  root-GID rejection, display values.
- Isolated child, root: full drop, all three flavors, group policy (including
  strict `getgrouplist` comparison), inability to restore root, `drop_privileges_to`
  after `account_by_name`, `id`-promise lifecycle, `enter_chroot` confinement.
- Isolated child, non-root: `EPERM` paths.
- Tests that change identity must never run in the shared process or on the
  agent host. Use an OpenBSD VM.
- Acceptance requires that a partial failure is still fatal in the documentation
  and that no code path silently restores privileges.

## References

- <https://man.openbsd.org/setgroups.2>
- <https://man.openbsd.org/initgroups.3>
- <https://man.openbsd.org/setresgid.2>
- <https://man.openbsd.org/setresuid.2>
- <https://man.openbsd.org/getpwnam_r.3>
- <https://man.openbsd.org/chroot.2>
- <https://man.openbsd.org/chdir.2>
- <https://man.openbsd.org/getpeereid.3>
- <https://man.openbsd.org/issetugid.2>
- OpenBSD `sys/kern/kern_prot.c` and `include/pwd.h` for the target release.

## Maintenance & Continuous Learning

When this skill is used to modify the repository, review it after the task alongside the applicable `AGENTS.md`, related specialist instructions, and referenced skill materials. Update this skill when procedures, tools, configuration, project behavior, or assumptions changed; add reusable discoveries and correct guidance that proved wrong. Keep examples, paths, and validation commands current, remove obsolete or contradictory knowledge, and avoid notes tied only to one execution. Check references and run `python3 scripts/check_agent_maintenance.py --base <base-ref>` before completion. The automated check validates structure and the presence of a substantive knowledge-file diff, not semantic relevance; judge relevance explicitly. Report the synchronization result in the final response. A task is incomplete if required synchronization is skipped or fails.
