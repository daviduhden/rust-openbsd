#!/usr/bin/env python3
"""Enforce structural agent/skill synchronization for a Git change set."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOTS = (".agents/skills", ".github/skills", ".claude/skills")
AGENT_GLOBS = ("AGENTS.md", "*.agent.md")
REQUIRED_SKILL_HEADING = "## Maintenance & Continuous Learning"


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def changed_paths(base: str | None) -> set[str]:
    paths: set[str] = set()
    if base:
        paths.update(
            filter(None, git("diff", "--name-only", "-z", f"{base}...HEAD").split("\0"))
        )
    # Include staged and unstaged tracked edits, plus untracked files for local use.
    paths.update(filter(None, git("diff", "--name-only", "-z", "HEAD").split("\0")))
    paths.update(
        filter(
            None, git("ls-files", "--others", "--exclude-standard", "-z").split("\0")
        )
    )
    return paths


def knowledge_file(path: str) -> bool:
    name = Path(path).name
    return (
        name == "AGENTS.md"
        or name.endswith(".agent.md")
        or (
            name == "SKILL.md"
            and any(path.startswith(f"{root}/") for root in SKILL_ROOTS)
        )
    )


def substantive_diff(path: str, base: str | None) -> bool:
    revisions = ["HEAD"]
    if base:
        revisions.insert(0, f"{base}...HEAD")
    if (ROOT / path).is_file():
        tracked = subprocess.run(
            ["git", "cat-file", "-e", f"HEAD:{path}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if (
            tracked.returncode != 0
            and len((ROOT / path).read_text(encoding="utf-8").strip()) >= 80
        ):
            return True
    for revision in revisions:
        result = subprocess.run(
            ["git", "diff", "--ignore-all-space", "--numstat", revision, "--", path],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            continue
        for row in result.stdout.splitlines():
            fields = row.split("\t", 2)
            if (
                len(fields) == 3
                and fields[0].isdigit()
                and fields[1].isdigit()
                and int(fields[0]) + int(fields[1]) > 0
            ):
                return True
    return False


def validate_skill(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        errors.append(f"{path}: missing or malformed YAML frontmatter")
    else:
        frontmatter = text[4 : text.index("\n---\n", 4)]
        if not re.search(r"(?m)^name:\s*\S", frontmatter):
            errors.append(f"{path}: frontmatter must define name")
        if not re.search(r"(?m)^description:\s*\S", frontmatter):
            errors.append(f"{path}: frontmatter must define description")
    if REQUIRED_SKILL_HEADING not in text:
        errors.append(f"{path}: missing {REQUIRED_SKILL_HEADING!r}")


def validate_links(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
        target = target.strip().split()[0].strip("<>") if target.strip() else ""
        if not target or target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = target.split("#", 1)[0].split("?", 1)[0]
        if not target:
            continue
        if target.startswith("/"):
            resolved = (ROOT / target.lstrip("/")).resolve()
        else:
            resolved = (path.parent / target).resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            errors.append(f"{path}: local link escapes repository: {target}")
            continue
        if not resolved.exists():
            errors.append(f"{path}: broken local link: {target}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="PR base commit/ref; compare base...HEAD")
    args = parser.parse_args()
    errors: list[str] = []
    try:
        changed = changed_paths(args.base)
        project_changes = {p for p in changed if not knowledge_file(p)}
        knowledge_changes = {p for p in changed if knowledge_file(p)}
        if project_changes and not knowledge_changes:
            errors.append(
                "repository files changed without an AGENTS.md, *.agent.md, or SKILL.md update; "
                "review the applicable guidance and include a substantive reusable update"
            )
        if (
            project_changes
            and knowledge_changes
            and not any(substantive_diff(p, args.base) for p in knowledge_changes)
        ):
            errors.append(
                "no substantive instruction/skill diff found (empty or committed-only update)"
            )

        instruction_paths = set()
        for pattern in AGENT_GLOBS:
            instruction_paths.update(ROOT.rglob(pattern))
        for root_name in SKILL_ROOTS:
            instruction_paths.update((ROOT / root_name).rglob("SKILL.md"))
        for path in sorted(instruction_paths):
            if ".git" in path.parts or "target" in path.parts:
                continue
            validate_links(path, errors)
            if path.name == "SKILL.md":
                validate_skill(path, errors)
    except (RuntimeError, OSError) as exc:
        errors.append(str(exc))

    if errors:
        print("Agent maintenance check FAILED:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        print(
            "The check is structural; reviewers must still confirm the update is semantically relevant.",
            file=sys.stderr,
        )
        return 1
    print(
        "Agent maintenance check passed "
        "(structural checks only; semantic relevance requires review)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
