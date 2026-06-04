#!/usr/bin/env python3
"""Fail closed when Signet test or CI paths contain key-material operations."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

TEST_RULES = (
    (
        "signing-or-secret-key-type",
        re.compile(r"\b(?:SigningKey|SecretKey|StaticSecret|Keypair)\b"),
    ),
    (
        "key-material-identifier",
        re.compile(
            r"\b(?:signing_key|private_key|secret_key|key_bytes|current_secret|previous_secret)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "key-derivation-or-generation",
        re.compile(r"\b(?:generate_mnemonic|derive_key|from_mnemonic)\b"),
    ),
    (
        "signing-operation",
        re.compile(r"\b(?:sign_ed25519|sign_webhook_payload)\b"),
    ),
)

EXECUTION_RULES = (
    ("test-execution-command", re.compile(r"\bcargo\s+(?:test|nextest)\b")),
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str


def scan_lines(path: Path, lines: list[str], rules: tuple[tuple[str, re.Pattern[str]], ...]) -> list[Finding]:
    relative = path.relative_to(ROOT).as_posix()
    findings: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        for rule, pattern in rules:
            if pattern.search(line):
                findings.append(Finding(relative, line_number, rule))
    return findings


def rust_test_lines(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if "/tests/" in f"/{path.relative_to(ROOT).as_posix()}":
        return lines

    in_tests = False
    visible: list[str] = []
    for line in lines:
        if line.strip() == "#[cfg(test)]":
            in_tests = True
        visible.append(line if in_tests else "")
    return visible


def scan_test_paths() -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        findings.extend(scan_lines(path, rust_test_lines(path), TEST_RULES))
    for path in sorted((ROOT / "tests").rglob("*")):
        if path.is_file():
            findings.extend(
                scan_lines(path, path.read_text(encoding="utf-8", errors="replace").splitlines(), TEST_RULES)
            )
    return findings


def scan_execution_entrypoints() -> list[Finding]:
    findings: list[Finding] = []
    workflows = ROOT / ".github" / "workflows"
    if workflows.exists():
        for path in sorted(workflows.glob("*.y*ml")):
            findings.extend(scan_lines(path, path.read_text(encoding="utf-8").splitlines(), EXECUTION_RULES))
    makefile = ROOT / "Makefile"
    if makefile.exists():
        findings.extend(scan_lines(makefile, makefile.read_text(encoding="utf-8").splitlines(), EXECUTION_RULES))
    return findings


def main() -> int:
    findings = sorted(scan_test_paths() + scan_execution_entrypoints())
    if not findings:
        print("No key-material operations detected in test or CI execution paths.")
        return 0

    print("No-key gate failed: prohibited test/CI paths remain.", file=sys.stderr)
    for finding in findings:
        print(f"{finding.path}:{finding.line}: {finding.rule}", file=sys.stderr)
    print(f"Total findings: {len(findings)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
