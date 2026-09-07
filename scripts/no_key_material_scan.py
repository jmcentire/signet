#!/usr/bin/env python3
"""Scan repository content for credentials without banning cryptographic tests.

The historical entrypoint name is retained for callers. Gitleaks supplies the
detection rules; this wrapper snapshots tracked and non-ignored untracked files
so local edits are checked without scanning vaults or build caches.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    scanner = shutil.which("gitleaks")
    if scanner is None:
        print("Credential scan requires Gitleaks 8.30.1+ (brew install gitleaks).", file=sys.stderr)
        return 2

    try:
        listing = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--deduplicate"],
            cwd=ROOT, check=True, capture_output=True,
        ).stdout
        with tempfile.TemporaryDirectory(prefix="signet-secret-scan-") as scratch:
            snapshot = Path(scratch)
            source = snapshot / "source"
            source.mkdir()
            for name in listing.split(b"\0"):
                if not name:
                    continue
                relative = Path(name.decode("utf-8"))
                original = ROOT / relative
                if any(part.is_symlink() for part in (original, *original.parents) if part != ROOT and ROOT in part.parents):
                    raise ValueError(f"Refusing to follow repository symlink: {relative}")
                if not original.exists():
                    continue  # Locally deleted tracked file.
                if not original.is_file():
                    raise ValueError(f"Cannot scan non-file repository entry: {relative}")
                destination = source / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, destination)

            # Do not inherit inline waivers, an ambient ignore file, or an
            # environment-selected ruleset. Exceptions belong in reviewed config.
            ignore = snapshot / ".gitleaksignore"
            ignore.touch()
            return subprocess.run([
                scanner, "dir", str(source), "--redact", "--no-banner", "--verbose",
                "--config", str(ROOT / ".gitleaks.toml"),
                "--gitleaks-ignore-path", str(ignore), "--ignore-gitleaks-allow",
            ], cwd=snapshot, check=False).returncode
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Credential scan could not complete: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
