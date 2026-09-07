"""Exercise the real local gate, including denial before Cargo can execute."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class CredentialGateTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="signet-gate-test-")
        self.addCleanup(self.scratch.cleanup)
        self.repo = Path(self.scratch.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "scripts").mkdir()
        for relative in ("scripts/no_key_material_scan.py", ".gitleaks.toml", "Makefile"):
            shutil.copyfile(ROOT / relative, self.repo / relative)
        self.bin = self.repo / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text("#!/bin/sh\ntouch cargo-executed\n", encoding="utf-8")
        cargo.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"}

    def run_gate(self, target="secrets"):
        return subprocess.run(
            ["make", target], cwd=self.repo, env=self.env,
            text=True, capture_output=True, check=False,
        )

    def credential(self):
        # Synthetic scanner probe, never a provisioned credential.
        return "ghp_" + "A7b8C9d0E1f2G3h4I5j6K7l8M9n0O1p2Q3r4"

    def test_generated_test_keys_are_allowed(self):
        (self.repo / "tests.rs").write_text(
            '#[test]\nfn signing_roundtrip() {\n'
            '    let signing_key = SigningKey::generate(&mut OsRng);\n'
            '    let test_seed = [42u8; 32];\n'
            '}\n', encoding="utf-8",
        )
        result = self.run_gate("e2e")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.repo / "cargo-executed").exists())

    def test_untracked_credential_blocks_every_execution_entrypoint(self):
        token = self.credential()
        (self.repo / "accidental.env").write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
        for target in ("test", "demo", "e2e", "check"):
            with self.subTest(target=target):
                result = self.run_gate(target)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("leaks found", result.stderr)
                self.assertNotIn(token, result.stdout + result.stderr)
                self.assertFalse((self.repo / "cargo-executed").exists())

    def test_unstaged_edit_is_scanned_even_with_inline_waiver(self):
        fixture = self.repo / "tracked.env"
        fixture.write_text("# empty config\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.env"], cwd=self.repo, check=True)
        fixture.write_text(f"GITHUB_TOKEN={self.credential()} # gitleaks:allow\n", encoding="utf-8")
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_symlink_fails_closed(self):
        (self.repo / "linked-file").symlink_to(ROOT / "README.md")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to follow", result.stderr)

    def test_scanner_failure_blocks_cargo(self):
        scanner = self.bin / "gitleaks"
        scanner.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        scanner.chmod(0o755)
        result = self.run_gate("e2e")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.repo / "cargo-executed").exists())

    def test_missing_or_malformed_config_blocks_cargo(self):
        config = self.repo / ".gitleaks.toml"
        config.unlink()
        for content in (None, "[invalid toml"):
            with self.subTest(content=content):
                if content is not None:
                    config.write_text(content, encoding="utf-8")
                result = self.run_gate("e2e")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.repo / "cargo-executed").exists())

    def test_tracked_file_under_symlinked_directory_is_not_read(self):
        folder = self.repo / "tracked"
        folder.mkdir()
        (folder / "README.md").write_text("fixture", encoding="utf-8")
        subprocess.run(["git", "add", "tracked"], cwd=self.repo, check=True)
        (folder / "README.md").unlink()
        folder.rmdir()
        folder.symlink_to(ROOT, target_is_directory=True)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to follow", result.stderr)


if __name__ == "__main__":
    unittest.main()
