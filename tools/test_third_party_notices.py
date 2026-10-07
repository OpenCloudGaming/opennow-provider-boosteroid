import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import subprocess

from third_party_notices import generate, indexed_files, license_files


class NoticesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "LICENSE").write_bytes(b"Exact upstream notice\n\n")
        self.entry = {
            "status": "upstream-at-published-commit",
            "license": "MIT",
            "files": [{"path": "LICENSE", "sha256": hashlib.sha256(
                (self.root / "LICENSE").read_bytes()).hexdigest()}],
        }

    def test_index_verifies_hash(self):
        self.assertEqual(indexed_files(self.root, self.entry), [self.root / "LICENSE"])
        (self.root / "LICENSE").write_text("changed")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            indexed_files(self.root, self.entry)

    def test_index_rejects_escape_and_unverified_provenance(self):
        for status in ("declared-only", "upstream-later-commit"):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "provenance"):
                indexed_files(self.root, dict(self.entry, status=status))
        for path in ("../LICENSE", str(self.root / "LICENSE")):
            self.entry["files"][0]["path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "escapes"):
                indexed_files(self.root, self.entry)

    def test_index_rejects_symlink_escape(self):
        try:
            (self.root / "alias").symlink_to(self.root.parent, target_is_directory=True)
        except OSError as error:
            if getattr(error, "winerror", None) != 1314:
                raise
            subprocess.run(["cmd", "/c", "mklink", "/J", str(self.root / "alias"),
                            str(self.root.parent)], check=True, capture_output=True)
        self.entry["files"][0]["path"] = "alias/LICENSE"
        with self.assertRaisesRegex(ValueError, "escapes"):
            indexed_files(self.root, self.entry)

    def test_license_directory_is_included(self):
        directory = self.root / "crate"
        (directory / "LICENSES").mkdir(parents=True)
        (directory / "LICENSES" / "MIT.txt").write_text("MIT notice")
        self.assertEqual(license_files({"manifest_path": str(directory / "Cargo.toml")}),
                         [directory / "LICENSES" / "MIT.txt"])

    def test_generation_checks_lock_and_toolchain_and_preserves_text(self):
        package = {"id": "dependency", "name": "dependency", "version": "1.0.0",
                   "source": "registry+https://example.invalid", "license": "MIT",
                   "manifest_path": str(self.root / "crate" / "Cargo.toml")}
        lock = [dict(package, checksum="verified-lock-checksum")]
        metadata = {"workspace_members": ["application"], "packages": [package],
                    "resolve": {"nodes": [{"id": "application", "dependencies": ["dependency"]},
                                           {"id": "dependency", "dependencies": []}]}}
        index = {"schema": 1, "packages": {"dependency@1.0.0": dict(
            self.entry, cargo_lock_checksum="verified-lock-checksum")},
            "distribution_notices": {"rust-std@1.99.0": dict(
                self.entry, status="toolchain-distribution", commit="compiler-commit")}}
        (self.root / "index.json").write_text(json.dumps(index))
        output = generate(metadata, self.root, lock, "1.99.0", "compiler-commit")
        self.assertIn("Exact upstream notice\n\n", output)
        self.assertIn("rust-std@1.99.0", output)
        with self.assertRaisesRegex(ValueError, "Missing toolchain"):
            generate(metadata, self.root, lock, "1.98.0", "compiler-commit")
        with self.assertRaisesRegex(ValueError, "Toolchain notice commit mismatch"):
            generate(metadata, self.root, lock, "1.99.0", "wrong-commit")
        lock[0]["checksum"] = "wrong-checksum"
        with self.assertRaisesRegex(ValueError, "lock checksum mismatch"):
            generate(metadata, self.root, lock, "1.99.0", "compiler-commit")


if __name__ == "__main__":
    unittest.main()
