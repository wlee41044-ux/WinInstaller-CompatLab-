"""Package integrity, deliberate trust and staging isolation. Standard-library only."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from module_bundle import build, verify, stage, BundleError, BUNDLE_ID, VERSION


class SourceKitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "module.wicmod"
        self.trusted = build(self.bundle)
        self.contract = self.root / "host-contract.json"
        self.contract.write_text(json.dumps({
            "consumer": "wininstaller", "host_api": 1,
            "allow_source_kits": True,
            "allowed_modules": ["winclab-file", "winclab-registry"]
        }), encoding="utf-8")

    def rewrite(self, replace):
        with zipfile.ZipFile(self.bundle) as z:
            rows = {name: z.read(name) for name in z.namelist()}
        replace(rows)
        with zipfile.ZipFile(self.bundle, "w") as z:
            for name, contents in rows.items():
                z.writestr(name, contents)

    def test_deterministic_package(self):
        again = self.root / "again.wicmod"
        self.assertEqual(self.trusted, build(again))
        self.assertEqual(self.bundle.read_bytes(), again.read_bytes())

    def test_contents(self):
        m, files = verify(self.bundle, self.trusted)
        self.assertEqual(m["kind"], "source-kit")
        self.assertEqual(m["activation"], "not-supported-without-private-host-integration")
        self.assertEqual(len(files), 4)

    def test_tamper_blocks(self):
        self.rewrite(lambda rows: rows.__setitem__("src/file_api.cpp", b"untrusted"))
        with self.assertRaises(BundleError):
            verify(self.bundle)

    def test_expected_hash_blocks(self):
        with self.assertRaises(BundleError):
            verify(self.bundle, "a" * 64)

    def test_extra_member_blocks(self):
        self.rewrite(lambda rows: rows.__setitem__("../evil", b"evil"))
        with self.assertRaises(BundleError):
            verify(self.bundle)

    def test_missing_member_blocks(self):
        self.rewrite(lambda rows: rows.pop("src/registry_api.cpp"))
        with self.assertRaises(BundleError):
            verify(self.bundle)

    def test_wrong_version_blocks(self):
        def change(rows):
            m = json.loads(rows["manifest.json"])
            m["host_api"] = 999
            rows["manifest.json"] = json.dumps(m).encode()
        self.rewrite(change)
        with self.assertRaises(BundleError):
            verify(self.bundle)

    def test_unauthorized_host_blocks(self):
        self.contract.write_text(json.dumps({"consumer":"other","host_api":1,"allow_source_kits":True,"allowed_modules":["winclab-file","winclab-registry"]}))
        with self.assertRaises(BundleError):
            stage(self.bundle, self.root / "staged", self.trusted, self.contract)

    def test_staging_and_no_overwrite(self):
        target = stage(self.bundle, self.root / "staged", self.trusted, self.contract)
        self.assertEqual(target.name, BUNDLE_ID + "-" + VERSION)
        self.assertTrue((target / "src" / "file_api.cpp").is_file())
        with self.assertRaises(BundleError):
            stage(self.bundle, self.root / "staged", self.trusted, self.contract)
        self.assertFalse((self.root / "evil").exists())

    def test_stage_rejects_wrong_trust_digest(self):
        with self.assertRaises(BundleError):
            stage(self.bundle, self.root / "staged", "0" * 64, self.contract)
        self.assertFalse((self.root / "staged" / (BUNDLE_ID + "-" + VERSION)).exists())


if __name__ == "__main__":
    unittest.main()
