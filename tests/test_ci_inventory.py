import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "validate_ci_inventory.py"
)


class TestCIInventory(unittest.TestCase):

    def setUp(self):

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.root = Path(self.temp_dir.name)
        self.artifacts = self.root / "ci-artifacts"
        self.artifacts.mkdir()

        self.inventory = self.artifacts / "packages.txt"
        self.sca_path = self.artifacts / "sca.json"
        self.sbom_path = self.artifacts / "sbom.json"

        self.inventory.write_text(
            "requests==2.19.1\n"
            "urllib3==1.23\n",
            encoding="utf-8"
        )

        self.sca = {
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.19.1",
                    "vulns": []
                },
                {
                    "name": "urllib3",
                    "version": "1.23",
                    "vulns": []
                }
            ]
        }

        self.sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "requests",
                    "version": "2.19.1"
                },
                {
                    "type": "library",
                    "name": "urllib3",
                    "version": "1.23"
                }
            ]
        }

        self.write_json(self.sca_path, self.sca)
        self.write_json(self.sbom_path, self.sbom)

    def write_json(self, path, data):

        path.write_text(
            json.dumps(data),
            encoding="utf-8"
        )

    def run_validator(self):

        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30
        )

    def assert_result(self, code, message):

        result = self.run_validator()

        self.assertEqual(
            result.returncode,
            code,
            msg=result.stdout + result.stderr
        )

        self.assertIn(message, result.stdout)

    def test_001_valid_inventory(self):

        self.assert_result(
            0, "Validation Result: PASS"
        )

    def test_002_missing_sca_package(self):

        self.sca["dependencies"].pop()

        self.write_json(self.sca_path, self.sca)

        self.assert_result(
            1, "MISSING: urllib3==1.23"
        )

    def test_003_missing_sbom_package(self):

        self.sbom["components"].pop()

        self.write_json(self.sbom_path, self.sbom)

        self.assert_result(
            1, "MISSING: urllib3==1.23"
        )

    def test_004_version_mismatch(self):

        self.sbom["components"][0]["version"] = "2.20.0"

        self.write_json(self.sbom_path, self.sbom)

        self.assert_result(
            1, "UNEXPECTED: requests==2.20.0"
        )

    def test_005_skipped_package(self):

        self.sca["dependencies"][0] = {
            "name": "requests",
            "skip_reason": "Simulated audit failure"
        }

        self.write_json(self.sca_path, self.sca)

        self.assert_result(
            2, "Skipped package: requests"
        )

    def test_006_invalid_json(self):

        self.sca_path.write_text(
            "{invalid json",
            encoding="utf-8"
        )

        self.assert_result(2, "[ERROR]")

    def test_007_empty_inventory(self):

        self.inventory.write_text(
            "",
            encoding="utf-8"
        )

        self.assert_result(
            2, "Empty package inventory"
        )

    def test_008_missing_input_file(self):

        self.sbom_path.unlink()

        self.assert_result(2, "[ERROR]")


if __name__ == "__main__":
    unittest.main()
