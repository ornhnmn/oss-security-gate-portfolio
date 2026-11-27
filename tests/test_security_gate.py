
import json
import subprocess
import sys
import tempfile
import unittest

from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml


ROOT = Path(__file__).resolve().parents[1]


class TestSecurityGate(unittest.TestCase):

    def setUp(self):

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.temp_path = Path(self.temp_dir.name)

        self.scan = (
            "tests/fixtures/scan_single_high.json"
        )

        with (ROOT / "security/policy.yaml").open() as f:
            policy = yaml.safe_load(f)

        timezone_name = policy[
            "exception_policy"
        ]["timezone"]

        self.today = datetime.now(
            ZoneInfo(timezone_name)
        ).date()

    def run_gate(self, scan=None, exceptions=None):

        command = [
            sys.executable,
            "scripts/security_gate.py",
            "--scan",
            self.scan if scan is None else str(scan)
        ]

        if exceptions is not None:
            command.extend([
                "--exceptions",
                str(exceptions)
            ])

        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30
        )

    def create_exception(self, expired=False):

        path = (
            ROOT
            / "tests/fixtures/exception_valid.yaml"
        )

        with path.open() as f:
            data = yaml.safe_load(f)

        record = data["exceptions"][0]

        if expired:
            approved = self.today - timedelta(days=7)
            expires = self.today
        else:
            approved = self.today - timedelta(days=1)
            expires = self.today + timedelta(days=6)

        record["approved_date"] = approved.isoformat()
        record["expires_at"] = expires.isoformat()

        output = self.temp_path / "exception.yaml"

        output.write_text(
            yaml.safe_dump(data),
            encoding="utf-8"
        )

        return output

    # IT-01: 예외 승인 없는 취약점 차단
    def test_01_default_block(self):

        result = self.run_gate()

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Blocked Findings: 1",
            result.stdout
        )
        self.assertIn(
            "Deployment Decision: BLOCK",
            result.stdout
        )

    # IT-02: 정상 예외 승인 후 최종 PASS
    def test_02_exception_pass(self):

        exception_file = self.create_exception()

        result = self.run_gate(
            exceptions=exception_file
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "Exception Findings: 1",
            result.stdout
        )
        self.assertIn(
            "Blocked Findings: 0",
            result.stdout
        )
        self.assertIn(
            "Deployment Decision: PASS",
            result.stdout
        )

    # IT-03: 만료된 예외 승인 차단
    def test_03_expired_exception(self):

        exception_file = self.create_exception(
            expired=True
        )

        result = self.run_gate(
            exceptions=exception_file
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Reason: EXPIRED",
            result.stdout
        )

    # IT-04: 취약점 없는 진단 결과
    def test_04_clean_scan(self):

        result = self.run_gate(
            scan="security/scan_results/tools_final_scan.json"
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "Deployment Decision: PASS",
            result.stdout
        )

    # IT-05: 존재하지 않는 진단 파일
    def test_05_missing_scan(self):

        result = self.run_gate(
            scan=self.temp_path / "missing.json"
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "Deployment Decision: BLOCK",
            result.stdout
        )

    # IT-06: 손상된 JSON 입력
    def test_06_invalid_json(self):

        path = self.temp_path / "invalid.json"

        path.write_text(
            "{invalid json",
            encoding="utf-8"
        )

        result = self.run_gate(scan=path)

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "Deployment Decision: BLOCK",
            result.stdout
        )

    # IT-07: 검사 누락 패키지 차단
    def test_07_skipped_package(self):

        path = self.temp_path / "skipped.json"

        data = {
            "dependencies": [
                {
                    "name": "requests",
                    "skip_reason": "Simulated scan failure"
                }
            ]
        }

        path.write_text(
            json.dumps(data),
            encoding="utf-8"
        )

        result = self.run_gate(scan=path)

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "Deployment Decision: BLOCK",
            result.stdout
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
