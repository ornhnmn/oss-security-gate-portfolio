
import copy
import unittest

from datetime import date
from pathlib import Path

import yaml

from scripts.exception_manager import evaluate_exception


ROOT = Path(__file__).resolve().parents[1]


def load_yaml(relative_path):

    with (ROOT / relative_path).open(
        encoding="utf-8"
    ) as f:
        return yaml.safe_load(f)


class TestExceptionManager(unittest.TestCase):

    def setUp(self):

        self.policy = load_yaml(
            "security/policy.yaml"
        )

        self.rules = self.policy["severity_rules"]

        self.valid = load_yaml(
            "tests/fixtures/exception_valid.yaml"
        )

        self.finding = {
            "package": "requests",
            "version": "2.19.1",
            "id": "PYSEC-2018-28",
            "aliases": {"CVE-2018-18074"}
        }

        self.today = date(2026, 11, 27)

    def evaluate(
        self,
        data=None,
        severity="HIGH",
        today=None
    ):

        return evaluate_exception(
            self.finding,
            severity,
            self.rules,
            self.valid if data is None else data,
            self.policy,
            today=self.today if today is None else today
        )

    # TC-01: 정상 승인
    def test_01_valid_exception(self):

        self.assertEqual(
            self.evaluate(),
            (True, "EX-TEST-001")
        )

    # TC-02: 만료된 승인
    def test_02_expired_exception(self):

        data = load_yaml(
            "tests/fixtures/exception_expired.yaml"
        )

        self.assertEqual(
            self.evaluate(data),
            (False, "EXPIRED")
        )

    # TC-03: 미승인
    def test_03_pending_exception(self):

        data = load_yaml(
            "tests/fixtures/exception_pending.yaml"
        )

        self.assertEqual(
            self.evaluate(data),
            (False, "NOT_APPROVED")
        )

    # TC-04: Critical 예외 금지
    def test_04_critical_exception(self):

        self.finding = {
            "package": "pyyaml",
            "version": "5.3",
            "id": "PYSEC-2021-142",
            "aliases": {"CVE-2020-14343"}
        }

        data = load_yaml(
            "tests/fixtures/exception_critical.yaml"
        )

        self.assertEqual(
            self.evaluate(data, severity="CRITICAL"),
            (False, "SEVERITY_NOT_ELIGIBLE")
        )

    # TC-05: Unknown 예외 금지
    def test_05_unknown_exception(self):

        self.assertEqual(
            self.evaluate(severity="UNKNOWN"),
            (False, "SEVERITY_NOT_ELIGIBLE")
        )

    # TC-06: 승인일 당일
    def test_06_approval_date(self):

        self.assertEqual(
            self.evaluate(today=date(2026, 11, 27)),
            (True, "EX-TEST-001")
        )

    # TC-07: 승인일 이전
    def test_07_before_approval(self):

        self.assertEqual(
            self.evaluate(today=date(2026, 11, 26)),
            (False, "FUTURE_APPROVAL")
        )

    # TC-08: 만료일 직전
    def test_08_before_expiration(self):

        self.assertEqual(
            self.evaluate(today=date(2026, 12, 3)),
            (True, "EX-TEST-001")
        )

    # TC-09: 만료일 당일
    def test_09_expiration_date(self):

        self.assertEqual(
            self.evaluate(today=date(2026, 12, 4)),
            (False, "EXPIRED")
        )

    # TC-10: 최대 승인 기간 초과
    def test_10_duration_exceeded(self):

        self.valid["exceptions"][0]["expires_at"] = (
            "2027-01-01"
        )

        self.assertEqual(
            self.evaluate(),
            (False, "DURATION_EXCEEDED")
        )

    # TC-11: 자기 승인
    def test_11_self_approval(self):

        record = self.valid["exceptions"][0]

        record["approved_by"] = record["owner"]

        self.assertEqual(
            self.evaluate(),
            (False, "SELF_APPROVAL")
        )

    # TC-12: 버전 불일치
    def test_12_version_mismatch(self):

        self.finding["version"] = "2.19.0"

        self.assertEqual(
            self.evaluate(),
            (False, "NO_MATCHING_EXCEPTION")
        )

    # TC-13: 대체 보안 통제 누락
    def test_13_missing_controls(self):

        self.valid["exceptions"][0][
            "compensating_controls"
        ] = []

        self.assertEqual(
            self.evaluate(),
            (False, "MISSING_COMPENSATING_CONTROLS")
        )

    # TC-14: 중복 예외 승인
    def test_14_ambiguous_exception(self):

        duplicate = copy.deepcopy(
            self.valid["exceptions"][0]
        )

        duplicate["exception_id"] = "EX-TEST-999"

        self.valid["exceptions"].append(duplicate)

        self.assertEqual(
            self.evaluate(),
            (False, "AMBIGUOUS_EXCEPTION")
        )

    # TC-15: 잘못된 시간대 설정
    def test_15_invalid_timezone(self):

        self.policy["exception_policy"]["timezone"] = (
            "Invalid/Timezone"
        )

        with self.assertRaisesRegex(
            ValueError,
            "Invalid policy timezone"
        ):
            self.evaluate()

    # TC-16: 예외 승인 정보 없음
    def test_16_no_exception(self):

        self.assertEqual(
            self.evaluate({"exceptions": []}),
            (False, "NO_MATCHING_EXCEPTION")
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
