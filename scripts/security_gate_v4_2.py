
import argparse
import json
import sys
from pathlib import Path

import yaml
from packaging.utils import canonicalize_name

from exception_manager import (
    evaluate_exception,
    validate_exception_policy,
    validate_exception_records
)


# 1. 명령행 인자 설정
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="OSS Security Gate V4.2"
    )

    parser.add_argument(
        "--scan",
        required=True,
        help="SCA JSON result file"
    )

    parser.add_argument(
        "--policy",
        default="security/policy.yaml"
    )

    parser.add_argument(
        "--severity",
        default="security/severity.yaml"
    )

    parser.add_argument(
        "--exceptions",
        default="security/exceptions.yaml"
    )

    return parser.parse_args()


# 2. YAML 설정 파일 로드
def load_yaml(path):
    with Path(path).open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(
            f"Invalid YAML configuration: {path}"
        )

    return data


# 3. SCA JSON 파일 로드
def load_scan(path):
    with Path(path).open(encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Invalid scan format")

    dependencies = data.get("dependencies")

    if not isinstance(dependencies, list):
        raise ValueError("Invalid dependencies field")

    if not dependencies:
        raise ValueError("Empty dependency inventory")

    return dependencies


# 4. 취약점 정규화
def normalize_vulnerabilities(dependencies):
    findings = {}
    packages = set()
    skipped = []
    raw_count = 0

    for package in dependencies:

        if not isinstance(package, dict):
            raise ValueError("Invalid package record")

        name = canonicalize_name(package["name"])

        if package.get("skip_reason"):
            skipped.append(name)
            continue

        version = package["version"]
        vulns = package["vulns"]

        if not isinstance(version, str) or not version:
            raise ValueError("Invalid package version")

        if not isinstance(vulns, list):
            raise ValueError("Invalid vulnerability list")

        packages.add((name, version))

        for vuln in vulns:
            vuln_id = vuln["id"]

            if not isinstance(vuln_id, str) or not vuln_id:
                raise ValueError("Invalid vulnerability ID")

            raw_count += 1
            key = (name, version, vuln_id)

            if key not in findings:
                findings[key] = {
                    "package": name,
                    "version": version,
                    "id": vuln_id,
                    "aliases": set(),
                    "fix_versions": set()
                }

            findings[key]["aliases"].update(
                vuln.get("aliases", [])
            )

            findings[key]["fix_versions"].update(
                vuln.get("fix_versions", [])
            )

    return findings, packages, skipped, raw_count

# 5. 보안 정책 설정 검증
def validate_policy(policy):
    required_levels = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNKNOWN"
    }

    rules = policy.get("severity_rules")

    if not isinstance(rules, dict):
        raise ValueError("Invalid severity rules")

    if set(rules) != required_levels:
        raise ValueError("Invalid severity levels")

    for level, rule in rules.items():

        if not isinstance(rule, dict):
            raise ValueError(f"Invalid rule: {level}")

        if rule.get("action") not in {"BLOCK", "ALLOW"}:
            raise ValueError(
                f"Invalid action for {level}"
            )

        if type(rule.get("exception_allowed")) is not bool:
            raise ValueError(
                f"Invalid exception setting for {level}"
            )

    for level in ("CRITICAL", "UNKNOWN"):
        if rules[level]["action"] != "BLOCK":
            raise ValueError(f"{level} must be blocked")

        if rules[level]["exception_allowed"]:
            raise ValueError(
                f"{level} cannot allow exceptions"
            )

    return rules


# 6. CVSS 점수를 심각도로 변환
def cvss_to_severity(score):

    if type(score) not in (int, float):
        raise ValueError("Invalid CVSS score")

    if not 0 <= score <= 10:
        raise ValueError("CVSS score out of range")

    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"

    return "UNKNOWN"


# 7. 취약점 심각도 매핑
def resolve_severity(finding, severity_data):

    records = severity_data.get("vulnerabilities")

    if not isinstance(records, dict):
        raise ValueError("Invalid severity data")

    identifiers = (
        finding["aliases"] | {finding["id"]}
    )

    matched_levels = set()
    pending = False

    for identifier in identifiers:

        record = records.get(identifier)

        if record is None:
            continue

        if not isinstance(record, dict):
            raise ValueError("Invalid severity record")

        if canonicalize_name(record["package"]) != finding["package"]:
            continue

        if record.get("verification_status") != "VERIFIED":
            pending = True
            continue

        if not record.get("source"):
            raise ValueError("Missing severity source")

        level = cvss_to_severity(record["cvss"])

        if record.get("severity") != level:
            raise ValueError(
                f"Severity mismatch: {identifier}"
            )

        matched_levels.add(level)

    if pending or not matched_levels:
        return "UNKNOWN"

    if len(matched_levels) > 1:
        raise ValueError("Conflicting severity records")

    return matched_levels.pop()


# 8. 심각도 기반 보안 정책 판단
def evaluate_policy(
    findings,
    rules,
    severity_data,
    exception_data,
    policy
):

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    blocked = 0
    allowed = 0
    excepted = 0

    print("\n" + "=" * 55)
    print("Vulnerability Policy Evaluation")
    print("=" * 55)

    for key, finding in sorted(findings.items()):

        level = resolve_severity(
            finding,
            severity_data
        )

        counts[level] += 1
        action = rules[level]["action"]
        reason = "DEFAULT_POLICY"

        if action == "BLOCK":

            approved, reason = evaluate_exception(
                finding,
                level,
                rules,
                exception_data,
                policy
            )

            if approved:
                action = "EXCEPTION"

        if action == "BLOCK":
            blocked += 1

        elif action == "EXCEPTION":
            excepted += 1

        else:
            allowed += 1

        print(
            f"[{action}] "
            f"{finding['package']}=={finding['version']} "
            f"| {finding['id']} "
            f"| Severity: {level} "
            f"| Reason: {reason}"
        )

    print("\n" + "=" * 55)
    print("Security Policy Summary")
    print("=" * 55)

    for level, count in counts.items():
        print(f"{level}: {count}")

    print(f"Total Findings: {len(findings)}")
    print(f"Blocked Findings: {blocked}")
    print(f"Allowed Findings: {allowed}")
    print(f"Exception Findings: {excepted}")

    if blocked > 0:
        print("\nDeployment Decision: BLOCK")
        return 1

    print("\nDeployment Decision: PASS")
    return 0


# 9. 메인 함수
def main():
    args = parse_arguments()

    print("=" * 55)
    print("OSS Security Gate V4.2")
    print("=" * 55)

    try:
        policy = load_yaml(args.policy)
        severity = load_yaml(args.severity)
        exceptions = load_yaml(args.exceptions)

        print("[PASS] Policy loaded")
        print("[PASS] Severity data loaded")
        print("[PASS] Exception data loaded")

        rules = validate_policy(policy)

        print("[PASS] Policy validation completed")

        if not isinstance(
            severity.get("vulnerabilities"), dict
        ):
            raise ValueError("Invalid severity configuration")

        validate_exception_policy(policy)
        validate_exception_records(exceptions)

        print("[PASS] Exception configuration validated")

        dependencies = load_scan(args.scan)

        findings, packages, skipped, raw_count = (
            normalize_vulnerabilities(dependencies)
        )

        if skipped:
            raise ValueError(
                "Skipped packages: " + ", ".join(skipped)
            )

        print("[PASS] Scan normalization completed")

        print("\n" + "=" * 55)
        print("Security Gate Input Summary")
        print("=" * 55)

        print(f"Scan File: {args.scan}")
        print(f"Scanned Packages: {len(packages)}")
        print(f"Skipped Packages: {len(skipped)}")
        print(f"Raw Vulnerabilities: {raw_count}")
        print(f"Unique Vulnerabilities: {len(findings)}")
        print(
            f"Duplicate Records: {raw_count - len(findings)}"
        )

        print("\nInput Validation: PASS")

        return evaluate_policy(
            findings,
            rules,
            severity,
            exceptions,
            policy
        )

    except Exception as error:
        print(f"\n[ERROR] {error}", file=sys.stderr)
        print("Input Validation: ERROR")
        print("Deployment Decision: BLOCK")
        return 2


if __name__ == "__main__":
    sys.exit(main())
