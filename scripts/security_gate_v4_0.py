
import argparse
import json
import sys
from pathlib import Path

import yaml
from packaging.utils import canonicalize_name


# 1. 명령행 인자 설정
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="OSS Security Gate V4.0"
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


# 5. 메인 함수
def main():
    args = parse_arguments()

    print("=" * 55)
    print("OSS Security Gate V4.0")
    print("=" * 55)

    try:
        policy = load_yaml(args.policy)
        severity = load_yaml(args.severity)
        exceptions = load_yaml(args.exceptions)

        print("[PASS] Policy loaded")
        print("[PASS] Severity data loaded")
        print("[PASS] Exception data loaded")

        dependencies = load_scan(args.scan)

        print("[PASS] Scan file loaded")

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
        print("Deployment Decision: NOT IMPLEMENTED")

        # 정책 판단 기능 구현 전에는 배포 허용 금지
        return 2

    except Exception as error:
        print(f"\n[ERROR] {error}", file=sys.stderr)
        print("Input Validation: ERROR")
        print("Deployment Decision: BLOCK")
        return 2


if __name__ == "__main__":
    sys.exit(main())
