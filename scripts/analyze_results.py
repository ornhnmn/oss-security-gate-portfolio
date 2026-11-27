
import argparse
import json
from packaging.utils import canonicalize_name
from packaging.version import Version

# 1. 명령행 인자 설정
parser = argparse.ArgumentParser(
    description="OSS Security Gate - Vulnerability Analysis"
)

parser.add_argument(
    "--scan",
    default="security/scan_results/initial_scan.json",
    help="SCA JSON result file"
)

parser.add_argument(
    "--requirements",
    default="requirements.txt",
    help="Direct dependency requirements file"
)

args = parser.parse_args()

scan_path = args.scan
requirements_path = args.requirements

# 2. 빌드 및 환경 관리 도구 정의
environment_tools = {
    "pip",
    "setuptools",
    "wheel",
    "cython",
    "packaging"
}

# 3. 직접 의존성 추출
direct_dependencies = set()

with open(requirements_path, encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        name = canonicalize_name(line.split("==")[0].strip())
        direct_dependencies.add(name)

# 4. SCA 결과 읽기
with open(scan_path, encoding="utf-8") as f:
    data = json.load(f)

dependencies = data["dependencies"]

total_vulnerabilities = 0
vulnerable_packages = 0
skipped_packages = 0
unique_vulnerabilities = {}

category_counts = {
    "DIRECT": 0,
    "TRANSITIVE": 0,
    "BUILD_TOOL": 0
}

print("=" * 50)
print("OSS Security Gate - Scan Analysis V3.1")
print("=" * 50)
print(f"Scan File: {scan_path}")

# 5. 패키지별 분석
for package in dependencies:

    name = canonicalize_name(package["name"])

    if package.get("skip_reason"):
        skipped_packages += 1
        print(f"\nSkipped Package: {name}")
        print(f"Reason: {package['skip_reason']}")
        continue

    version = package["version"]
    vulns = package.get("vulns", [])

    if name in direct_dependencies:
        dependency_type = "DIRECT"
    elif name in environment_tools:
        dependency_type = "BUILD_TOOL"
    else:
        dependency_type = "TRANSITIVE"

    if vulns:
        vulnerable_packages += 1

    total_vulnerabilities += len(vulns)

    print(f"\nPackage: {name}")
    print(f"Version: {version}")
    print(f"Dependency Type: {dependency_type}")

    package_vulnerabilities = {}

    # 6. 중복 제거 및 정보 병합
    for vuln in vulns:

        vuln_id = vuln["id"]
        key = (name, version, vuln_id)

        if key not in package_vulnerabilities:
            package_vulnerabilities[key] = {
                "aliases": set(),
                "fix_versions": set()
            }

        package_vulnerabilities[key]["aliases"].update(
            vuln.get("aliases", [])
        )

        package_vulnerabilities[key]["fix_versions"].update(
            vuln.get("fix_versions", [])
        )

    # 7. CVE 및 GHSA 매핑
    for key, info in package_vulnerabilities.items():

        unique_vulnerabilities[key] = info

        cve_ids = sorted(
            alias for alias in info["aliases"]
            if alias.startswith("CVE-")
        )

        ghsa_ids = sorted(
            alias for alias in info["aliases"]
            if alias.startswith("GHSA-")
        )

        fix_versions = sorted(
            info["fix_versions"],
            key=Version
        )

        print(f"  - ID: {key[2]}")
        print(f"    CVE: {', '.join(cve_ids) or 'N/A'}")
        print(f"    GHSA: {', '.join(ghsa_ids) or 'N/A'}")
        print(f"    Fix: {', '.join(fix_versions) or 'N/A'}")

    package_unique_count = len(package_vulnerabilities)

    category_counts[dependency_type] += package_unique_count

    print(f"Raw Vulnerabilities: {len(vulns)}")
    print(f"Unique Vulnerabilities: {package_unique_count}")

# 8. 최종 통계
unique_count = len(unique_vulnerabilities)
duplicate_count = total_vulnerabilities - unique_count

print("\n" + "=" * 50)
print("Scan Summary")
print("=" * 50)

print(f"Total Packages: {len(dependencies)}")
print(f"Skipped Packages: {skipped_packages}")
print(f"Vulnerable Packages: {vulnerable_packages}")
print(f"Raw Vulnerabilities: {total_vulnerabilities}")
print(f"Unique Vulnerabilities: {unique_count}")
print(f"Duplicate Records: {duplicate_count}")

print(f"Direct Vulnerabilities: {category_counts['DIRECT']}")
print(f"Transitive Vulnerabilities: {category_counts['TRANSITIVE']}")
print(f"Build Tool Vulnerabilities: {category_counts['BUILD_TOOL']}")

if total_vulnerabilities > 0:
    duplicate_rate = duplicate_count / total_vulnerabilities * 100
    print(f"Duplicate Rate: {duplicate_rate:.2f}%")
