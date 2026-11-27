
import json

scan_path = "security/scan_results/initial_scan.json"
requirements_path = "requirements.txt"

# 1. 직접 의존성 목록 추출
direct_dependencies = set()

with open(requirements_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        name = line.split("==")[0].strip().lower()
        direct_dependencies.add(name)

# 2. SCA 진단 결과 읽기
with open(scan_path, "r", encoding="utf-8") as f:
    data = json.load(f)

dependencies = data["dependencies"]

total_vulnerabilities = 0
vulnerable_packages = 0
direct_count = 0
transitive_count = 0

# 3. 중복 취약점 정보 병합
unique_vulnerabilities = {}

print("=" * 50)
print("OSS Security Gate - Scan Analysis V3")
print("=" * 50)

for package in dependencies:
    name = package["name"].lower()
    version = package["version"]
    vulns = package.get("vulns", [])

    if name in direct_dependencies:
        dependency_type = "DIRECT"
    else:
        dependency_type = "TRANSITIVE"

    if vulns:
        vulnerable_packages += 1

    total_vulnerabilities += len(vulns)

    print(f"\nPackage: {name}")
    print(f"Version: {version}")
    print(f"Dependency Type: {dependency_type}")

    package_vulnerabilities = {}

    for vuln in vulns:
        vuln_id = vuln["id"]
        key = (name, version, vuln_id)

        if key not in package_vulnerabilities:
            package_vulnerabilities[key] = {
                "aliases": set(),
                "fix_versions": set()
            }

        # 중복 레코드의 식별자와 수정 버전 병합
        package_vulnerabilities[key]["aliases"].update(
            vuln.get("aliases", [])
        )

        package_vulnerabilities[key]["fix_versions"].update(
            vuln.get("fix_versions", [])
        )

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

        print(f"  - ID: {key[2]}")
        print(f"    CVE: {', '.join(cve_ids) or 'N/A'}")
        print(f"    GHSA: {', '.join(ghsa_ids) or 'N/A'}")
        print(f"    Fix: {', '.join(sorted(info['fix_versions'])) or 'N/A'}")

    package_unique_count = len(package_vulnerabilities)

    if dependency_type == "DIRECT":
        direct_count += package_unique_count
    else:
        transitive_count += package_unique_count

    print(f"Raw Vulnerabilities: {len(vulns)}")
    print(f"Unique Vulnerabilities: {package_unique_count}")

# 4. 전체 진단 결과 집계
unique_count = len(unique_vulnerabilities)
duplicate_count = total_vulnerabilities - unique_count

print("\n" + "=" * 50)
print("Scan Summary")
print("=" * 50)

print(f"Total Packages: {len(dependencies)}")
print(f"Vulnerable Packages: {vulnerable_packages}")
print(f"Raw Vulnerabilities: {total_vulnerabilities}")
print(f"Unique Vulnerabilities: {unique_count}")
print(f"Duplicate Records: {duplicate_count}")
print(f"Direct Vulnerabilities: {direct_count}")
print(f"Transitive Vulnerabilities: {transitive_count}")

if total_vulnerabilities > 0:
    duplicate_rate = duplicate_count / total_vulnerabilities * 100
    print(f"Duplicate Rate: {duplicate_rate:.2f}%")

if unique_count > 0:
    transitive_rate = transitive_count / unique_count * 100
    print(f"Transitive Vulnerability Rate: {transitive_rate:.2f}%")
