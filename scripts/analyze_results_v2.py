
import json

file_path = "security/scan_results/initial_scan.json"

with open(file_path, "r", encoding="utf-8") as f:
    data = json.load(f)

dependencies = data["dependencies"]

total_vulnerabilities = 0
vulnerable_packages = 0

# V2: 중복 제거를 위한 집합
unique_vulnerabilities = set()

print("=" * 50)
print("OSS Security Gate - Scan Analysis V2")
print("=" * 50)

for package in dependencies:
    name = package["name"]
    version = package["version"]
    vulns = package.get("vulns", [])

    if vulns:
        vulnerable_packages += 1

    total_vulnerabilities += len(vulns)

    print(f"\nPackage: {name}")
    print(f"Version: {version}")

    package_unique_count = 0

    for vuln in vulns:
        vuln_id = vuln["id"]
        fix_versions = vuln["fix_versions"]

        # V2: 취약점 고유 식별 기준
        key = (name, version, vuln_id)

        # 이미 처리한 취약점이면 건너뛰기
        if key in unique_vulnerabilities:
            continue

        unique_vulnerabilities.add(key)
        package_unique_count += 1

        print(f"  - ID: {vuln_id}")
        print(f"    Fix: {fix_versions}")

    print(f"Raw Vulnerabilities: {len(vulns)}")
    print(f"Unique Vulnerabilities: {package_unique_count}")

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

if total_vulnerabilities > 0:
    duplicate_rate = duplicate_count / total_vulnerabilities * 100
    print(f"Duplicate Rate: {duplicate_rate:.2f}%")
