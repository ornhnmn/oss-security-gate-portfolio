import json

# 1. 진단 결과 파일 경로
file_path = "security/scan_results/initial_scan.json"

# 2. JSON 파일 읽기
with open(file_path, "r", encoding="utf-8") as f:
    data = json.load(f)

# 3. 의존성 목록 추출
dependencies = data["dependencies"]

total_vulnerabilities = 0
vulnerable_packages = 0

print("=" * 50)
print("OSS Security Gate - Scan Analysis V1")
print("=" * 50)

# 4. 패키지별 취약점 분석
for package in dependencies:
    name = package["name"]
    version = package["version"]
    vulns = package.get("vulns", [])

    print(f"\nPackage: {name}")
    print(f"Version: {version}")
    print(f"Vulnerabilities: {len(vulns)}")

    if vulns:
        vulnerable_packages += 1

    total_vulnerabilities += len(vulns)

    for vuln in vulns:
        vuln_id = vuln["id"]
        fix_versions = vuln["fix_versions"]

        print(f"  - ID: {vuln_id}")
        print(f"    Fix: {fix_versions}")

# 5. 전체 진단 결과 출력
print("\n" + "=" * 50)
print("Scan Summary")
print("=" * 50)

print(f"Total Packages: {len(dependencies)}")
print(f"Vulnerable Packages: {vulnerable_packages}")
print(f"Total Vulnerabilities: {total_vulnerabilities}")
