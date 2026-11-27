
import json
from packaging.utils import canonicalize_name

sbom_path = "sbom/initial_sbom.json"
scan_path = "security/scan_results/initial_scan.json"

# 1. JSON 파일 읽기
with open(sbom_path, encoding="utf-8") as f:
    sbom_data = json.load(f)

with open(scan_path, encoding="utf-8") as f:
    scan_data = json.load(f)

# 2. 패키지 이름 및 버전 추출
sbom_packages = {
    (canonicalize_name(component["name"]), component["version"])
    for component in sbom_data["components"]
}

scan_packages = {
    (canonicalize_name(package["name"]), package["version"])
    for package in scan_data["dependencies"]
}

# 3. 집합 연산을 통한 비교
matched = sbom_packages & scan_packages
sbom_only = sbom_packages - scan_packages
scan_only = scan_packages - sbom_packages

# 4. 알려진 검사 범위 차이 분류
environment_tools = {"pip"}

expected_differences = {
    package for package in sbom_only
    if package[0] in environment_tools
}

unexpected_differences = sbom_only - expected_differences

# 5. 검증 결과 출력
print("=" * 50)
print("OSS Security Gate - SBOM Validation")
print("=" * 50)

print(f"SBOM Components: {len(sbom_packages)}")
print(f"SCA Components: {len(scan_packages)}")
print(f"Matched Components: {len(matched)}")

print("\n[Matched Components]")
for name, version in sorted(matched):
    print(f"  {name}=={version}")

print("\n[Expected Scope Differences]")
for name, version in sorted(expected_differences):
    print(f"  {name}=={version}")

print("\n[Unexpected SBOM-only Components]")
for name, version in sorted(unexpected_differences):
    print(f"  {name}=={version}")

print("\n[SCA-only Components]")
for name, version in sorted(scan_only):
    print(f"  {name}=={version}")

# 6. 최종 검증 결과
print("\n" + "=" * 50)

if unexpected_differences or scan_only:
    print("Validation Result: FAIL")
    raise SystemExit(1)
else:
    print("Validation Result: PASS")
    raise SystemExit(0)
