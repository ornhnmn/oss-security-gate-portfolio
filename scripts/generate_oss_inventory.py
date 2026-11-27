import csv
import json
import sys

from pathlib import Path
from packaging.utils import canonicalize_name
from packaging.version import Version


SBOM_PATH = Path(
    "sbom/remediated_sbom_enriched.json"
)

SCA_PATH = Path(
    "security/scan_results/remediated_scan.json"
)

METADATA_PATH = Path(
    "security/scan_results/remediated_metadata.json"
)

OUTPUT_PATH = Path(
    "docs/governance/oss_inventory.csv"
)

DIRECT_PACKAGES = {"requests", "pyyaml"}

BUILD_TOOLS = {
    "pip", "setuptools", "wheel",
    "cython", "packaging"
}

SNAPSHOT_DATE = "2026-11-27"


def load_json(path):
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def package_key(item):
    return (
        canonicalize_name(item["name"]),
        Version(item["version"])
    )


def build_index(items):
    result = {}

    for item in items:
        key = package_key(item)

        if key in result:
            raise ValueError(
                f"Duplicate package: {key}"
            )

        result[key] = item

    if not result:
        raise ValueError("Empty package inventory")

    return result


def dependency_type(name):
    name = canonicalize_name(name)

    if name in DIRECT_PACKAGES:
        return "DIRECT"

    if name in BUILD_TOOLS:
        return "BUILD_TOOL"

    return "TRANSITIVE"


def main():
    sbom = load_json(SBOM_PATH)
    sca = load_json(SCA_PATH)
    metadata = load_json(METADATA_PATH)

    components = sbom["components"]
    dependencies = sca["dependencies"]

    for package in dependencies:
        if package.get("skip_reason"):
            raise ValueError(
                "Skipped package detected"
            )

        if not isinstance(package.get("vulns"), list):
            raise ValueError(
                "Invalid vulnerability data"
            )

    sbom_index = build_index(components)
    sca_index = build_index(dependencies)
    metadata_index = build_index(metadata)

    if not (
        set(sbom_index)
        == set(sca_index)
        == set(metadata_index)
    ):
        raise ValueError(
            "Package inventory mismatch"
        )

    rows = []

    for number, key in enumerate(
        sorted(sbom_index), start=1
    ):
        component = sbom_index[key]
        scan = sca_index[key]
        package = metadata_index[key]

        name = component["name"]
        version = component["version"]

        licenses = [
            item["expression"]
            for item in component.get("licenses", [])
            if item.get("expression")
        ]

        license_source = next(
            (
                item["value"]
                for item in component.get(
                    "properties", []
                )
                if item["name"] ==
                "oss-security-gate:license-source"
            ),
            "UNKNOWN"
        )

        vulnerability_ids = {
            item["id"]
            for item in scan["vulns"]
        }

        notes = []

        if canonicalize_name(name) == "pip":
            notes.append(
                "Vendored components require review"
            )

        if canonicalize_name(name) == "packaging":
            notes.append(
                "Alternative license selection pending"
            )

        if canonicalize_name(name) == "certifi":
            notes.append(
                "MPL-2.0 obligations require review"
            )

        rows.append({
            "inventory_id": f"OSS-{number:03d}",
            "package_name": name,
            "version": version,
            "purl": component.get("purl", ""),
            "dependency_type": dependency_type(name),
            "license_expression": (
                "; ".join(licenses)
                if licenses else "UNKNOWN"
            ),
            "license_source": license_source,
            "license_review_status": "PENDING_REVIEW",
            "raw_findings": len(scan["vulns"]),
            "unique_findings": len(vulnerability_ids),
            "vulnerability_ids": "; ".join(
                sorted(vulnerability_ids)
            ),
            "sca_status": (
                "FINDINGS_DETECTED"
                if vulnerability_ids
                else "NO_KNOWN_FINDINGS"
            ),
            "distribution_url": (
                f"https://pypi.org/project/{name}/{version}/"
            ),
            "project_urls": "; ".join(
                package.get("project_urls", [])
            ),
            "service": "oss-security-gate-poc",
            "owner_role": "PROJECT_MAINTAINER",
            "approval_status": "PENDING_REVIEW",
            "snapshot_date": SNAPSHOT_DATE,
            "approval_date": "",
            "notes": "; ".join(notes)
        })

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if OUTPUT_PATH.exists():
        raise FileExistsError(
            "Inventory already exists. "
            "Preserve existing approval records "
            "before generating a new inventory."
        )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(rows[0].keys())
        )

        writer.writeheader()
        writer.writerows(rows)

    print("=" * 60)
    print("OSS Inventory Generation")
    print("=" * 60)

    print("SBOM Components:", len(sbom_index))
    print("SCA Packages:", len(sca_index))
    print("Metadata Packages:", len(metadata_index))
    print("Inventory Validation: PASS")
    print("Generated Records:", len(rows))

    for category in [
        "DIRECT", "TRANSITIVE", "BUILD_TOOL"
    ]:
        count = sum(
            row["dependency_type"] == category
            for row in rows
        )

        print(f"{category}: {count}")

    print("Approval Status: PENDING_REVIEW")
    print("Output:", OUTPUT_PATH)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        sys.exit(2)
