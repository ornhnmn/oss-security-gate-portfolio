import json
import sys
import uuid

from datetime import datetime, timezone
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.licenses import canonicalize_license_expression
from packaging.version import Version

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator


SBOM_PATH = Path("sbom/remediated_sbom.json")

METADATA_PATH = Path(
    "security/scan_results/remediated_metadata.json"
)

OUTPUT_PATH = Path(
    "sbom/remediated_sbom_enriched.json"
)


def package_key(item):
    return (
        canonicalize_name(item["name"]),
        Version(item["version"])
    )


def build_index(items):
    index = {}

    for item in items:
        key = package_key(item)

        if key in index:
            raise ValueError(
                f"Duplicate package: {key}"
            )

        index[key] = item

    return index


def resolve_license(metadata):
    for field in ("license_expression", "license"):
        value = metadata.get(field)

        if value and value.strip():
            expression = canonicalize_license_expression(
                value.strip()
            )

            return expression, field

    return None, None


def main():
    sbom = json.loads(
        SBOM_PATH.read_text(encoding="utf-8")
    )

    metadata = json.loads(
        METADATA_PATH.read_text(encoding="utf-8")
    )

    components = sbom["components"]

    sbom_index = build_index(components)
    metadata_index = build_index(metadata)

    if not sbom_index:
        raise ValueError("Empty SBOM")

    if set(sbom_index) != set(metadata_index):
        raise ValueError(
            "SBOM and metadata inventory mismatch"
        )

    before = sum(
        bool(item.get("licenses"))
        for item in components
    )

    enriched = 0
    unresolved = 0

    print("=" * 65)
    print("OSS Security Gate - SBOM License Enrichment")
    print("=" * 65)

    for component in components:
        key = package_key(component)
        package = metadata_index[key]

        expression, source = resolve_license(package)

        if expression is None:
            unresolved += 1
            print(f"[UNKNOWN] {component['name']}")
            continue

        component["licenses"] = [
            {"expression": expression}
        ]

        component.setdefault("properties", []).extend([
            {
                "name": "oss-security-gate:license-source",
                "value": f"installed-metadata:{source}"
            },
            {
                "name": "oss-security-gate:license-status",
                "value": "DECLARED_NOT_LEGALLY_VERIFIED"
            }
        ])

        enriched += 1

        print(
            f"[PASS] {component['name']} "
            f"{component['version']}: "
            f"{expression} ({source})"
        )

    sbom["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    sbom["version"] = 1

    sbom.setdefault("metadata", {})["timestamp"] = (
        datetime.now(timezone.utc).isoformat()
    )

    result = json.dumps(
        sbom,
        indent=2,
        ensure_ascii=False
    )

    validator = JsonStrictValidator(
        SchemaVersion.V1_6
    )

    errors = validator.validate_str(result)

    if errors is not None:
        raise ValueError(
            f"CycloneDX schema error: {errors}"
        )

    OUTPUT_PATH.write_text(
        result + "\n",
        encoding="utf-8"
    )

    print()
    print("=" * 65)
    print("Enrichment Summary")
    print("=" * 65)

    print("Total Components:", len(components))
    print("License Coverage Before:", before)
    print("License Metadata Enriched:", enriched)
    print("Unresolved Licenses:", unresolved)
    print("Inventory Validation: PASS")
    print("CycloneDX Schema Validation: PASS")
    print("Output:", OUTPUT_PATH)

    return 1 if unresolved else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        sys.exit(2)
