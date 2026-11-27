import json
import sys
from pathlib import Path

from packaging.utils import canonicalize_name


ROOT = Path("ci-artifacts")


def load_inventory():

    packages = set()

    for line in (ROOT / "packages.txt").read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if not line:
            continue

        if line.count("==") != 1:
            raise ValueError(
                f"Invalid pinned requirement: {line}"
            )

        name, version = line.split("==")

        if not name.strip() or not version.strip():
            raise ValueError("Empty package name or version")

        packages.add(
            (canonicalize_name(name), version)
        )

    if not packages:
        raise ValueError("Empty package inventory")

    return packages


def load_sca():

    data = json.loads(
        (ROOT / "sca.json").read_text(
            encoding="utf-8"
        )
    )

    packages = set()

    for item in data["dependencies"]:

        if "skip_reason" in item:
            raise ValueError(
                f"Skipped package: {item['name']}"
            )

        if not isinstance(item.get("vulns"), list):
            raise ValueError(
                f"Invalid vulnerability list: {item['name']}"
            )

        packages.add((
            canonicalize_name(item["name"]),
            item["version"]
        ))

    return packages


def load_sbom():

    data = json.loads(
        (ROOT / "sbom.json").read_text(
            encoding="utf-8"
        )
    )

    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("Invalid SBOM format")

    return {
        (
            canonicalize_name(item["name"]),
            item["version"]
        )
        for item in data["components"]
    }


def compare(label, expected, actual):

    missing = expected - actual
    unexpected = actual - expected

    print(f"\n[{label}]")

    for name, version in sorted(missing):
        print(f"MISSING: {name}=={version}")

    for name, version in sorted(unexpected):
        print(f"UNEXPECTED: {name}=={version}")

    if missing or unexpected:
        print("Result: FAIL")
        return False

    print("Result: PASS")
    return True


def main():

    try:

        inventory = load_inventory()
        sca = load_sca()
        sbom = load_sbom()

        print("=" * 50)
        print("CI Inventory Validation")
        print("=" * 50)

        print("Installed Packages:", len(inventory))
        print("SCA Packages:", len(sca))
        print("SBOM Components:", len(sbom))

        sca_valid = compare(
            "Inventory vs SCA",
            inventory,
            sca
        )

        sbom_valid = compare(
            "Inventory vs SBOM",
            inventory,
            sbom
        )

        if sca_valid and sbom_valid:
            print("\nValidation Result: PASS")
            return 0

        print("\nValidation Result: FAIL")
        return 1

    except Exception as error:

        print(f"[ERROR] {error}")
        print("Validation Result: FAIL")

        return 2


if __name__ == "__main__":
    sys.exit(main())
