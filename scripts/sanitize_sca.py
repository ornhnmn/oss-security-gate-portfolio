import argparse
import json
import sys
from pathlib import Path


def string_list(value):
    if not isinstance(value, list):
        raise ValueError("Expected list")

    if not all(isinstance(item, str) for item in value):
        raise ValueError("Invalid list item")

    return value


def sanitize(data):
    if not isinstance(data, dict):
        raise ValueError("Invalid SCA document")

    dependencies = data.get("dependencies")

    if not isinstance(dependencies, list):
        raise ValueError("Invalid dependencies")

    result = []
    findings = 0

    for package in dependencies:
        if not isinstance(package, dict):
            raise ValueError("Invalid package")

        if not isinstance(package.get("name"), str):
            raise ValueError("Invalid package name")

        if "skip_reason" in package:
            result.append({
                "name": package["name"],
                "skip_reason": "Package skipped by scanner"
            })
            continue

        if not isinstance(package.get("version"), str):
            raise ValueError("Invalid package version")

        vulns = package.get("vulns")

        if not isinstance(vulns, list):
            raise ValueError("Invalid vulnerability list")

        clean_vulns = []

        for vuln in vulns:
            if not isinstance(vuln, dict):
                raise ValueError("Invalid vulnerability")

            if not isinstance(vuln.get("id"), str):
                raise ValueError("Invalid vulnerability ID")

            clean_vulns.append({
                "id": vuln["id"],
                "aliases": string_list(
                    vuln.get("aliases", [])
                ),
                "fix_versions": string_list(
                    vuln.get("fix_versions", [])
                )
            })

            findings += 1

        result.append({
            "name": package["name"],
            "version": package["version"],
            "vulns": clean_vulns
        })

    return {"dependencies": result}, findings


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)

    args = parser.parse_args()

    source = Path(args.input)
    target = Path(args.output)

    try:
        if source.resolve() == target.resolve():
            raise ValueError("Input and output must differ")

        target.unlink(missing_ok=True)

        data = json.loads(
            source.read_text(encoding="utf-8")
        )

        clean, findings = sanitize(data)

        with target.open("x", encoding="utf-8") as f:
            json.dump(clean, f, indent=2)
            f.write("\n")

        print("Packages:", len(clean["dependencies"]))
        print("Findings Preserved:", findings)
        print("Sanitization: PASS")

        return 0

    except (OSError, ValueError, TypeError):
        print(
            "Sanitization: FAILED",
            file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
