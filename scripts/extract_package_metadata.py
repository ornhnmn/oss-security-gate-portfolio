import json
from importlib.metadata import distributions


def extract_metadata():
    packages = []

    for dist in distributions():
        metadata = dist.metadata

        packages.append({
            "name": metadata.get("Name"),
            "version": dist.version,
            "license": metadata.get("License"),
            "license_expression": metadata.get(
                "License-Expression"
            ),
            "license_files": metadata.get_all(
                "License-File"
            ) or [],
            "license_classifiers": [
                item
                for item in (
                    metadata.get_all("Classifier") or []
                )
                if item.startswith("License ::")
            ],
            "home_page": metadata.get("Home-page"),
            "project_urls": metadata.get_all(
                "Project-URL"
            ) or [],
            "requires_dist": metadata.get_all(
                "Requires-Dist"
            ) or []
        })

    return sorted(
        packages,
        key=lambda item: (item["name"] or "").lower()
    )


if __name__ == "__main__":
    result = extract_metadata()
    print(json.dumps(
        result,
        indent=2,
        ensure_ascii=False
    ))
