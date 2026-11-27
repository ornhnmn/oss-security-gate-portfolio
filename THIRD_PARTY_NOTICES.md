# Third-Party Notices and Data Attribution

## 1. Scope

This repository contains source code, policy documents,
software component metadata, SBOM files and
vulnerability scan results.

Third-party data remains subject to the applicable
terms of its original sources.

## 2. Vulnerability Data Sources

### PyPI Advisory Database

- Source: https://github.com/pypa/advisory-database
- License: Creative Commons Attribution 4.0 International
- License URL: https://creativecommons.org/licenses/by/4.0/

### GitHub Advisory Database

- Source: https://github.com/github/advisory-database
- License: Creative Commons Attribution 4.0 International
- License URL: https://creativecommons.org/licenses/by/4.0/

### OSV

- Source: https://osv.dev/
- Data sources: https://google.github.io/osv.dev/data/

Licensing conditions may differ depending on the
original vulnerability data source.

## 3. Data Processing

Vulnerability scan results were collected using
pip-audit.

Selected records were normalized, deduplicated,
classified and summarized for security policy
evaluation and remediation tracking.

The original advisory identifiers and aliases
are retained where available.

## 4. Software Component Metadata

SBOM and inventory records include package names,
versions, identifiers and declared license metadata
obtained from installed Python distributions.

Declared license metadata does not constitute
legal verification of license compliance.

## 5. Review Status

The data sources listed above are reference sources.
Individual record provenance and redistribution
requirements require further verification.

This notice does not override third-party licenses
or grant additional rights to third-party material.

## 6. Disclaimer

This repository is an educational security PoC.
It is not affiliated with any financial institution
or certification authority.

## 7. Public Portfolio Data Sanitization

The public portfolio version excludes the original
vulnerability description fields from historical
SCA snapshot files.

Structured advisory identifiers, aliases, package
versions and reported fix versions are retained
for security analysis and reproducibility.

Original development history and raw scan evidence
are maintained separately in a private repository.

Sanitization does not remove applicable third-party
attribution or licensing obligations.
