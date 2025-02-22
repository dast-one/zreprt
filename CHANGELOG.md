
# Changelog


## [v0.4](https://github.com/dast-one/zreprt/tree/v0.4) (2025-02)

[Full Changelog](https://github.com/dast-one/zreprt/compare/v0.3.1...v0.4)

**New:**

  - Initial SARIF support, with structure and `repr`s tuned according to Nuclei and ZAP outputs.

    **_Hint_**: You can convert your past ZAP-Traditional-JSON reports or Zap-Like reports generated by this utility.

**Minor changes:**

  - HTML-tags clearing at some descr/reference-like strings (within zap alert info) is now a bit more eye and `splitlines()` friendly.


## [v0.3.1](https://github.com/dast-one/zreprt/tree/v0.4) (2025-02)

[Full Changelog](https://github.com/dast-one/zreprt/compare/v0.3...v0.3.1)

  - Fixed ValueError for some ZAP JSON reports with empty strings at int typed fields

  - Relicensed to Apache-2.0


## [v0.3](https://github.com/dast-one/zreprt/tree/v0.3) (2024-02)

[Full Changelog](https://github.com/dast-one/zreprt/compare/v0.2...v0.3)

WARN: Mind several breaking CLI changes.
Major one: related to input data, files/stdin.

  - Reports merging feature
  - Alerts exclusion parametrized
  - Following the ZAP report structure update (new JSON fields)
  - Report reducing as an option


## [v0.2](https://github.com/dast-one/zreprt/tree/v0.2) (2024-01)

[Full Changelog](https://github.com/dast-one/zreprt/compare/v0.1...v0.2)

  - Python package module to be runnable, both with `python -m ...` and as an executable
  - Following the ZAP report structure update (new JSON fields)
  - Python-3.9 compatibility


## [v0.1](https://github.com/dast-one/zreprt/tree/v0.1) (2023-12)

[Full](https://github.com/dast-one/zreprt/commits/v0.1) [Changelog](https://github.com/dast-one/zreprt/compare/a7c066e...v0.1)

  - After some experiments with `pydantic`... finally relied on `attrs`/`cattrs`
  - Py-packaged
  - Published under MIT terms


----

_This changelog is carefully crafted by the author._
