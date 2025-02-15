# DAST unified reporting

Utilities here should help you to normalize and merge non-SARIF DAST reports, producing either ZAP-like or SARIF output.

Structures here resemble OWASP/Checkmarx ZAP Traditional JSON Report model. Alerts are considered grouped by their info.

Install from [pypi](https://pypi.org/project/zreprt/): `pip install zreprt`

Use CLI utility to convert/merge ZAP and ZAP-like reports to ZAP-like or SARIF:

```sh
python -m zreprt --help
# or
zreprt -h
```


## What is _ZAP-like_

Changes to the Traditional JSON Report format:

  - some fields renamed, keeping original names as aliases;
  - some (re)typing: timestamps are ISO-formatted,
      some int and bool instead of strings;
  - html tags are stripped from some fields containing descriptions.

See also:

  - https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/
  - https://www.zaproxy.org/docs/constants/


## What is SARIF

Despite the origin,

> The Static Analysis Results Interchange Format (SARIF) is an industry standard format for the output of static analysis tools, [approved](https://www.oasis-open.org/news/announcements/static-analysis-results-interchange-format-sarif-v2-1-0-is-approved-as-an-oasis-s) by the [OASIS](https://www.oasis-open.org/).

such model would also fit DAST reporting needs, and that's nice to see, at least [Nuclei](https://docs.projectdiscovery.io/tools/nuclei) and [ZAP](https://www.zaproxy.org) also think so.

Utilities here have minimal enough support to _read_ SARIF reports and evolving support to _produce_ SARIF output, especially in the domain of Dynamic AppSec Testing.

If you need to deal with SARIF-files only, e.g. read & mangle them, in general, please refer to the tools like https://github.com/microsoft/sarif-tools.
