# zreprt

ZAP and ZAP-like reporting facility

Structures here resemble OWASP® ZAP Traditional JSON Report, with or without Requests and Responses. Alerts are considered grouped by their info.

Changes to the Traditional JSON Report format:

- some fields renamed, keeping original names as aliases;
- some (re)typing: timestamps are ISO-formatted,
    some int and bool instead of strings;
- html tags are stripped from some fields containing descriptions.

See also:
- https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/
- https://www.zaproxy.org/docs/constants/
