"""
Structures here resemble OWASP® ZAP Traditional JSON Report,
with or without Requests and Responses.
Alerts are considered grouped by their info.

Changes to the Traditional JSON Report format:
- some fields renamed, keeping original names as aliases;
- some (re)typing: timestamps are ISO-formatted,
    some int and bool instead of strings;
- html tags are stripped from some fields containing descriptions.

See also:
- https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/
- https://www.zaproxy.org/docs/constants/
"""

import re
from datetime import datetime, timezone

import dateutil.parser
from attrs import define, field
from cattrs import Converter
from cattrs.gen import make_dict_structure_fn, make_dict_unstructure_fn, override
from cattrs.preconf.json import make_converter


def _clns(s, p=re.compile(r'</?p>')):
    """Clear single string of extra html tags."""
    return p.sub('', s)


_zlike_conv = make_converter()
_zlike_conv.register_unstructure_hook(datetime, lambda dt: dt.isoformat())
_zlike_conv.register_structure_hook(datetime, lambda s, _: ts if (ts:=dateutil.parser.parse(s)).tzinfo
                                                             else ts.replace(tzinfo=timezone.utc))
_zorig_conv = _zlike_conv.copy()


def _fallback_field(
    old_to_new_field: dict[str, str],
    zap_like_report_converter: Converter = _zlike_conv,
    zap_orig_report_converter: Converter = _zorig_conv,
):
    """Ref: https://catt.rs/en/stable/usage.html#using-fallback-key-names"""
    def decorator(cls):
        struct = make_dict_structure_fn(cls, zap_like_report_converter)
        def structure(d, cl):
            # if set(d.keys()) & set(old_to_new_field.keys()):
            for old_field, new_field in old_to_new_field.items():
                if old_field in d:
                    d[new_field] = d[old_field]
            return struct(d, cl)
        zap_like_report_converter.register_structure_hook(cls, structure)

        unstruct = make_dict_unstructure_fn(
            cls,
            zap_orig_report_converter,
            **{
                new_field: override(rename=old_field) for old_field, new_field in old_to_new_field.items()
            },
        )
        zap_orig_report_converter.register_unstructure_hook(cls, unstruct)

        return cls
    return decorator


@_fallback_field({
    "request-header": "request_header",
    "request-body": "request_body",
    "response-header": "response_header",
    "response-body": "response_body",
})
@define
class ZapAlertInstance:
    uri: str
    method: str
    param: str
    attack: str
    evidence: str
    request_header: str | None = field(default=None, repr=False)
    request_body: str | None = field(default=None, repr=False)
    response_header: str | None = field(default=None, repr=False)
    response_body: str | None = field(default=None, repr=False)


@_fallback_field({
    "alertRef": "alertref",
    "desc": "description",
})
@define
class ZapAlertInfo:
    pluginid: int
    alertref: str
    alert: str
    name: str
    riskcode: int
    confidence: int
    riskdesc: str
    description: str = field(converter=_clns)
    solution: str = field(converter=_clns)
    otherinfo: str = field(converter=_clns)
    reference: str = field(converter=_clns)
    cweid: int = field(converter=lambda v: v or -1)
    wascid: int = field(converter=lambda v: v or -1)
    sourceid: int = field(converter=lambda v: v or -1)
    instances: list[ZapAlertInstance]
    count: int | None = None

    # @field_validator('description', 'solution', 'otherinfo', 'reference', mode='before')
    # def clean_some_attrs(cls, v):
    #     """Clear single string of extra html tags."""
    #     return _clns(v)

    # @field_validator('cweid', 'wascid', 'sourceid', mode='before')
    # def empty_to_none(cls, v):
    #     """Empty str -> -1 (backward compatibility)."""
    #     return v or -1


@_fallback_field({
    "@name": "name",
    "@host": "host",
    "@port": "port",
    "@ssl": "ssl",
})
@define
class ZapSite:
    name: str
    host: str
    port: str
    ssl: bool
    alerts: list[ZapAlertInfo]


@_fallback_field({
    "@version": "version",
    "@generated": "generated_ts",
})
@define
class ZapReport:
    """Represents ZAP Traditional JSON Report."""

    version: str = field(default='x3')
    generated_ts: datetime = field(factory=lambda: datetime.now(timezone.utc))
    site: list[ZapSite] = field(factory=list)

    @classmethod
    def from_json_file(cls, f):
        with open(f) as fo:
            return _zlike_conv.loads(fo.read(), cls)

    @classmethod
    def from_dict(cls, d):
        return _zlike_conv.structure(d, cls)

    def json(self):
        return _zlike_conv.dumps(self, indent=4, ensure_ascii=False)

    def json_orig(self):
        return _zorig_conv.dumps(self, indent=4, ensure_ascii=False)


if __name__ == '__main__':
    import sys
    from pathlib import Path

    report_file = Path(sys.argv[1]).expanduser()

    zr = ZapReport.from_json_file(report_file)

    # # dump only one alert and one its instance
    # zr.site[0].alerts = [zr.site[0].alerts.pop(),]
    # zr.site[0].alerts[0].instances = [zr.site[0].alerts[0].instances.pop(),]
    # print(zr.json_orig())

    while len(zr.site) > 1:
        _ = zr.site.pop(0)

    for a in zr.site[0].alerts:
        for i in range(len(a.instances) - 1):
            a.instances[i].request_header = ''
            a.instances[i].request_body = ''
            a.instances[i].response_header = ''
            a.instances[i].response_body = ''

    # Exclude some alerts
    zr.site[0].alerts = list(filter(
        lambda a: int(a.pluginid) not in (10096, 10027),
        zr.site[0].alerts
    ))

    with open(report_file.with_stem(f'{report_file.stem}-m'), 'w') as fo:
        fo.write(zr.json_orig())
