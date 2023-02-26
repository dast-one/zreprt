"""
Structures here resemble OWASP® ZAP Traditional JSON Report,
with or without Requests and Responses.
Alerts are considered grouped by their info.

Changes to the Traditional JSON Report format:
- some fields renamed, keeping original names as aliases
- timestamps are in ISO format, in UTC

Some refs:
- https://www.zaproxy.org/docs/constants/
"""

import re
from datetime import datetime, timezone

import dateutil.parser
from pydantic import BaseModel, Field, validator


def _clns(s, p=re.compile(r'</?p>')):
    """Clean single string from extra html tags."""
    return p.sub('', s)


class ZapAlertInstance(BaseModel):
    uri: str
    method: str
    param: str
    attack: str
    evidence: str
    request_header: str | None = Field(alias='request-header', repr=False)
    request_body: str | None = Field(alias='request-body', repr=False)
    response_header: str | None = Field(alias='response-header', repr=False)
    response_body: str | None = Field(alias='response-body', repr=False)

    def json_orig(self):
        return self.json(by_alias=True, exclude_none=True, indent=4, ensure_ascii=False)

    class Config:
        allow_population_by_field_name = True
        orm_mode = True


class ZapAlertInfo(BaseModel):
    pluginid: int
    alertref: str = Field(alias='alertRef')
    alert: str
    name: str
    riskcode: int
    confidence: int
    riskdesc: str
    description: str = Field(alias='desc')
    solution: str
    otherinfo: str
    reference: str
    cweid: int
    wascid: int
    sourceid: int
    instances: list[ZapAlertInstance]
    count: int | None

    @validator('description', 'solution', 'otherinfo', 'reference', pre=True)
    def clean_some_attrs(cls, v):
        """Clean single string from extra html tags."""
        return _clns(v)

    @validator('cweid', 'wascid', 'sourceid', pre=True)
    def empty_to_none(cls, v):
        """Empty str -> -1 (backward compatibility)."""
        return v or -1

    def json_orig(self):
        return self.json(by_alias=True, exclude_none=True, indent=4, ensure_ascii=False)

    class Config:
        allow_population_by_field_name = True
        orm_mode = True


class ZapSite(BaseModel):
    name: str = Field(alias='@name')
    host: str = Field(alias='@host')
    port: str = Field(alias='@port')
    ssl: bool = Field(alias='@ssl')
    alerts: list[ZapAlertInfo]

    def json_orig(self):
        return self.json(by_alias=True, exclude_none=True, indent=4, ensure_ascii=False)

    class Config:
        allow_population_by_field_name = True
        orm_mode = True


class ZapReport(BaseModel):
    """Represents ZAP Traditional JSON Report."""

    version: str = Field(default='x3',
        alias='@version')
    generated_ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        alias='@generated')
    site: list[ZapSite] = Field(default_factory=list)

    @validator('generated_ts', pre=True)
    def parse_ts(cls, v):
        ts = dateutil.parser.parse(v)
        return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts

    def json_orig(self):
        return self.json(by_alias=True, exclude_none=True, indent=4, ensure_ascii=False)

    class Config:
        allow_population_by_field_name = True
        orm_mode = True


if __name__ == '__main__':
    import sys
    from pathlib import Path

    report_file = Path(sys.argv[1]).expanduser()

    zr = ZapReport.parse_file(report_file)

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

