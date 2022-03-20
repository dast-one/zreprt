"""
Structures here resemble OWASP® ZAP Traditional JSON Report,
with or without Requests and Responses.
Alerts are considered grouped by their info.
"""


import re
from datetime import datetime

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
        return self.json(by_alias=True)

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

    @validator('description', 'solution', 'otherinfo', 'reference', pre=True)
    def clean_some_attrs(cls, v):
        """Clean single string from extra html tags."""
        return _clns(v)

    @validator('cweid', 'wascid', 'sourceid', pre=True)
    def empty_to_none(cls, v):
        """Empty str -> -1 (backward compatibility)."""
        return v or -1

    def json_orig(self):
        return self.json(by_alias=True)

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
        return self.json(by_alias=True)

    class Config:
        allow_population_by_field_name = True
        orm_mode = True


class ZapReport(BaseModel):
    """Represents ZAP Traditional JSON Report."""

    version: str = Field(default='x3',
        alias='@version')
    generated_ts: datetime = Field(default_factory=lambda: datetime.now().ctime(),
        alias='@generated')
    site: list[ZapSite] = Field(default_factory=list)

    @validator('generated_ts', pre=True)
    def parse_ts(cls, v):
        return dateutil.parser.parse(v)

    def json_orig(self):
        return self.json(by_alias=True)

    class Config:
        allow_population_by_field_name = True
        orm_mode = True


if __name__ == '__main__':
    import sys
    from pathlib import Path
    zr = ZapReport.parse_file(
        Path(sys.argv[1]).expanduser())
    # dump only one alert and one its instance
    zr.site[0].alerts = [zr.site[0].alerts.pop(),]
    zr.site[0].alerts[0].instances = [zr.site[0].alerts[0].instances.pop(),]
    print(zr.json_orig())

