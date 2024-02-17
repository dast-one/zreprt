"""OWASP® Zed Attack Proxy (ZAP) reporting utilities."""

__all__ = [
    'ZapReport', 'ZapSite', 'ZapAlertInfo', 'ZapAlertInstance',
]
__version__ = '0.3'

import sys

if sys.version_info.minor < 3 or sys.version_info.minor < 9:
    raise Exception('Python >= 3.9 please.')

from .zreprt import ZapReport, ZapSite, ZapAlertInfo, ZapAlertInstance
