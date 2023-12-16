"""OWASP® Zed Attack Proxy (ZAP) reporting utilities."""

__all__ = [
    'ZapReport', 'ZapSite', 'ZapAlertInfo', 'ZapAlertInstance',
]
__version__ = '0.2'

import sys

if sys.version_info.minor < 10:
    raise Exception('Python >= 3.10 please.')

from .zreprt import ZapReport, ZapSite, ZapAlertInfo, ZapAlertInstance
