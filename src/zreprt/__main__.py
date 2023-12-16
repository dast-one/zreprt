import sys
from pathlib import Path

from . import ZapReport


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
