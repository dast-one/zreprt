"""`__main__.py` is an entry point for `python -m ...`."""

import argparse
import sys
from io import TextIOWrapper
from pathlib import Path

from . import ZapReport


def main():
    """This callable is for more CLI-friendliness;
    ref: `project.scripts` at `pyproject.toml`."""

    parser = argparse.ArgumentParser(
        prog=sys.modules[__name__].__package__,
        usage='{ %(prog)s | python -m %(prog)s } [options]',
    )
    parser.add_argument(
        '-i', '--in_file',
        type=argparse.FileType('r'),
        default=sys.stdin,
        help='Input file to parse as ZAP(-like) report, defaults to `-` (STDIN data).'
    )
    parser.add_argument(
        '-o', '--out_file',
        type=argparse.FileType('w'),
        # default=sys.stdout,
        default=None,
        help='Output file to write ZAP[-like] report to.'
             ' Defaults to STDOUT when reading from STDIN,'
             ' and to "<filename>-m.<ext>" when "<filename>.<ext>" specified as input.'
    )
    # parser.add_argument(
    #     '--format',
    #     type=str.lower,
    #     choices=['original', 'd1-zap-like'],
    #     default='d1-zap-like',
    #     help='Output format.',
    # )
    parser.add_argument(
        '-z', '--zap-original-format', '--zap_original_format',
        action='store_true',
        help='Use ZAP original JSON output. Defaults to False, causing ZAP-like output.',
    )
    args = parser.parse_args()

    zr = ZapReport.from_json_file(args.in_file)

    # # dump only one alert and one its instance
    # # TODO: Parametrize this
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
    # TODO: Parametrize this
    zr.site[0].alerts = list(filter(
        lambda a: int(a.pluginid) not in (
            10096,  # Timestamp Disclosure
            10027,  # Information Disclosure - Suspicious Comments
        ),
        zr.site[0].alerts
    ))

    output_file = args.out_file
    if output_file is None:
        if args.in_file.name == '<stdin>':
            output_file = sys.stdout
        else:
            input_file = Path(args.in_file.name)
            output_file = input_file.with_stem(f'{input_file.stem}-m')

    with (output_file if isinstance(output_file, TextIOWrapper) else open(output_file, 'w')) as fo:
        fo.write(zr.json_orig() if args.zap_original_format else zr.json())


if __name__ == '__main__':
    main()
