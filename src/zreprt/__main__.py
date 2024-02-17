"""`__main__.py` is an entry point for `python -m ...`."""

import argparse
import sys
from attrs import evolve
from io import TextIOWrapper
from pathlib import Path
from itertools import chain, groupby

from . import ZapReport


DEFAULT_ALERTS_EXCLUDED = [
    10109,  # Modern Web Application
]


def main():
    """This callable is for more CLI-friendliness;
    ref: `project.scripts` at `pyproject.toml`."""

    parser = argparse.ArgumentParser(
        prog=sys.modules[__name__].__package__,
        usage='{ %(prog)s | python -m %(prog)s } [options]',
    )
    parser.add_argument(
        'in_file',
        nargs='*',
        type=argparse.FileType('r'),
        default=[sys.stdin,],
        help='Input file to parse as ZAP(-like) report, defaults to `-` (STDIN data).'
    )
    parser.add_argument(
        '-o', '--out_file',
        type=argparse.FileType('w'),
        default=None,
        help='Output file to write ZAP[-like] report to.'
             ' Defaults to STDOUT when reading from STDIN,'
             ' and to "<filename>-m.<ext>" when "<filename>.<ext>" specified as input.'
    )
    parser.add_argument(
        '-x',
        action='append',
        default=list(),
        help="Exclude alert(s) by their ZAP's `pluginid`, can be specified multiple times."
             ' Ref: <https://www.zaproxy.org/docs/alerts/>.'
             f' Use of this option overrides the default {DEFAULT_ALERTS_EXCLUDED}.'
    )
    parser.add_argument(
        '-k', '--keep-data-full', '--keep_data_full',
        action='store_true',
        help='Skip the default clearing request-response for alert instances,'
             ' except the last one within each alert.'
    )
    parser.add_argument(
        '-z', '--zap-original-output', '--zap_original_output',
        action='store_true',
        help='Use ZAP original field naming in JSON output, trying to resemble `traditional-json-plus`. Defaults to False, causing our ZAP-like output.'
             ' WARN: Mind some irreversible transformations performed:'
             ' HTML-tags removed from some fields;'
             ' some fields casted to int.'
    )
    args = parser.parse_args()

    zrs = list()
    for input_file in args.in_file:
        zr = ZapReport.from_json_file(input_file)

        while len(zr.site) > 1:
            _ = zr.site.pop(0)

        # Exclude some alerts
        zr.site[0].alerts = list(filter(
            lambda a: int(a.pluginid) not in (args.x or DEFAULT_ALERTS_EXCLUDED),
            zr.site[0].alerts
        ))

        zrs.append(zr)

    zr_merged = evolve(
        zrs[0],
        **({'program_name': '(combo)', 'version': ''} if len(zrs) > 1 else {}),
        site=[evolve(
            zrs[0].site[0],
            alerts=list(),
        ),]
    )
    kf = lambda a: (-int(a.riskcode), a.pluginid, a.alert, a.name, a.otherinfo)
    for _gk, agrp in groupby(sorted((a for zr in zrs for a in zr.site[0].alerts), key=kf), key=kf):
        agrp = list(agrp)
        ais = sorted(
            set(chain.from_iterable(a.instances for a in agrp)),
            # Keep alert instances with non-empty request/response in the end, to be consistent with further clearing
            key=lambda ai: (
                bool(ai.request_header or ai.request_body or ai.response_header or ai.response_body),
                ai,
            )
        )
        if not args.keep_data_full:
            # Clear the request/response for all but the last one
            for i in range(len(ais) - 1):
                ais[i].request_header = ''
                ais[i].request_body = ''
                ais[i].response_header = ''
                ais[i].response_body = ''
        new_alert = evolve(agrp[0], instances=ais, count=len(ais))
        zr_merged.site[0].alerts.append(new_alert)

    output_file = args.out_file
    if output_file is None:
        if args.in_file[0].name == '<stdin>':
            output_file = sys.stdout
        else:
            first_input_file = Path(args.in_file[0].name)
            output_file = first_input_file.with_stem(f'{first_input_file.stem}-m')

    with (output_file if isinstance(output_file, TextIOWrapper) else open(output_file, 'w')) as fo:
        fo.write(zr_merged.json_orig() if args.zap_original_output else zr_merged.json())


if __name__ == '__main__':
    main()
