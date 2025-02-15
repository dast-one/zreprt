"""ZAP-like report to SARIF converter."""

import logging
import re
from collections import Counter
from datetime import datetime, UTC

from attrs import define, field

from . import __version__
from .sarif_om import *
from .zrlog import notii, _SarifNotificationKeeper


_THIS_TOOL_COMPONENT = ToolComponent(
    name='zreprt',
    full_description=MultiformatMessageString(text='DAST reporting facility that builds such SARIF reports with extended object model based on `python-sarif-om`.'),
    semantic_version=__version__,
)

_SARIF_SCH = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json'
_SARIF_SCH_VER = '2.1.0'

# A value specifying the severity level of the result.
# enum: [ "none", "note", "warning", "error" ]; default: "warning"
def ALERT_LEVEL_NORM(x):
    x = int(x or 2)
    if x > 2:
        return 'error'
    elif x == 2:
        return 'warning'
    else:
        return 'note'


REQUEST_LINE_P = re.compile(r'^(\w+) (.*) (\S+)')  # <method> <request-target> <protocol>
RESPONSE_LINE_P = re.compile(r'^(\S+) (\w+) (\w+)')  # <protocol> <status-code> <status-text>


# To be removed after
def _back_compat_trick(web_rr_parse_func):
    """Wrapper for http request/response coverter."""
    def foo(zhdr, zbody):
        """Preprocess headers+body stored as single string in body."""
        if zbody and not zhdr:
            if '\r\n' in zbody and (maybe_start_line := zbody[:zbody.index('\r\n')].replace('\n', ' ')):
                zbody = maybe_start_line + zbody[zbody.index('\r\n'):]
            lines = zbody.splitlines(keepends=False)
            try:
                e_o_hdr = lines.index('')
            except ValueError:
                return web_rr_parse_func(zhdr, zbody)
            else:
                return web_rr_parse_func('\r\n'.join(lines[:e_o_hdr]), '\r\n'.join(lines[e_o_hdr+1:]))
        else:
            return web_rr_parse_func(zhdr, zbody)
    return foo


@_back_compat_trick
def _web_request(zhdr, zbody):
    r = WebRequest()
    raw_data = dict()

    hdr_lines = list(filter(None, zhdr.splitlines(keepends=False)))
    start_line = (hdr_lines or ['',]).pop(0)

    if (m := REQUEST_LINE_P.match(start_line)) and len(m.groups()) == 3:
        r.method, r.target, protocol_version = m.groups()  # <method> <request-target> <protocol>
    else:
        notii.warning('Failed to parse start line of request header. Ref. to WebRequest.properties for raw-data.')
        raw_data.update({'request_header': zhdr, 'request_body': zbody})
        r.properties = {'raw_data': raw_data}
        return r

    if len(pv := protocol_version.split('/', maxsplit=1)) == 2:
        r.protocol, r.version = pv
    else:
        notii.warning('Failed to parse protocol/version at request header. Ref. to WebRequest.properties for raw-data.')
        raw_data.update({'start_line': start_line})

    hdr_lines_split = [line.split(':', maxsplit=1) for line in hdr_lines]
    if hdrs_ok := [h for h in hdr_lines_split if len(h) == 2]:
        r.headers = hdrs_ok
    if hdrs_nok := [h for h in hdr_lines_split if len(h) != 2]:
        notii.warning('Failed to parse request header(s). Ref. to WebRequest.properties for raw-data.')
        raw_data.update({'headers': hdrs_nok})

    if zbody:
        # TODO/WARN: Maybe there is more proper place for such data
        notii.info('Unknown (text/binary/rendered) body format (SARIF::artifactContent) stored to WebRequest.body.properties.')
        r.body = {'properties': {'request_body': zbody}}

    if raw_data:
        r.properties = {'raw_data': raw_data}

    return r


@_back_compat_trick
def _web_response(zhdr, zbody, no_response=False):
    r = WebResponse()
    raw_data = dict()

    hdr_lines = list(filter(None, zhdr.splitlines(keepends=False)))
    start_line = (hdr_lines or ['',]).pop(0)

    if (m := RESPONSE_LINE_P.match(start_line)) and len(m.groups()) == 3:
        protocol_version, r.status_code, r.reason_phrase = m.groups()  # <protocol> <status-code> <status-text>
    else:
        notii.warning('Failed to parse start line of response header. Ref. to WebResponse.properties for raw-data.')
        raw_data.update({'response_header': zhdr, 'response_body': zbody})
        r.properties = {'raw_data': raw_data}
        return r

    if len(pv := protocol_version.split('/', maxsplit=1)) == 2:
        r.protocol, r.version = pv
    else:
        notii.warning('Failed to parse protocol/version at response header. Ref. to WebResponse.properties for raw-data.')
        raw_data.update({'start_line': start_line})

    hdr_lines_split = [line.split(':', maxsplit=1) for line in hdr_lines]
    if hdrs_ok := [h for h in hdr_lines_split if len(h) == 2]:
        r.headers = hdrs_ok
    if hdrs_nok := [h for h in hdr_lines_split if len(h) != 2]:
        notii.warning('Failed to parse response header(s). Ref. to WebResponse.properties for raw-data.')
        raw_data.update({'headers': hdrs_nok})

    if zbody:
        # TODO/WARN: Maybe there is more proper place for such data
        notii.info('Unknown (text/binary/rendered) body format (SARIF::artifactContent) stored to WebResponse.body.properties.')
        r.body = {'properties': {'response_body': zbody}}

    if raw_data:
        r.properties = {'raw_data': raw_data}
    # r.index
    # r.no_response_received = no_response  # defaults to False, according to SARIF sch.

    return r


def transmodel(zr):
    ts0 = datetime.now(UTC).isoformat()

    rules = [
        ReportingDescriptor(
            id=str(alert.pluginid) or alert.alertref,  # TODO/WARN: pluginid-vs-alertref,
            name=alert.name or alert.alert,
            short_description=MultiformatMessageString(text=alert.alert or alert.name),
            full_description=MultiformatMessageString(text=alert.description),
            properties={
                k: v
                for (k, v) in {
                    'references': (
                        list(filter(None, alert.reference.splitlines()))
                        + list(filter(None, (e['link'] for e in alert.tags)))
                    ),
                    'solution': alert.solution,
                    'confidence': {1: 'low', 2: 'medium', 3: 'high'}.get(int(alert.confidence or 2)),
                    'otherinfo': alert.otherinfo,
                    'cweid': str(alert.cweid) if int(alert.cweid or -1) > 0 else None,
                    'wascid': str(alert.wascid) if int(alert.wascid or -1) > 0 else None,
                    'tags': list(filter(None, (e['tag'] for e in alert.tags))),
                }.items()
                if v
            } or None,
            # default_configuration=,  # zap: level
            # relationships=,  # zap: refs to cwe in its taxonomy
        ) for alert in zr.site[0].alerts
    ]

    results = [
        Result(
            level=ALERT_LEVEL_NORM(alert.riskcode),
            locations=[
                Location(
                    physical_location=PhysicalLocation(
                        artifact_location=ArtifactLocation(
                            uri=alein.uri
                        ),
                        # region=Region(snippet=ArtifactContent(text=alein.evidence)) if alein.evidence else None,
                    ),
                    # properties={'attack': alein.attack} if alein.attack else None,
                    properties={
                        k: v
                        for k in ('param', 'attack', 'evidence')
                        if (v := getattr(alein, k))
                    } or None
                ),
            ],
            message=Message(text=alert.description),
            rule_id=str(alert.pluginid) or alert.alertref,  # TODO/WARN: pluginid-vs-alertref
            **(
                {'web_request': _web_request(alein.request_header, alein.request_body)}
                if alein.request_header or alein.request_body else {}
            ),
            **(
                {'web_response': _web_response(alein.response_header, alein.response_body)}
                if alein.response_header or alein.response_body else {}
            ),
        )
        for alert in zr.site[0].alerts for alein in alert.instances
    ]

    # WARN: Order matters: Conversion summary should be constructed
    # after other entities, since it includes the notifications log.
    ts1 = datetime.now(UTC).isoformat()
    conv_info = Conversion(
        tool=_THIS_TOOL_COMPONENT,
        invocation=Invocation(
            start_time_utc=ts0,
            end_time_utc=ts1,
            tool_execution_notifications=[
                Notification(Message(text=f'{levelname} (x{n}) {msg}'))
                for (levelname, msg), n in Counter(
                    (r.levelname, r.msg) for r in _SarifNotificationKeeper.sarif_notii).items()
            ],
            # tool_configuration_notifications=[Notification(Message(
            #     text='...note on excludes and trimming performed...')),],
            execution_successful=True,
        ),
    )

    return SarifLog(
        schema_uri=_SARIF_SCH,
        version=_SARIF_SCH_VER,
        runs=[
            Run(
                results=results,
                # taxonomies=,
                tool=Tool(
                    driver=ToolComponent(
                        name=zr.program_name,
                        version=zr.version,
                        rules=rules,
                    ),
                    # extensions=[_D1J_COMPONENT,],
                ),
                # invocations=,
                conversion=conv_info,
            ),
        ],
    )
