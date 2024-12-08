"""Proxy/wrapper module to the sarif_om package.

Microsoft's sarif-python-om is a set of classes generated from the OASIS spec.
This module adds typing annotations for convenience with cattrs-structuring.
"""

import sys
from io import TextIOWrapper

from attrs import define, field, fields, has
from cattrs import BaseValidationError, transform_error
from cattrs.gen import make_dict_structure_fn, make_dict_unstructure_fn, override
from cattrs.preconf.json import make_converter
from sarif_om import *


# Module variable allows user to select __repr__,
# either defined here or original one.
PRETTY_REPR = True


def _combine(cls, cls_fields, module=sys.modules['sarif_om']):
    """Field transformer
    that copies Attributes from the class with the same name in given module
    and enrich them with the type annotations in the class defined here.
    """
    redefined_type = {a.name: a.type for a in cls_fields}
    return [
        a.evolve(type=redefined_type[a.name]) if a.name in redefined_type else a
        for a in fields(getattr(module, cls.__name__))
    ]


def _pretty_repr(cls):
    """Class decorator for conditional customizing `__repr__`.

    Classes (re)defined here should define `prepr` (pretty-repr) method
    that will be used as `__repr__` instead of added by `attrs`.
    """
    attrs_orig_repr = cls.__repr__
    cls.__repr__ = lambda self: cls.prepr(self) if PRETTY_REPR else attrs_orig_repr(self)
    return cls


conv = make_converter()

# Hook factories to add renaming overrides on un/structured fields
# whose name-at-class differs from name-at-schema (as per metadata).
conv.register_unstructure_hook_factory(
    has,
    lambda cls: make_dict_unstructure_fn(
        cls,
        conv,
        _cattrs_omit_if_default=True,
        **{
            a.name: override(rename=metaname)
            for a in fields(cls)
            if (metaname := a.metadata.get('schema_property_name')) and a.name != metaname
        }
    )
)
conv.register_structure_hook_factory(
    has,
    lambda cls: make_dict_structure_fn(
        cls,
        conv,
        **{
            a.name: override(rename=metaname)
            for a in fields(cls)
            if (metaname := a.metadata.get('schema_property_name')) and a.name != metaname
        }
    )
)


@define
class ZreprtExtraInfo:
    """Extra messages to be included as properties, when needed,
    e.g. error/exception info."""
    zreprt_msgs: list[str] = field(factory=list)
    extras: dict = field(factory=dict)

    def add(self, msg, d=dict(), **kwargs):
        self.zreprt_msgs.append(msg)
        self.extras.update(d)
        self.extras.update(kwargs)

    def asdict(self):
        return {
            '_zreprt_msg': ';\n'.join(map(str, self.zreprt_msgs)),
            **self.extras,
        }

conv.register_unstructure_hook(ZreprtExtraInfo, lambda ze: ze.asdict())


# ---------------------------------------------------------------------
# Here go the SARIF object model (re)definitions
#
#   - with `field_transformer` to be set for classes where,
#   - with pretty-reprs optionally decor-defined.
#
# Redefinitions required: typing, marking optional fields.
# WARN: DEFINITION ORDER MATTERS!
#
# Minimal enough set of required redefinitions: those that should be
# resolved when structuring _from_ a dict or a json file.


@define(field_transformer=_combine)
class ToolComponent:
    full_description: MultiformatMessageString | None
    short_description: MultiformatMessageString | None
    taxa: list[ReportingDescriptor] | None


@_pretty_repr
@define(field_transformer=_combine)
class PhysicalLocation:
    address: Address | None  # WARN: "anyOf" (address, artifact_location) is required
    artifact_location: ArtifactLocation | None  # WARN: "anyOf" (address, artifact_location) is required
    context_region: Region | None
    region: Region | None

    def prepr(self):
        loc = (
            (getattr(self.artifact_location, 'description') or dict()).get('text')  # Nuclei writes nice URI here
            or getattr(self.artifact_location, 'uri', '')
        )
        start_line = f', L{self.region.start_line}' if hasattr(self.region, 'start_line') else ''
        return f'PhysLoc({repr(loc)}{start_line})' if loc else 'PhysLoc(WARN_Empty_PRETTY_REPR)'


@_pretty_repr
@define(field_transformer=_combine)
class Location:
    message: Message | None
    physical_location: PhysicalLocation | None

    def prepr(self):
        return repr(self.physical_location) if self.physical_location else 'Location(WARN_Empty_PRETTY_REPR)'


@_pretty_repr
@define(field_transformer=_combine)
class Result:
    analysis_target: ArtifactLocation | None
    locations: list[Location] | None
    message: Message
    rule: ReportingDescriptorReference | None
    web_request: WebRequest | None
    web_response: WebResponse | None

    def prepr(self):
        rule = self.rule_id or (self.rule.id if self.rule else '') or None
        msg = self.message.text or 'WARN_Empty_PRETTY_REPR'
        if len(msg) > 80:
            msg = msg[:80] + '...'
        locs = list(map(repr, self.locations))
        return f'Result({repr(rule)} ~ {repr(msg)} @ {locs})'


@define(field_transformer=_combine)
class Tool:
    driver: ToolComponent


@define(field_transformer=_combine)
class Run:
    tool: Tool
    results: list[Result] | None
    invocations: list[Invocation] | None
    taxonomies: list[ToolComponent] | None

    def __repr__(self):
        return ',\n'.join((
            'Run(',
            repr(self.tool),
            repr(self.invocations),
            repr(self.results),
            repr(self.taxonomies),
            ')',
        ))


@define(field_transformer=_combine)
class SarifLog:
    """Root entity."""
    runs: list[Run]

    @classmethod
    def from_json_file(cls, f):
        with (f if isinstance(f, TextIOWrapper) else open(f)) as fo:
            try:
                return conv.loads(fo.read(), cls)
            except BaseValidationError as e:
                print(transform_error(e), file=sys.stderr)
                # raise e
                return None

    @classmethod
    def from_dict(cls, d):
        return conv.structure(d, cls)

    def json(self):
        return conv.dumps(self, indent=4, ensure_ascii=False)
