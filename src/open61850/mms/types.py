# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""MMS type descriptions (GetVariableAccessAttributes, ISO 9506-2).

::

    TypeDescription ::= CHOICE {
        array          [1]  IMPLICIT SEQUENCE { packed [0] BOOLEAN DEFAULT FALSE,
                                                numberOfElements [1] Unsigned32,
                                                elementType [2] TypeSpecification },
        structure      [2]  IMPLICIT SEQUENCE { packed [0] BOOLEAN DEFAULT FALSE,
                                                components [1] SEQUENCE OF SEQUENCE {
                                                    componentName [0] Identifier OPTIONAL,
                                                    componentType [1] TypeSpecification } },
        boolean [3] NULL,  bit-string [4] Integer32,  integer [5] Unsigned8,
        unsigned [6] Unsigned8,  floating-point [7] SEQUENCE { format-width, exponent-width },
        octet-string [9] Integer32,  visible-string [10] Integer32,
        generalized-time [11] NULL,  binary-time [12] BOOLEAN,  bcd [13] Unsigned8,
        objId [15] NULL,  mMSString [16] Integer32,  utc-time [17] NULL }

String and bit-string sizes are negative for "variable, up to |n|".

:func:`label` pairs a decoded ``Data`` value with its type to name every leaf
(``cVal.mag.f``), which is how a report member becomes readable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

from .. import ber
from ..data import ArrayData, IECData, StructureData
from .errors import MmsProtocolError

__all__ = [
    "PRIMITIVES",
    "PrimitiveType",
    "StructureType",
    "ArrayType",
    "NamedType",
    "MmsType",
    "decode_type_description",
    "encode_type_description",
    "decode_type_specification",
    "get_variable_access_attributes_response",
    "label",
    "describe",
]


PRIMITIVES = {
    3: "boolean", 4: "bit-string", 5: "integer", 6: "unsigned", 7: "float",
    9: "octet-string", 10: "visible-string", 11: "generalized-time", 12: "binary-time",
    13: "bcd", 15: "objId", 16: "mms-string", 17: "utc-time",
}


@dataclass
class PrimitiveType:
    kind: str
    size: Optional[int] = None  # bits, bytes or characters; negative = variable up to |size|


@dataclass
class StructureType:
    components: list[tuple[str, MmsType]] = field(default_factory=list)

    def component(self, name: str) -> Optional[MmsType]:
        return next((t for n, t in self.components if n == name), None)


@dataclass
class ArrayType:
    count: int
    element: MmsType


@dataclass
class NamedType:
    """A reference to a named type (typeName); IEC 61850 servers rarely use it."""

    name: str


MmsType = Union[PrimitiveType, StructureType, ArrayType, NamedType]


def decode_type_description(tlv: ber.Tlv) -> MmsType:
    number = ber.tag_number(tlv.tag)
    if number == 2:
        components: list[tuple[str, MmsType]] = []
        for part in ber.iter_tlvs(tlv.value):
            if part.tag != 0xA1:
                continue  # packed
            for comp in ber.iter_tlvs(part.value):
                name, ctype = "", None
                for item in ber.iter_tlvs(comp.value):
                    if item.tag == 0x80:
                        name = item.value.decode("ascii", errors="replace")
                    elif item.tag == 0xA1:
                        ctype = decode_type_specification(ber.decode_tlv(item.value))
                if ctype is None:
                    raise MmsProtocolError("structure component without type")
                components.append((name, ctype))
        return StructureType(components)
    if number == 1:
        fields = {t.tag: t for t in ber.iter_tlvs(tlv.value)}
        element = decode_type_specification(ber.decode_tlv(fields[0xA2].value))
        return ArrayType(ber.decode_unsigned(fields[0x81].value), element)
    if number in PRIMITIVES:
        kind = PRIMITIVES[number]
        if number == 7:
            width = [ber.decode_unsigned(t.value) for t in ber.iter_tlvs(tlv.value)] if tlv.value else []
            return PrimitiveType(kind, width[0] if width else None)
        if tlv.value and number in (4, 5, 6, 9, 10, 13, 16):
            return PrimitiveType(kind, ber.decode_integer(tlv.value))
        return PrimitiveType(kind)
    raise MmsProtocolError(f"unsupported TypeDescription tag 0x{tlv.tag:X}")


_PRIMITIVE_TAGS = {kind: number for number, kind in PRIMITIVES.items()}
_FLOAT_EXPONENT = {32: 8, 64: 11}


def encode_type_description(mms_type: MmsType) -> bytes:
    """The TypeDescription TLV of a type (what :func:`decode_type_description` reads)."""
    if isinstance(mms_type, StructureType):
        components = b"".join(
            ber.encode_tlv(0x30, ber.encode_tlv(0x80, name.encode("ascii"))
                           + ber.encode_tlv(0xA1, encode_type_description(ctype)))
            for name, ctype in mms_type.components
        )
        return ber.encode_tlv(0xA2, ber.encode_tlv(0xA1, components))
    if isinstance(mms_type, ArrayType):
        return ber.encode_tlv(0xA1, ber.encode_tlv(0x81, ber.encode_unsigned(mms_type.count))
                              + ber.encode_tlv(0xA2, encode_type_description(mms_type.element)))
    if isinstance(mms_type, NamedType):
        raise ValueError("a named type has no description of its own")
    number = _PRIMITIVE_TAGS[mms_type.kind]
    if mms_type.kind == "float":
        width = mms_type.size or 32
        body = (ber.encode_tlv(0x02, ber.encode_unsigned(width))
                + ber.encode_tlv(0x02, ber.encode_unsigned(_FLOAT_EXPONENT[width])))
        return ber.encode_tlv(ber.make_tag(number, constructed=True), body)
    if mms_type.kind == "binary-time":
        return ber.encode_tlv(ber.make_tag(number), ber.encode_boolean(True))  # with the date
    if mms_type.size is None:
        return ber.encode_tlv(ber.make_tag(number))
    return ber.encode_tlv(ber.make_tag(number), ber.encode_integer(mms_type.size))


def decode_type_specification(tlv: ber.Tlv) -> MmsType:
    if tlv.tag == 0xA0:  # typeName [0] ObjectName
        inner = ber.decode_tlv(tlv.value)
        return NamedType(inner.value.decode("ascii", errors="replace"))
    return decode_type_description(tlv)


def get_variable_access_attributes_response(content: bytes) -> MmsType:
    """The type of a GetVariableAccessAttributes-Response."""
    for tlv in ber.iter_tlvs(content):
        if tlv.tag == 0xA2:  # typeDescription [2]
            return decode_type_description(ber.decode_tlv(tlv.value))
    raise MmsProtocolError("GetVariableAccessAttributes-Response without typeDescription")


def describe(mms_type: Optional[MmsType]) -> str:
    """Short text of a type: ``integer32``, ``float32``, ``visible-string(<=255)``, ``array[3] of ...``."""
    if mms_type is None:
        return "?"
    if isinstance(mms_type, PrimitiveType):
        size = mms_type.size
        if size is None:
            return mms_type.kind
        if mms_type.kind in ("integer", "unsigned", "float"):
            return f"{mms_type.kind}{size}"
        return f"{mms_type.kind}(<={-size})" if size < 0 else f"{mms_type.kind}({size})"
    if isinstance(mms_type, StructureType):
        return f"structure of {len(mms_type.components)}"
    if isinstance(mms_type, ArrayType):
        return f"array[{mms_type.count}] of {describe(mms_type.element)}"
    return f"type {mms_type.name}"


def label(value: IECData, mms_type: Optional[MmsType], prefix: str = "") -> list[tuple[str, IECData]]:
    """Leaves of ``value`` with their dotted path, named after ``mms_type``.

    Components without a matching type fall back to their index.
    """
    if isinstance(value, StructureData):
        comps = mms_type.components if isinstance(mms_type, StructureType) else []
        out: list[tuple[str, IECData]] = []
        for i, member in enumerate(value.members):
            name, ctype = comps[i] if i < len(comps) else (str(i), None)
            out += label(member, ctype, f"{prefix}.{name}" if prefix else name)
        return out
    if isinstance(value, ArrayData):
        element = mms_type.element if isinstance(mms_type, ArrayType) else None
        out = []
        for i, item in enumerate(value.elements):
            out += label(item, element, f"{prefix}[{i}]")
        return out
    return [(prefix, value)]
