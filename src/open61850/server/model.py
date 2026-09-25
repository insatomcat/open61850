# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The data an IEC 61850 server holds: typed values, from an SCL file.

An :class:`IedModel` keeps, for each logical device (MMS domain) and logical
node, a tree of :class:`Node`: the functional constraints, then data
objects, sub data objects and attributes, each with its MMS type. Leaves
hold their value (a :mod:`open61850.data` value). Control blocks are nodes
too, with the attributes IEC 61850-8-1 gives them, so clients read and
write them like any variable.

:meth:`IedModel.from_scl` builds the model from a CID/ICD/SCD: the
DataTypeTemplates give the types (bType to MMS type as IEC 61850-8-1 maps
them), ``Val`` elements and the IED's DOI/DAI the initial values.
:meth:`IedModel.set` changes a value from the application; the change
listeners (reports) are told.
"""

from __future__ import annotations

import threading
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from ..data import (
    ArrayData,
    BitStringData,
    BoolData,
    FloatData,
    IECData,
    IntData,
    MmsStringData,
    OctetStringData,
    RawData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
)
from ..mms.pdu import ObjectName
from ..mms.reference import Name, Reference, to_object_name
from ..mms.types import ArrayType, MmsType, PrimitiveType, StructureType
from ..scl import SclError, _children, _ln_name, _local, _root

__all__ = [
    "ACCESS_OBJECT_ACCESS_DENIED",
    "ACCESS_OBJECT_NON_EXISTENT",
    "ACCESS_TYPE_INCONSISTENT",
    "ACCESS_OBJECT_VALUE_INVALID",
    "WRITABLE_FCS",
    "Node",
    "IedModel",
    "to_data",
]

# DataAccessError codes (ISO 9506-2)
ACCESS_OBJECT_INVALIDATED = 0
ACCESS_TEMPORARILY_UNAVAILABLE = 2
ACCESS_OBJECT_ACCESS_DENIED = 3
ACCESS_TYPE_INCONSISTENT = 7
ACCESS_OBJECT_ACCESS_UNSUPPORTED = 9
ACCESS_OBJECT_NON_EXISTENT = 10
ACCESS_OBJECT_VALUE_INVALID = 11

# What a client may write (the CO FC goes through the control handling).
WRITABLE_FCS = frozenset({"CF", "DC", "SP", "SV", "SE", "BL"})

_BTYPES: dict[str, tuple[str, Optional[int]]] = {
    "BOOLEAN": ("boolean", None),
    "INT8": ("integer", 8), "INT16": ("integer", 16), "INT24": ("integer", 32), "INT32": ("integer", 32),
    "INT64": ("integer", 64), "INT128": ("integer", 64),
    "INT8U": ("unsigned", 8), "INT16U": ("unsigned", 16), "INT24U": ("unsigned", 32), "INT32U": ("unsigned", 32),
    "FLOAT32": ("float", 32), "FLOAT64": ("float", 64),
    "Enum": ("integer", 8),
    "Dbpos": ("bit-string", 2), "Tcmd": ("bit-string", 2), "Check": ("bit-string", -2),
    "Quality": ("bit-string", -13), "Timestamp": ("utc-time", None), "EntryTime": ("binary-time", None),
    "VisString32": ("visible-string", -32), "VisString64": ("visible-string", -64),
    "VisString65": ("visible-string", -65), "VisString129": ("visible-string", -129),
    "VisString255": ("visible-string", -255), "ObjRef": ("visible-string", -129), "Currency": ("visible-string", -3),
    "Octet64": ("octet-string", -64), "OctetString": ("octet-string", -64), "EntryID": ("octet-string", 8),
    "Unicode255": ("mms-string", -255),
    "TrgOps": ("bit-string", 6), "OptFlds": ("bit-string", 10), "SvOptFlds": ("bit-string", 5),
    "PhyComAddr": ("octet-string", 6),
}
_DBPOS = {"intermediate-state": 0, "off": 1, "on": 2, "bad-state": 3}


def _prim(kind: str, size: Optional[int] = None) -> PrimitiveType:
    return PrimitiveType(kind, size)


def default_value(mms_type: MmsType) -> IECData:
    """The value of a fresh attribute: zeros, empty strings, the epoch."""
    if isinstance(mms_type, StructureType):
        return StructureData([default_value(t) for _n, t in mms_type.components])
    if isinstance(mms_type, ArrayType):
        return ArrayData([default_value(mms_type.element) for _ in range(mms_type.count)])
    assert isinstance(mms_type, PrimitiveType)
    kind, size = mms_type.kind, mms_type.size
    if kind == "boolean":
        return BoolData(False)
    if kind == "integer":
        return IntData(0)
    if kind == "unsigned":
        return UIntData(0)
    if kind == "float":
        return FloatData(0.0, double=size == 64)
    if kind == "bit-string":
        bits = abs(size or 0)
        length = (bits + 7) // 8
        return BitStringData(bytes(length), length * 8 - bits)
    if kind == "utc-time":
        return TimestampData(datetime(1970, 1, 1, tzinfo=timezone.utc))
    if kind == "binary-time":
        return RawData(0x8C, bytes(6))  # TimeOfDay with date, kept as its octets
    if kind == "octet-string":
        return OctetStringData(bytes(size) if size and size > 0 else b"")
    if kind == "mms-string":
        return MmsStringData("")
    return VisibleStringData("")


_KIND_CLASSES: dict[str, tuple[type, ...]] = {
    "boolean": (BoolData,),
    "integer": (IntData,),
    "unsigned": (UIntData, IntData),
    "float": (FloatData,),
    "bit-string": (BitStringData,),
    "utc-time": (TimestampData,),
    "binary-time": (RawData, TimestampData),
    "octet-string": (OctetStringData,),
    "visible-string": (VisibleStringData,),
    "mms-string": (MmsStringData, VisibleStringData),
}


def to_data(mms_type: MmsType, value: Any) -> IECData:
    """A Python value (bool, int, float, str, bytes, datetime) as the Data of ``mms_type``."""
    if isinstance(value, (BoolData, IntData, UIntData, FloatData, BitStringData, OctetStringData,
                          VisibleStringData, MmsStringData, TimestampData, StructureData, ArrayData, RawData)):
        return value
    if not isinstance(mms_type, PrimitiveType):
        raise TypeError(f"give a StructureData or ArrayData for a {type(mms_type).__name__}")
    kind = mms_type.kind
    if kind == "boolean":
        return BoolData(bool(value))
    if kind == "integer":
        return IntData(int(value))
    if kind == "unsigned":
        return UIntData(int(value))
    if kind == "float":
        return FloatData(float(value), double=mms_type.size == 64)
    if kind in ("utc-time", "binary-time") and isinstance(value, datetime):
        return TimestampData(value)
    if kind == "octet-string":
        return OctetStringData(bytes(value))
    if kind == "mms-string":
        return MmsStringData(str(value))
    if kind == "visible-string":
        return VisibleStringData(str(value))
    if kind == "bit-string" and isinstance(value, int):
        bits = abs(mms_type.size or 0)
        length = (bits + 7) // 8
        unused = length * 8 - bits
        return BitStringData((value << unused).to_bytes(length, "big"), unused)
    raise TypeError(f"cannot make a {kind} of {value!r}")


def _fits(mms_type: MmsType, value: IECData) -> bool:
    if isinstance(mms_type, StructureType):
        return (isinstance(value, StructureData) and len(value.members) == len(mms_type.components)
                and all(_fits(t, v) for (_n, t), v in zip(mms_type.components, value.members)))
    if isinstance(mms_type, ArrayType):
        return (isinstance(value, ArrayData) and len(value.elements) == mms_type.count
                and all(_fits(mms_type.element, v) for v in value.elements))
    assert isinstance(mms_type, PrimitiveType)
    if not isinstance(value, _KIND_CLASSES.get(mms_type.kind, ())):
        return False
    size = mms_type.size
    if mms_type.kind == "bit-string" and size is not None and isinstance(value, BitStringData):
        bits = len(value.value) * 8 - value.unused_bits
        return bits == size if size > 0 else bits <= -size
    if isinstance(value, (VisibleStringData, MmsStringData, OctetStringData)) and size is not None:
        length = len(value.value)
        return length == size if size > 0 else length <= -size
    return True


class Node:
    """A variable of the model: a structure (children), an array or a leaf (value)."""

    __slots__ = ("children", "enum_type", "fc", "mms_type", "name", "parent", "triggers", "value")

    def __init__(self, name: str, mms_type: MmsType, parent: Optional[Node] = None, fc: Optional[str] = None) -> None:
        self.name = name
        self.mms_type = mms_type
        self.parent = parent
        self.fc: Optional[str] = fc if fc is not None else (parent.fc if parent is not None else None)
        self.children: dict[str, Node] = {}
        self.value: Optional[IECData] = None
        self.triggers: frozenset[str] = frozenset()  # dchg, qchg, dupd of the attribute
        self.enum_type: Optional[str] = None  # the SCL EnumType of an Enum attribute

    @property
    def item(self) -> str:
        """The MMS name within the domain: ``LN$FC$DO$DA``."""
        parts = []
        node: Optional[Node] = self
        while node is not None:
            parts.append(node.name)
            node = node.parent
        return "$".join(reversed(parts))

    def child(self, name: str) -> Optional[Node]:
        return self.children.get(name)

    def data(self) -> IECData:
        if self.children:
            members = [c.data() for c in self.children.values()]
            return ArrayData(members) if isinstance(self.mms_type, ArrayType) else StructureData(members)
        assert self.value is not None
        return self.value

    def leaves(self) -> Iterator[Node]:
        if not self.children:
            yield self
        for child in self.children.values():
            yield from child.leaves()

    def assign(self, value: IECData) -> list[Node]:
        """Set the value (the whole subtree for a structure); the leaves that changed."""
        if self.children:
            members = value.elements if isinstance(value, ArrayData) else value.members  # type: ignore[union-attr]
            changed: list[Node] = []
            for child, member in zip(self.children.values(), members):
                changed += child.assign(member)
            return changed
        if self.value == value:
            return []
        self.value = value
        return [self]

    def __repr__(self) -> str:
        return f"Node({self.item})"


def _build(name: str, mms_type: MmsType, parent: Optional[Node], fc: Optional[str] = None) -> Node:
    node = Node(name, mms_type, parent, fc)
    if isinstance(mms_type, StructureType):
        for child_name, child_type in mms_type.components:
            node.children[child_name] = _build(child_name, child_type, node)
    elif isinstance(mms_type, ArrayType):
        for i in range(mms_type.count):
            node.children[str(i)] = _build(str(i), mms_type.element, node)
    else:
        node.value = default_value(mms_type)
    return node


ChangeListener = Callable[[list[Node]], None]


class IedModel:
    """The logical devices of one IED, their values, data sets and control blocks."""

    def __init__(self, ied_name: str = "") -> None:
        self.ied_name = ied_name
        self.logical_devices: dict[str, dict[str, Node]] = {}  # domain -> LN name -> LN node
        self.data_sets: dict[ObjectName, list[ObjectName]] = {}
        self.lock = threading.RLock()
        self._listeners: list[ChangeListener] = []

    # --- navigation ------------------------------------------------------------

    def node(self, name: Name) -> Optional[Node]:
        """The node of an MMS variable (``LN``, ``LN$FC``, ``LN$FC$DO$DA``...), or None."""
        obj = to_object_name(name)
        lns = self.logical_devices.get(obj.domain or "")
        if lns is None:
            return None
        parts = obj.item.split("$")
        node = lns.get(parts[0])
        for part in parts[1:]:
            if node is None:
                return None
            node = node.child(part)
        return node

    def names(self, domain: str) -> list[str]:
        """Every variable of a domain, at every level, sorted (the GetNameList order)."""
        out: list[str] = []

        def walk(node: Node, prefix: str) -> None:
            out.append(prefix)
            if isinstance(node.mms_type, ArrayType):
                return  # array elements have no names
            for child in node.children.values():
                walk(child, f"{prefix}${child.name}")

        for ln_name, ln in self.logical_devices.get(domain, {}).items():
            walk(ln, ln_name)
        return sorted(out)

    # --- values ----------------------------------------------------------------

    def read(self, name: Name) -> Union[IECData, int]:
        """The value of a variable, or a DataAccessError code."""
        with self.lock:
            node = self.node(name)
            return ACCESS_OBJECT_NON_EXISTENT if node is None else node.data()

    def get(self, name: Name) -> IECData:
        """The value of a variable (``LD/LN.DO.DA[FC]`` or an MMS name); KeyError if unknown."""
        with self.lock:
            node = self.node(name)
            if node is None:
                raise KeyError(f"no {name} in the model")
            return node.data()

    def set(self, name: Name, value: Any, *, notify: bool = True) -> None:
        """Change a value from the application (any FC); the listeners are told."""
        with self.lock:
            node = self.node(name)
            if node is None:
                raise KeyError(f"no {name} in the model")
            data = to_data(node.mms_type, value)
            if not _fits(node.mms_type, data):
                raise TypeError(f"{data!r} does not fit {name} ({node.mms_type})")
            changed = node.assign(data)
        if notify and changed:
            self._notify(changed)

    def write(self, name: ObjectName, value: IECData) -> Optional[int]:
        """A client's write: None when done, else a DataAccessError code."""
        with self.lock:
            node = self.node(name)
            if node is None:
                return ACCESS_OBJECT_NON_EXISTENT
            if node.fc not in WRITABLE_FCS:
                return ACCESS_OBJECT_ACCESS_DENIED
            if not _fits(node.mms_type, value):
                return ACCESS_TYPE_INCONSISTENT
            changed = node.assign(value)
        if changed:
            self._notify(changed)
        return None

    def add_listener(self, listener: ChangeListener) -> None:
        self._listeners.append(listener)

    def remove_listener(self, listener: ChangeListener) -> None:
        self._listeners.remove(listener)

    def _notify(self, changed: list[Node]) -> None:
        for listener in list(self._listeners):
            listener(changed)

    # --- building ----------------------------------------------------------------

    @classmethod
    def from_scl(cls, source: Union[str, Path], ied_name: Optional[str] = None, *,
                 brcb_resv_tms: Optional[bool] = None) -> IedModel:
        """The model of an IED of an SCL file (the only one when ``ied_name`` is None).

        Edition 2 files (SCL version 2007 or later) give BRCBs a ResvTms and
        spell TimeOfEntry; edition 1 files spell TimeofEntry and have no
        ResvTms unless ``Services/ReportSettings resvTms="true"``;
        ``brcb_resv_tms`` forces the choice (libiec61850 always has one).
        """
        return _SclBuilder(_root(source)).build(ied_name, brcb_resv_tms)


# --- SCL ---------------------------------------------------------------------


def _ms_type_for(bda: ET.Element, templates: _SclBuilder, seen: frozenset[str]) -> MmsType:
    btype = bda.get("bType", "")
    if btype == "Struct":
        da_type = templates.types.get(("DAType", bda.get("type", "")))
        if da_type is None or da_type.get("id", "") in seen:
            raise SclError(f"unknown or recursive DAType {bda.get('type')!r}")
        inner = seen | {da_type.get("id", "")}
        element: MmsType = StructureType([(b.get("name", ""), _ms_type_for(b, templates, inner))
                                          for b in _children(da_type, "BDA")])
    elif btype in _BTYPES:
        kind, size = _BTYPES[btype]
        element = _prim(kind, size)
    else:
        raise SclError(f"unsupported bType {btype!r}")
    count = bda.get("count")
    return ArrayType(int(count), element) if count and count.isdigit() and int(count) > 0 else element


_Layout = list[tuple[str, MmsType]]
_BRCB: _Layout = [("RptID", _prim("visible-string", -129)), ("RptEna", _prim("boolean")),
         ("DatSet", _prim("visible-string", -129)),
         ("ConfRev", _prim("unsigned", 32)), ("OptFlds", _prim("bit-string", -10)), ("BufTm", _prim("unsigned", 32)),
         ("SqNum", _prim("unsigned", 16)), ("TrgOps", _prim("bit-string", -6)), ("IntgPd", _prim("unsigned", 32)),
         ("GI", _prim("boolean")), ("PurgeBuf", _prim("boolean")), ("EntryID", _prim("octet-string", 8)),
         ("TimeOfEntry", _prim("binary-time")), ("ResvTms", _prim("integer", 16)), ("Owner", _prim("octet-string", -64))]
_URCB: _Layout = [("RptID", _prim("visible-string", -129)), ("RptEna", _prim("boolean")), ("Resv", _prim("boolean")),
         ("DatSet", _prim("visible-string", -129)), ("ConfRev", _prim("unsigned", 32)), ("OptFlds", _prim("bit-string", -10)),
         ("BufTm", _prim("unsigned", 32)), ("SqNum", _prim("unsigned", 8)), ("TrgOps", _prim("bit-string", -6)),
         ("IntgPd", _prim("unsigned", 32)), ("GI", _prim("boolean")), ("Owner", _prim("octet-string", -64))]
_DST_ADDRESS = StructureType([("Addr", _prim("octet-string", 6)), ("PRIORITY", _prim("unsigned", 8)),
                              ("VID", _prim("unsigned", 16)), ("APPID", _prim("unsigned", 16))])
_GOCB: _Layout = [("GoEna", _prim("boolean")), ("GoID", _prim("visible-string", -129)), ("DatSet", _prim("visible-string", -129)),
         ("ConfRev", _prim("unsigned", 32)), ("NdsCom", _prim("boolean")), ("DstAddress", _DST_ADDRESS),
         ("MinTime", _prim("unsigned", 32)), ("MaxTime", _prim("unsigned", 32)), ("FixedOffs", _prim("boolean"))]
_MSVCB: _Layout = [("SvEna", _prim("boolean")), ("MsvID", _prim("visible-string", -129)),
          ("DatSet", _prim("visible-string", -129)),
          ("ConfRev", _prim("unsigned", 32)), ("SmpRate", _prim("unsigned", 16)), ("OptFlds", _prim("bit-string", 5)),
          ("SmpMod", _prim("integer", 8)), ("DstAddress", _DST_ADDRESS)]
# The order of the functional constraints in a logical node, as libiec61850 builds it
# (IEC 61850-8-1 leaves it open); control blocks sit among them.
FC_ORDER = ["MX", "ST", "CO", "CF", "DC", "SP", "SG", "RP", "LG", "BR", "GO", "SV", "SE", "MS", "US", "EX", "SR", "OR", "BL"]
_OPT_FIELDS = ["seqNum", "timeStamp", "reasonCode", "dataSet", "dataRef", "bufOvfl", "entryID", "configRef", "segmentation"]
_TRG_OPS = ["dchg", "qchg", "dupd", "period", "gi"]


# SCL defaults (IEC 61850-6 Ed2 schema, as libiec61850 reads it): gi and bufOvfl are true when absent.
_FLAG_DEFAULTS = {"gi": "true", "bufOvfl": "true"}


def _flags(element: Optional[ET.Element], names: list[str], size: int, first_reserved: bool) -> BitStringData:
    bits = [False] * size
    offset = 1 if first_reserved else 0
    for i, name in enumerate(names):
        default = _FLAG_DEFAULTS.get(name, "false") if element is not None else "false"
        if element is not None and element.get(name, default) == "true" and i + offset < size:
            bits[i + offset] = True
    raw = bytearray((size + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            raw[i // 8] |= 0x80 >> (i % 8)
    return BitStringData(bytes(raw), len(raw) * 8 - size)


class _SclBuilder:
    def __init__(self, root: ET.Element) -> None:
        self.root = root
        self.owner = False  # RCBs carry Owner (Services/ReportSettings owner="true", edition 2)
        self.resv_tms = True  # BRCBs carry ResvTms (edition 2)
        self.edition2 = True  # edition 1 spells TimeofEntry
        self.types: dict[tuple[str, str], ET.Element] = {}
        for templates in _children(root, "DataTypeTemplates"):
            for element in templates:
                self.types[(_local(element.tag), element.get("id", ""))] = element
        self.enums: dict[str, dict[str, int]] = {}
        for (kind, type_id), element in self.types.items():
            if kind == "EnumType":
                self.enums[type_id] = {(v.text or "").strip(): int(v.get("ord", "0")) for v in _children(element, "EnumVal")}

    # values

    def _parse(self, node: Node, text: str, enum_type: Optional[str]) -> Optional[IECData]:
        mms_type = node.mms_type
        if not isinstance(mms_type, PrimitiveType):
            return None
        kind, text = mms_type.kind, text.strip()
        try:
            if kind == "boolean":
                return BoolData(text.lower() in ("true", "1"))
            if kind == "integer" and enum_type is not None and text in self.enums.get(enum_type, {}):
                return IntData(self.enums[enum_type][text])
            if kind in ("integer", "unsigned"):
                return to_data(mms_type, int(text))
            if kind == "float":
                return to_data(mms_type, float(text))
            if kind == "bit-string" and text in _DBPOS:
                return to_data(mms_type, _DBPOS[text])
            if kind in ("visible-string", "mms-string"):
                return to_data(mms_type, text)
        except ValueError:
            return None
        return None

    def _set_val(self, node: Node, element: ET.Element) -> None:
        vals = _children(element, "Val")
        if vals and node.value is not None:
            enum_type = element.get("type") if element.get("bType") == "Enum" else node.enum_type
            value = self._parse(node, vals[0].text or "", enum_type)
            if value is not None and _fits(node.mms_type, value):
                node.value = value

    # types

    def _do_components(self, do_type_id: str, fc: str, seen: frozenset[str]) -> list[tuple[str, MmsType, ET.Element]]:
        """The components of a data object in one FC: its attributes and sub data objects."""
        do_type = self.types.get(("DOType", do_type_id))
        if do_type is None or do_type_id in seen:
            return []
        out: list[tuple[str, MmsType, ET.Element]] = []
        for child in do_type:
            kind = _local(child.tag)
            if kind == "DA" and child.get("fc") == fc:
                out.append((child.get("name", ""), _ms_type_for(child, self, frozenset()), child))
            elif kind == "SDO":
                inner = self._do_components(child.get("type", ""), fc, seen | {do_type_id})
                if inner:
                    out.append((child.get("name", ""), StructureType([(n, t) for n, t, _e in inner]), child))
        return out

    def _do_fcs(self, do_type_id: str, seen: frozenset[str] = frozenset()) -> list[str]:
        do_type = self.types.get(("DOType", do_type_id))
        if do_type is None or do_type_id in seen:
            return []
        fcs: list[str] = []
        for child in do_type:
            if _local(child.tag) == "DA" and child.get("fc") and child.get("fc") not in fcs:
                fcs.append(child.get("fc", ""))
            elif _local(child.tag) == "SDO":
                fcs += [fc for fc in self._do_fcs(child.get("type", ""), seen | {do_type_id}) if fc not in fcs]
        return fcs

    def _defaults(self, node: Node, do_type_id: str, seen: frozenset[str] = frozenset()) -> None:
        """Val elements of the DOType (and its SDO and DA types) under ``node`` (a DO in one FC)."""
        do_type = self.types.get(("DOType", do_type_id))
        if do_type is None or do_type_id in seen:
            return
        for child in do_type:
            target = node.child(child.get("name", ""))
            if target is None:
                continue
            kind = _local(child.tag)
            if kind == "SDO":
                self._defaults(target, child.get("type", ""), seen | {do_type_id})
            elif kind == "DA":
                if child.get("bType") == "Enum":
                    target.enum_type = child.get("type")
                self._set_val(target, child)
                if child.get("bType") == "Struct":
                    self._bda_defaults(target, child.get("type", ""))
                target_triggers = frozenset(t for t in ("dchg", "qchg", "dupd") if child.get(t) == "true")
                for leaf in target.leaves():
                    leaf.triggers = target_triggers

    def _bda_defaults(self, node: Node, da_type_id: str) -> None:
        da_type = self.types.get(("DAType", da_type_id))
        if da_type is None:
            return
        for bda in _children(da_type, "BDA"):
            target = node.child(bda.get("name", ""))
            if target is not None:
                if bda.get("bType") == "Enum":
                    target.enum_type = bda.get("type")
                self._set_val(target, bda)
                if bda.get("bType") == "Struct":
                    self._bda_defaults(target, bda.get("type", ""))

    def _ln(self, ln: ET.Element, domain: str) -> Node:
        name = _ln_name(ln)
        node_type = self.types.get(("LNodeType", ln.get("lnType", "")))
        fc_components: dict[str, list[tuple[str, MmsType]]] = {}
        dos = _children(node_type, "DO") if node_type is not None else []
        for do in dos:
            for fc in self._do_fcs(do.get("type", "")):
                components = self._do_components(do.get("type", ""), fc, frozenset())
                if components:
                    fc_components.setdefault(fc, []).append(
                        (do.get("name", ""), StructureType([(n, t) for n, t, _e in components])))
        blocks = self._control_blocks(ln, domain, name)
        for fc, items in blocks.items():
            fc_components.setdefault(fc, []).extend((n, StructureType(c)) for n, c, _v in items)
        order = {fc: i for i, fc in enumerate(FC_ORDER)}
        ln_type = StructureType([(fc, StructureType(comps))
                                 for fc, comps in sorted(fc_components.items(), key=lambda kv: (order.get(kv[0], 99), kv[0]))])
        ln_node = _build(name, ln_type, None)
        for fc_node in ln_node.children.values():
            fc_node.fc = fc_node.name
            for sub in _walk(fc_node):
                sub.fc = fc_node.name
        for do in dos:
            for fc_node in ln_node.children.values():
                target = fc_node.child(do.get("name", ""))
                if target is not None and fc_node.name not in blocks:
                    self._defaults(target, do.get("type", ""))
        for fc, items in blocks.items():
            for block_name, _components, values in items:
                block = ln_node.children[fc].children[block_name]
                for attribute, value in values.items():
                    block.children[attribute].assign(value)
        self._instances(ln, ln_node)
        return ln_node

    def _instances(self, element: ET.Element, node: Node) -> None:
        """DOI / SDI / DAI values of the IED section."""
        for child in element:
            kind = _local(child.tag)
            if kind not in ("DOI", "SDI", "DAI"):
                continue
            name = child.get("name", "")
            if node.fc is None and node.parent is None:  # the LN: the DO lives in several FCs
                targets = [fc.child(name) for fc in node.children.values()]
            else:
                targets = [node.child(name)]
            for target in targets:
                if target is None:
                    continue
                if kind == "DAI":
                    self._set_val(target, child)
                else:
                    self._instances(child, target)

    def _control_blocks(self, ln: ET.Element, domain: str, ln_name: str
                        ) -> dict[str, list[tuple[str, list[tuple[str, MmsType]], dict[str, IECData]]]]:
        out: dict[str, list[tuple[str, list[tuple[str, MmsType]], dict[str, IECData]]]] = {}
        for rc in _children(ln, "ReportControl"):
            buffered = rc.get("buffered", "false") == "true"
            fc = "BR" if buffered else "RP"
            enabled = _children(rc, "RptEnabled")
            count = max(1, int(enabled[0].get("max", "1"))) if enabled else 1
            indexed = rc.get("indexed", "true") == "true"
            names = [f"{rc.get('name', '')}{i:02d}" for i in range(1, count + 1)] if indexed else [rc.get("name", "")]
            opt = _children(rc, "OptFields")
            trg = _children(rc, "TrgOps")
            for block_name in names:
                values: dict[str, IECData] = {
                    "RptID": VisibleStringData(rc.get("rptID") or f"{domain}/{ln_name}${fc}${block_name}"),
                    "DatSet": VisibleStringData(f"{domain}/{ln_name}${rc.get('datSet')}" if rc.get("datSet") else ""),
                    "ConfRev": UIntData(int(rc.get("confRev", "0"))),
                    "OptFlds": _flags(opt[0] if opt else None, _OPT_FIELDS, 10, True),
                    "BufTm": UIntData(int(rc.get("bufTime", "0"))),
                    "TrgOps": _flags(trg[0] if trg else None, _TRG_OPS, 6, True),
                    "IntgPd": UIntData(int(rc.get("intgPd", "0"))),
                }
                layout = [("TimeofEntry" if n == "TimeOfEntry" and not self.edition2 else n, t)
                          for n, t in (_BRCB if buffered else _URCB)
                          if (n != "Owner" or self.owner) and (n != "ResvTms" or self.resv_tms)]
                out.setdefault(fc, []).append((block_name, layout, values))
        for gc in _children(ln, "GSEControl"):
            values = {"GoID": VisibleStringData(gc.get("appID", "")),
                      "DatSet": VisibleStringData(f"{domain}/{ln_name}${gc.get('datSet')}" if gc.get("datSet") else ""),
                      "ConfRev": UIntData(int(gc.get("confRev", "0")))}
            out.setdefault("GO", []).append((gc.get("name", ""), _GOCB, values))
        for sc in _children(ln, "SampledValueControl"):
            values = {"MsvID": VisibleStringData(sc.get("smvID", "")),
                      "DatSet": VisibleStringData(f"{domain}/{ln_name}${sc.get('datSet')}" if sc.get("datSet") else ""),
                      "ConfRev": UIntData(int(sc.get("confRev", "0"))),
                      "SmpRate": UIntData(int(sc.get("smpRate", "0")))}
            fc = "MS" if sc.get("multicast", "true") == "true" else "US"
            out.setdefault(fc, []).append((sc.get("name", ""), _MSVCB, values))
        return out

    def build(self, ied_name: Optional[str], brcb_resv_tms: Optional[bool] = None) -> IedModel:
        ieds = _children(self.root, "IED")
        ied = next((i for i in ieds if ied_name is None or i.get("name") == ied_name), None)
        if ied is None or (ied_name is None and len(ieds) != 1):
            raise SclError(f"no IED {ied_name!r} in the SCL" if ied_name else "several IEDs: name one")
        name = ied.get("name", "")
        edition2 = self.edition2 = self.root.get("version", "") >= "2007"
        settings = [e for e in ied.iter() if _local(e.tag) == "ReportSettings"]
        self.owner = edition2 and bool(settings) and settings[0].get("owner", "false") == "true"
        self.resv_tms = edition2 or (bool(settings) and settings[0].get("resvTms", "false") == "true")
        if brcb_resv_tms is not None:
            self.resv_tms = brcb_resv_tms
        model = IedModel(name)
        domains: dict[str, str] = {}
        for ld in ied.iter():
            if _local(ld.tag) == "LDevice":
                domains[ld.get("inst", "")] = ld.get("ldName") or name + ld.get("inst", "")
        for ld in ied.iter():
            if _local(ld.tag) != "LDevice":
                continue
            domain = domains[ld.get("inst", "")]
            lns = model.logical_devices[domain] = {}
            for ln in ld:
                if _local(ln.tag) not in ("LN0", "LN"):
                    continue
                node = self._ln(ln, domain)
                lns[node.name] = node
                for ds in _children(ln, "DataSet"):
                    members = []
                    for f in _children(ds, "FCDA"):
                        member_ln = "LLN0" if f.get("lnClass") == "LLN0" else \
                            f"{f.get('prefix', '')}{f.get('lnClass', '')}{f.get('lnInst', '')}"
                        path = [p for p in (f.get("doName", "") + "." + f.get("daName", "")).split(".") if p]
                        members.append(ObjectName("$".join([member_ln, f.get("fc", "")] + path),
                                                  domains.get(f.get("ldInst", ""), domain)))
                    model.data_sets[ObjectName(f"{node.name}${ds.get('name', '')}", domain)] = members
        return model


def _walk(node: Node) -> Iterator[Node]:
    for child in node.children.values():
        yield child
        yield from _walk(child)


def reference_of(node: Node, domain: str) -> Reference:
    return Reference.from_object_name(ObjectName(node.item, domain))
