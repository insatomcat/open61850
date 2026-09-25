# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""What a client, a subscriber or a test tool needs from an SCL file (CID, SCD, ICD).

Per IED: addresses, logical devices, data sets and their members, report,
GOOSE and Sampled Values control blocks with their multicast addresses
(MAC, APPID, VLAN, MinTime/MaxTime), and the data model its
DataTypeTemplates describe, in the form :func:`open61850.mms.discover`
returns, so the two can be compared (:func:`open61850.mms.model.compare`).

::

    ieds = load_ieds("station.scd")
    ied = find_ied(ieds, "10.0.0.2")
    for block in ied.report_controls:
        print(block.domain, block.instances())
    for gcb in ied.goose_controls:
        print(gcb.gocb_ref, gcb.address)       # IED01LD0/LLN0$GO$gcb1 GseAddress(mac=..., app_id=...)
    model = ied_model(ieds_root, ied.name)    # or load_model("station.scd", "IED01")

Addresses follow IEC 61850-6: APPID in hexadecimal, VLAN-ID in
hexadecimal, MinTime and MaxTime in milliseconds.

MMS naming (IEC 61850-8-1): the domain of a logical device is the IED name
followed by the LD inst; a report control block of LN ``LLN0`` is
``LLN0$BR$<name>`` (buffered) or ``LLN0$RP$<name>``; an indexed block has
one instance per client, suffixed ``01``, ``02``... up to RptEnabled max.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

from .mms.model import LogicalDevice, LogicalNode, ServerModel
from .mms.pdu import ObjectName
from .mms.reference import Reference

if TYPE_CHECKING:
    from .goose_publisher import GooseControl

__all__ = [
    "SclError",
    "ReportControlBlock",
    "Fcda",
    "SclDataSet",
    "GseAddress",
    "GooseControlBlock",
    "SvControlBlock",
    "SclIed",
    "load_ieds",
    "find_ied",
    "load_model",
    "ied_model",
]


class SclError(ValueError):
    """The file is not usable SCL."""


@dataclass(frozen=True)
class ReportControlBlock:
    ied_name: str
    ld_inst: str
    ln: str  # MMS LN name: LLN0, or prefix + lnClass + inst
    name: str
    buffered: bool
    max_instances: int
    indexed: bool
    dat_set: Optional[str]

    domain_name: Optional[str] = None  # the LD's ldName, when set

    @property
    def domain(self) -> str:
        return self.domain_name or self.ied_name + self.ld_inst

    @property
    def base(self) -> ObjectName:
        """The block without instance number: ``LLN0$BR$CB_X``."""
        return ObjectName(f"{self.ln}${'BR' if self.buffered else 'RP'}${self.name}", self.domain)

    def instances(self) -> list[ObjectName]:
        """MMS names of every instance, in order."""
        base = self.base
        if not self.indexed:
            return [base]
        return [ObjectName(f"{base.item}{i:02d}", base.domain) for i in range(1, self.max_instances + 1)]

    @property
    def data_set_reference(self) -> Optional[str]:
        """``<domain>/<ln>$<datSet>``, as the RCB DatSet attribute reads."""
        return f"{self.domain}/{self.ln}${self.dat_set}" if self.dat_set else None


@dataclass(frozen=True)
class Fcda:
    """A data set member: a data object or attribute with its FC."""

    ld_inst: str
    prefix: str
    ln_class: str
    ln_inst: str
    do_name: str
    da_name: str
    fc: str

    @property
    def ln(self) -> str:
        return "LLN0" if self.ln_class == "LLN0" else f"{self.prefix}{self.ln_class}{self.ln_inst}"

    def reference(self, domain: str) -> Reference:
        """The member's reference in logical device ``domain`` (IED name + LD inst)."""
        path = tuple(p for p in self.do_name.split(".") + self.da_name.split(".") if p)
        return Reference(domain, self.ln, path, self.fc or None)


@dataclass(frozen=True)
class SclDataSet:
    domain: str
    ln: str
    name: str
    members: tuple[Fcda, ...]
    member_domains: tuple[str, ...]  # the domain of each member's logical device

    @property
    def object_name(self) -> ObjectName:
        return ObjectName(f"{self.ln}${self.name}", self.domain)

    def references(self) -> list[Reference]:
        return [m.reference(d) for m, d in zip(self.members, self.member_domains)]


@dataclass(frozen=True)
class GseAddress:
    """A GSE or SMV address (Communication section)."""

    mac: Optional[str]
    app_id: Optional[int]
    vlan_id: Optional[int]
    vlan_priority: Optional[int]
    min_time_ms: Optional[int] = None
    max_time_ms: Optional[int] = None


@dataclass(frozen=True)
class GooseControlBlock:
    ied_name: str
    ld_inst: str
    domain: str
    name: str
    dat_set: Optional[str]
    conf_rev: int
    go_id: Optional[str]  # the GSEControl appID attribute
    address: Optional[GseAddress]

    @property
    def gocb_ref(self) -> str:
        """What GOOSE messages carry: ``<domain>/LLN0$GO$<name>``."""
        return f"{self.domain}/LLN0$GO${self.name}"

    @property
    def data_set_reference(self) -> Optional[str]:
        return f"{self.domain}/LLN0${self.dat_set}" if self.dat_set else None

    def goose_control(self, src_mac: str) -> GooseControl:
        """The :class:`~open61850.goose_publisher.GooseControl` to publish this block."""
        from .goose_publisher import GooseControl

        a = self.address
        if a is None or a.mac is None or a.app_id is None:
            raise SclError(f"{self.gocb_ref} has no GSE address with MAC and APPID")
        timing = {}
        if a.min_time_ms:
            timing["min_time_ms"] = a.min_time_ms
        if a.max_time_ms:
            timing["max_time_ms"] = max(a.max_time_ms, a.min_time_ms or 0)
        return GooseControl(
            self.gocb_ref, self.data_set_reference or "", a.app_id, a.mac, src_mac, go_id=self.go_id,
            conf_rev=self.conf_rev, vlan_id=a.vlan_id, vlan_priority=a.vlan_priority if a.vlan_id is not None else None,
            **timing,
        )


@dataclass(frozen=True)
class SvControlBlock:
    ied_name: str
    ld_inst: str
    domain: str
    name: str
    dat_set: Optional[str]
    conf_rev: int
    sv_id: str
    smp_rate: Optional[int]
    smp_mod: str  # SmpPerPeriod (default), SmpPerSec or SecPerSmp
    nof_asdu: int
    multicast: bool
    address: Optional[GseAddress]

    @property
    def reference(self) -> ObjectName:
        return ObjectName(f"LLN0${'MS' if self.multicast else 'US'}${self.name}", self.domain)

    def samples_per_second(self, frequency_hz: float = 50.0) -> Optional[int]:
        """Where smpCnt wraps: smpRate per second, or per period times the frequency."""
        if not self.smp_rate:
            return None
        if self.smp_mod == "SmpPerSec":
            return self.smp_rate
        if self.smp_mod == "SmpPerPeriod":
            return round(self.smp_rate * frequency_hz)
        return None


@dataclass
class SclIed:
    name: str
    manufacturer: Optional[str] = None
    ied_type: Optional[str] = None
    addresses: list[str] = field(default_factory=list)  # IP of every ConnectedAP
    ld_insts: list[str] = field(default_factory=list)
    report_controls: list[ReportControlBlock] = field(default_factory=list)
    data_sets: list[SclDataSet] = field(default_factory=list)
    goose_controls: list[GooseControlBlock] = field(default_factory=list)
    sv_controls: list[SvControlBlock] = field(default_factory=list)
    ld_names: dict[str, str] = field(default_factory=dict)  # inst -> ldName when the SCL gives one

    @property
    def domains(self) -> list[str]:
        return [self.domain(inst) for inst in self.ld_insts]

    def domain(self, ld_inst: str) -> str:
        """The MMS domain of a logical device: its ldName, or the IED name followed by its inst."""
        return self.ld_names.get(ld_inst, self.name + ld_inst)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in element if _local(c.tag) == name]


def _ln_name(ln: ET.Element) -> str:
    if _local(ln.tag) == "LN0":
        return "LLN0"
    return f"{ln.get('prefix', '')}{ln.get('lnClass', '')}{ln.get('inst', '')}"


def _root(source: Union[str, Path]) -> ET.Element:
    try:
        root = ET.parse(source).getroot()
    except (ET.ParseError, OSError) as exc:
        raise SclError(f"cannot read SCL {source}: {exc}") from exc
    if _local(root.tag) != "SCL":
        raise SclError(f"{source} is not SCL (root element {_local(root.tag)})")
    return root


def _p(address: ET.Element, kind: str) -> Optional[str]:
    for p in address.iter():
        if _local(p.tag) == "P" and p.get("type") == kind and p.text:
            return p.text.strip()
    return None


def _ms(element: Optional[ET.Element]) -> Optional[int]:
    if element is None or not (element.text or "").strip():
        return None
    value = float(element.text.strip())
    if element.get("unit", "s") == "s" and element.get("multiplier", "m") == "":
        value *= 1000  # plain seconds
    return round(value)


def _gse_address(element: ET.Element) -> GseAddress:
    address = next((c for c in element if _local(c.tag) == "Address"), element)
    mac = _p(address, "MAC-Address")
    app_id = _p(address, "APPID")
    vlan = _p(address, "VLAN-ID")
    priority = _p(address, "VLAN-PRIORITY")
    return GseAddress(
        mac=mac.replace("-", ":").lower() if mac else None,
        app_id=int(app_id, 16) if app_id else None,
        vlan_id=int(vlan, 16) if vlan else None,
        vlan_priority=int(priority) if priority else None,
        min_time_ms=_ms(next((c for c in element if _local(c.tag) == "MinTime"), None)),
        max_time_ms=_ms(next((c for c in element if _local(c.tag) == "MaxTime"), None)),
    )


def load_ieds(source: Union[str, Path]) -> list[SclIed]:
    """Every IED of an SCL file: addresses, logical devices, data sets, control blocks."""
    return _ieds(_root(source))


def _ieds(root: ET.Element) -> list[SclIed]:
    addresses: dict[str, list[str]] = {}
    gse: dict[tuple[str, str, str], GseAddress] = {}  # (iedName, ldInst, cbName)
    smv: dict[tuple[str, str, str], GseAddress] = {}
    for element in root.iter():
        if _local(element.tag) != "ConnectedAP":
            continue
        ied_name = element.get("iedName", "")
        for child in element:
            kind = _local(child.tag)
            if kind == "Address":
                ip = _p(child, "IP")
                if ip:
                    addresses.setdefault(ied_name, []).append(ip)
            elif kind in ("GSE", "SMV"):
                key = (ied_name, child.get("ldInst", ""), child.get("cbName", ""))
                (gse if kind == "GSE" else smv)[key] = _gse_address(child)

    ieds: list[SclIed] = []
    for ied_el in _children(root, "IED"):
        ied = SclIed(
            name=ied_el.get("name", ""),
            manufacturer=ied_el.get("manufacturer"),
            ied_type=ied_el.get("type"),
            addresses=addresses.get(ied_el.get("name", ""), []),
        )
        for ld in ied_el.iter():
            if _local(ld.tag) != "LDevice":
                continue
            inst = ld.get("inst", "")
            ied.ld_insts.append(inst)
            if ld.get("ldName"):
                ied.ld_names[inst] = ld.get("ldName", "")
            domain = ied.domain(inst)
            for ln in ld:
                if _local(ln.tag) not in ("LN0", "LN"):
                    continue
                for ds in _children(ln, "DataSet"):
                    members = tuple(
                        Fcda(f.get("ldInst", inst), f.get("prefix", ""), f.get("lnClass", ""), f.get("lnInst", ""),
                             f.get("doName", ""), f.get("daName", ""), f.get("fc", ""))
                        for f in _children(ds, "FCDA")
                    )
                    ied.data_sets.append(SclDataSet(domain, _ln_name(ln), ds.get("name", ""), members,
                                                    tuple(ied.domain(m.ld_inst) for m in members)))
                for gc in _children(ln, "GSEControl"):
                    if gc.get("type", "GOOSE") != "GOOSE":
                        continue
                    ied.goose_controls.append(GooseControlBlock(
                        ied.name, inst, domain, gc.get("name", ""), gc.get("datSet") or None,
                        int(gc.get("confRev", "0")), gc.get("appID") or None, gse.get((ied.name, inst, gc.get("name", ""))),
                    ))
                for sc in _children(ln, "SampledValueControl"):
                    ied.sv_controls.append(SvControlBlock(
                        ied.name, inst, domain, sc.get("name", ""), sc.get("datSet") or None,
                        int(sc.get("confRev", "0")), sc.get("smvID", ""),
                        int(sc.get("smpRate")) if sc.get("smpRate") else None, sc.get("smpMod", "SmpPerPeriod"),
                        int(sc.get("nofASDU", "1")), sc.get("multicast", "true") == "true",
                        smv.get((ied.name, inst, sc.get("name", ""))),
                    ))
                for rc in _children(ln, "ReportControl"):
                    enabled = _children(rc, "RptEnabled")
                    max_instances = int(enabled[0].get("max", "1")) if enabled else 1
                    ied.report_controls.append(ReportControlBlock(
                        ied_name=ied.name,
                        ld_inst=inst,
                        ln=_ln_name(ln),
                        name=rc.get("name", ""),
                        buffered=rc.get("buffered", "false") == "true",
                        max_instances=max(1, max_instances),
                        indexed=rc.get("indexed", "true") == "true",
                        dat_set=rc.get("datSet") or None,
                        domain_name=ied.ld_names.get(inst),
                    ))
        ieds.append(ied)
    return ieds


def find_ied(ieds: list[SclIed], host: str) -> Optional[SclIed]:
    """The IED whose address is ``host``; the only IED of a CID when no address matches."""
    for ied in ieds:
        if host in ied.addresses:
            return ied
    return ieds[0] if len(ieds) == 1 else None


# --- data model from the DataTypeTemplates ------------------------------------


class _Templates:
    def __init__(self, root: ET.Element) -> None:
        self.types: dict[tuple[str, str], ET.Element] = {}
        for templates in _children(root, "DataTypeTemplates"):
            for element in templates:
                self.types[(_local(element.tag), element.get("id", ""))] = element

    def get(self, kind: str, type_id: Optional[str]) -> Optional[ET.Element]:
        return self.types.get((kind, type_id or ""))

    def ln_items(self, ln_type: Optional[str]) -> list[str]:
        """The MMS items below a logical node of this LNodeType: ``FC``, ``FC$DO``, ``FC$DO$DA``..."""
        items: dict[str, None] = {}
        node = self.get("LNodeType", ln_type)
        if node is None:
            return []
        for do in _children(node, "DO"):
            self._do(self.get("DOType", do.get("type")), [do.get("name", "")], items, set())
        return list(items)

    def _do(self, do_type: Optional[ET.Element], path: list[str], items: dict[str, None], seen: set[str]) -> None:
        if do_type is None or do_type.get("id", "") in seen:
            return
        seen = seen | {do_type.get("id", "")}
        for child in do_type:
            kind = _local(child.tag)
            if kind == "SDO":
                self._do(self.get("DOType", child.get("type")), path + [child.get("name", "")], items, seen)
            elif kind == "DA" and child.get("fc"):
                self._da(child, child.get("fc", ""), path + [child.get("name", "")], items, seen)

    def _da(self, da: ET.Element, fc: str, path: list[str], items: dict[str, None], seen: set[str]) -> None:
        items.setdefault(fc, None)
        for depth in range(1, len(path) + 1):
            items.setdefault("$".join([fc] + path[:depth]), None)
        if da.get("bType") != "Struct" or da.get("count"):
            return  # a leaf, or an array (its elements have no names of their own)
        da_type = self.get("DAType", da.get("type"))
        if da_type is None or da_type.get("id", "") in seen:
            return
        for bda in _children(da_type, "BDA"):
            self._da(bda, fc, path + [bda.get("name", "")], items, seen | {da_type.get("id", "")})


def _ordered(items: list[str]) -> list[str]:
    """FC levels first, then each level after its parent (as a server lists them)."""
    return sorted(items, key=lambda item: item.split("$"))


def ied_model(root: ET.Element, ied_name: Optional[str] = None) -> ServerModel:
    """The data model an IED's SCL describes (the only IED when ``ied_name`` is None)."""
    ieds = _children(root, "IED")
    ied_el = next((i for i in ieds if ied_name is None or i.get("name") == ied_name), None)
    if ied_el is None or (ied_name is None and len(ieds) != 1):
        raise SclError(f"no IED {ied_name!r} in the SCL" if ied_name else "several IEDs: name one")
    templates = _Templates(root)
    name = ied_el.get("name", "")
    model = ServerModel()
    for ld in ied_el.iter():
        if _local(ld.tag) != "LDevice":
            continue
        domain = ld.get("ldName") or name + ld.get("inst", "")
        device = model.logical_devices[domain] = LogicalDevice(domain)
        for ln in ld:
            if _local(ln.tag) not in ("LN0", "LN"):
                continue
            node = LogicalNode(domain, _ln_name(ln))
            node.items = _ordered(templates.ln_items(ln.get("lnType")))
            for rc in _children(ln, "ReportControl"):
                fc = "BR" if rc.get("buffered", "false") == "true" else "RP"
                enabled = _children(rc, "RptEnabled")
                count = max(1, int(enabled[0].get("max", "1"))) if enabled else 1
                names = [rc.get("name", "")] if rc.get("indexed", "true") != "true" else [
                    f"{rc.get('name', '')}{i:02d}" for i in range(1, count + 1)]
                node.items += [fc] + [f"{fc}${n}" for n in names]
            for kind, fc in (("GSEControl", "GO"), ("LogControl", "LG")):
                node.items += [f"{fc}${c.get('name', '')}" for c in _children(ln, kind)]
            for sc in _children(ln, "SampledValueControl"):
                node.items.append(f"{'MS' if sc.get('multicast', 'true') == 'true' else 'US'}${sc.get('name', '')}")
            node.items = list(dict.fromkeys(i for item in node.items for i in _with_fc_level(item)))
            node.data_sets = [ds.get("name", "") for ds in _children(ln, "DataSet")]
            device.logical_nodes[node.name] = node
    return model


def _with_fc_level(item: str) -> list[str]:
    fc, sep, _rest = item.partition("$")
    return [fc, item] if sep else [item]


def load_model(source: Union[str, Path], ied_name: Optional[str] = None) -> ServerModel:
    """The data model of an IED of an SCL file (the only IED when ``ied_name`` is None)."""
    return ied_model(_root(source), ied_name)
