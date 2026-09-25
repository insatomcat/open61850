# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""What an MMS client needs from an SCL file (CID, SCD, ICD): IEDs, addresses, report control blocks.

::

    ieds = load_ieds("station.cid")
    ied = find_ied(ieds, "10.0.0.2")
    for block in ied.report_controls:
        print(block.domain, block.instances())

MMS naming (IEC 61850-8-1): the domain of a logical device is the IED name
followed by the LD inst; a report control block of LN ``LLN0`` is
``LLN0$BR$<name>`` (buffered) or ``LLN0$RP$<name>``; an indexed block has
one instance per client, suffixed ``01``, ``02``... up to RptEnabled max.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from .mms.pdu import ObjectName


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

    @property
    def domain(self) -> str:
        return self.ied_name + self.ld_inst

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


@dataclass
class SclIed:
    name: str
    manufacturer: Optional[str] = None
    ied_type: Optional[str] = None
    addresses: list[str] = field(default_factory=list)  # IP of every ConnectedAP
    ld_insts: list[str] = field(default_factory=list)
    report_controls: list[ReportControlBlock] = field(default_factory=list)

    @property
    def domains(self) -> list[str]:
        return [self.name + inst for inst in self.ld_insts]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in element if _local(c.tag) == name]


def _ln_name(ln: ET.Element) -> str:
    if _local(ln.tag) == "LN0":
        return "LLN0"
    return f"{ln.get('prefix', '')}{ln.get('lnClass', '')}{ln.get('inst', '')}"


def load_ieds(source: Union[str, Path]) -> list[SclIed]:
    """Every IED of an SCL file, with its addresses and report control blocks."""
    try:
        root = ET.parse(source).getroot()
    except (ET.ParseError, OSError) as exc:
        raise SclError(f"cannot read SCL {source}: {exc}") from exc
    if _local(root.tag) != "SCL":
        raise SclError(f"{source} is not SCL (root element {_local(root.tag)})")

    addresses: dict[str, list[str]] = {}
    for element in root.iter():
        if _local(element.tag) != "ConnectedAP":
            continue
        for p in element.iter():
            if _local(p.tag) == "P" and p.get("type") == "IP" and p.text:
                addresses.setdefault(element.get("iedName", ""), []).append(p.text.strip())

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
            for ln in ld:
                if _local(ln.tag) not in ("LN0", "LN"):
                    continue
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
                    ))
        ieds.append(ied)
    return ieds


def find_ied(ieds: list[SclIed], host: str) -> Optional[SclIed]:
    """The IED whose address is ``host``; the only IED of a CID when no address matches."""
    for ied in ieds:
        if host in ied.addresses:
            return ied
    return ieds[0] if len(ieds) == 1 else None
