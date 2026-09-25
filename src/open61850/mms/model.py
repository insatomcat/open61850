# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The data model of an IEC 61850 server, discovered over MMS.

A server lists, for each logical device (MMS domain), every variable at
every level: ``LLN0``, ``LLN0$ST``, ``LLN0$ST$Mod``, ``LLN0$ST$Mod$stVal``...
(GetNameList, in pages). That is enough to rebuild the ACSI tree: logical
devices, logical nodes, data objects and attributes with their functional
constraints, control blocks and data sets. Types (GetVariableAccessAttributes,
one request per logical node) are optional.

::

    model = discover(client)
    for ref in model.references(fc="MX"):
        print(ref)                                   # IED01_LD0/MMXU1.TotW.mag.f [MX]
    ref = model.resolve("IED01_LD0/LLN0.Mod.stVal")  # the FC is found: [ST]
    print(client.read(ref))

:func:`logical_device_from_names` builds a device from names already read,
without I/O.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from .errors import MmsError
from .pdu import OBJECT_CLASS_DOMAIN, OBJECT_CLASS_NAMED_VARIABLE, OBJECT_CLASS_NAMED_VARIABLE_LIST, ObjectName
from .reference import CONTROL_BLOCK_FCS, Reference
from .types import ArrayType, MmsType, StructureType

if TYPE_CHECKING:
    from .client import MmsClient

__all__ = [
    "LogicalNode",
    "LogicalDevice",
    "ServerModel",
    "logical_device_from_names",
    "discover",
]


@dataclass
class LogicalNode:
    """One logical node: its MMS variables below it (``FC$...``), data sets and optional type."""

    ld: str
    name: str
    items: list[str] = field(default_factory=list)  # below the LN, without the "LN$" prefix, server order
    data_sets: list[str] = field(default_factory=list)  # names without the "LN$" prefix
    type: Optional[MmsType] = None  # GetVariableAccessAttributes of the LN, when discovered with types

    @property
    def reference(self) -> Reference:
        return Reference(self.ld, self.name)

    def functional_constraints(self) -> list[str]:
        return [item for item in self.items if "$" not in item]

    def references(self, fc: Optional[str] = None, *, leaves: bool = True, control_blocks: bool = False) -> list[Reference]:
        """Data objects and attributes, in server order: only the leaves unless ``leaves=False``.

        The inside of control blocks is left out unless ``control_blocks=True``.
        """
        parents = {item.rsplit("$", 1)[0] for item in self.items}
        out = []
        for item in self.items:
            item_fc, _, path = item.partition("$")
            if not path or (fc is not None and item_fc != fc):
                continue
            if item_fc in CONTROL_BLOCK_FCS and not control_blocks:
                continue
            if leaves and item in parents:
                continue
            out.append(Reference(self.ld, self.name, tuple(path.split("$")), item_fc))
        return out

    def data_objects(self) -> list[str]:
        """Names of the data objects, in the order they first appear (over every data FC)."""
        seen: dict[str, None] = {}
        for item in self.items:
            parts = item.split("$")
            if len(parts) >= 2 and parts[0] not in CONTROL_BLOCK_FCS:
                seen.setdefault(parts[1], None)
        return list(seen)

    def control_blocks(self, fc: Optional[str] = None) -> list[Reference]:
        """Report, log, GOOSE and SV control blocks (FC BR, RP, LG, GO, GS, MS, US)."""
        out = []
        for item in self.items:
            parts = item.split("$")
            if len(parts) == 2 and parts[0] in CONTROL_BLOCK_FCS and (fc is None or parts[0] == fc):
                out.append(Reference(self.ld, self.name, (parts[1],), parts[0]))
        return out

    def has(self, ref: Reference) -> bool:
        if ref.fc is None:
            return not ref.path
        return "$".join((ref.fc, *ref.path)) in self.items

    def type_of(self, ref: Reference) -> Optional[MmsType]:
        """The type of a reference of this node, when the node was discovered with its type."""
        node: Optional[MmsType] = self.type
        for part in ((ref.fc,) if ref.fc else ()) + ref.path:
            while isinstance(node, ArrayType):
                node = node.element
            if not isinstance(node, StructureType):
                return None
            node = node.component(part)
        return node


@dataclass
class LogicalDevice:
    name: str
    logical_nodes: dict[str, LogicalNode] = field(default_factory=dict)


@dataclass
class ServerModel:
    logical_devices: dict[str, LogicalDevice] = field(default_factory=dict)

    def logical_node(self, ld: str, ln: str) -> LogicalNode:
        try:
            return self.logical_devices[ld].logical_nodes[ln]
        except KeyError:
            raise KeyError(f"no logical node {ld}/{ln}") from None

    def logical_nodes(self) -> Iterator[LogicalNode]:
        for device in self.logical_devices.values():
            yield from device.logical_nodes.values()

    def references(self, fc: Optional[str] = None) -> Iterator[Reference]:
        """Every data attribute (leaf) of the server, optionally of one FC."""
        for node in self.logical_nodes():
            yield from node.references(fc)

    def resolve(self, name: str | Reference) -> Reference:
        """The reference with its FC, checked against the model.

        Without FC, the one FC under which the path exists is taken; a data
        object present under several FCs (``Mod``: ST, CF, DC, CO) raises
        ``ValueError`` listing them. An unknown reference raises ``KeyError``.
        """
        ref = Reference.parse(name) if isinstance(name, str) else name
        node = self.logical_node(ref.ld, ref.ln)
        if ref.fc is not None or not ref.path:
            if not node.has(ref):
                raise KeyError(f"no {ref} in the model")
            return ref
        found = [fc for fc in node.functional_constraints() if node.has(ref.with_fc(fc))]
        if not found:
            raise KeyError(f"no {ref} in the model")
        if len(found) > 1:
            raise ValueError(f"{ref} exists under several functional constraints: {', '.join(found)}")
        return ref.with_fc(found[0])


def logical_device_from_names(domain: str, names: Iterable[str], data_sets: Iterable[str] = ()) -> LogicalDevice:
    """A logical device from the named variables and named variable lists of its domain."""
    device = LogicalDevice(domain)
    for name in names:
        ln, _, rest = name.partition("$")
        node = device.logical_nodes.get(ln)
        if node is None:
            node = device.logical_nodes[ln] = LogicalNode(domain, ln)
        if rest:
            node.items.append(rest)
    for name in data_sets:
        ln, _, rest = name.partition("$")
        if rest:
            device.logical_nodes.setdefault(ln, LogicalNode(domain, ln)).data_sets.append(rest)
    return device


def discover(client: MmsClient, domains: Optional[Iterable[str]] = None, *, types: bool = False) -> ServerModel:
    """Read the model of the server (or of some logical devices).

    Two GetNameList series per logical device (variables and data sets),
    plus one GetVariableAccessAttributes per logical node with ``types``.
    A logical node whose type the server refuses keeps ``type = None``.
    """
    model = ServerModel()
    for domain in list(domains) if domains is not None else client.get_name_list(OBJECT_CLASS_DOMAIN):
        names = client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE, domain)
        try:
            data_sets = client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE_LIST, domain)
        except MmsError:
            data_sets = []
        device = model.logical_devices[domain] = logical_device_from_names(domain, names, data_sets)
        if types:
            for node in device.logical_nodes.values():
                try:
                    node.type = client.get_type(ObjectName(node.name, domain))
                except MmsError:
                    node.type = None
    return model
