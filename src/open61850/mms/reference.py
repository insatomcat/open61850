# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""IEC 61850 object references and their MMS names (IEC 61850-8-1, clause 8.1.3).

An ACSI reference names a data object or attribute as
``LDName/LNName.DataObject.DataAttribute``, and a functional constraint (FC)
says which part of it is meant (``ST`` status, ``MX`` measurands, ``CF``
configuration...). MMS puts the FC right after the logical node, with ``$``
as separator, in a variable of the logical device's domain::

    IED01_LD0/LLN0.Mod.stVal [ST]   <->   domain IED01_LD0, item LLN0$ST$Mod$stVal

:class:`Reference` holds both views. :func:`to_object_name` takes an
:class:`~open61850.mms.ObjectName`, a :class:`Reference` or text in either
notation, which is what the client methods accept::

    client.read("IED01_LD0/LLN0.Mod.stVal[ST]")
    client.read("IED01_LD0/LLN0$ST$Mod$stVal")

A control block is a reference too: ``IED01_LD0/LLN0.brcbMeas01 [BR]`` is
``LLN0$BR$brcbMeas01``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Union

from .pdu import ObjectName

__all__ = [
    "FUNCTIONAL_CONSTRAINTS",
    "CONTROL_BLOCK_FCS",
    "Reference",
    "Name",
    "to_object_name",
    "data_set_object_name",
]


# IEC 61850-7-2 Ed2, table 20 (data) and the control block FCs.
FUNCTIONAL_CONSTRAINTS = {
    "ST": "status information",
    "MX": "measurands",
    "SP": "setpoint",
    "SV": "substitution",
    "CF": "configuration",
    "DC": "description",
    "SG": "setting group",
    "SE": "setting group editable",
    "SR": "service response",
    "OR": "operate received",
    "BL": "blocking",
    "EX": "extended definition",
    "CO": "control",
    "BR": "buffered report control block",
    "RP": "unbuffered report control block",
    "LG": "log control block",
    "GO": "GOOSE control block",
    "GS": "GSSE control block",
    "MS": "multicast sampled value control block",
    "US": "unicast sampled value control block",
}
CONTROL_BLOCK_FCS = frozenset({"BR", "RP", "LG", "GO", "GS", "MS", "US"})

_FC = re.compile(r"^[A-Z]{2}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]+$")
_WITH_FC = re.compile(r"^(?P<ref>.*?)\s*\[(?P<fc>[A-Za-z]{2})\]$")


@dataclass(frozen=True)
class Reference:
    """``ld/ln.path[0].path[1]...`` with a functional constraint.

    ``fc`` is ``None`` for a logical node, or a data object named without FC
    (to be resolved against a model, see :meth:`~open61850.mms.model.ServerModel.resolve`).
    """

    ld: str
    ln: str
    path: tuple[str, ...] = ()
    fc: Optional[str] = None

    def __post_init__(self) -> None:
        if not all(_IDENTIFIER.match(part) for part in (self.ld, self.ln, *self.path)):
            raise ValueError(f"bad reference {self.name!r}")
        if self.fc is not None and not _FC.match(self.fc):
            raise ValueError(f"bad functional constraint {self.fc!r}")

    @property
    def name(self) -> str:
        """The ACSI reference, without its FC."""
        return f"{self.ld}/" + ".".join((self.ln, *self.path))

    def __str__(self) -> str:
        return f"{self.name} [{self.fc}]" if self.fc else self.name

    def child(self, name: str) -> Reference:
        return Reference(self.ld, self.ln, (*self.path, name), self.fc)

    def with_fc(self, fc: Optional[str]) -> Reference:
        return Reference(self.ld, self.ln, self.path, fc)

    @property
    def object_name(self) -> ObjectName:
        """The MMS variable; a reference below the logical node needs its FC."""
        if self.path and self.fc is None:
            raise ValueError(f"{self.name} needs a functional constraint to be an MMS name")
        parts = [self.ln] + ([self.fc] if self.fc else []) + list(self.path)
        return ObjectName("$".join(parts), self.ld)

    @classmethod
    def from_object_name(cls, name: ObjectName) -> Reference:
        """The reference of an MMS variable of a logical device (``LN``, ``LN$FC`` or ``LN$FC$...``)."""
        if not name.domain:
            raise ValueError(f"{name} is not in a logical device")
        ln, *rest = name.item.split("$")
        fc = rest.pop(0) if rest else None
        return cls(name.domain, ln, tuple(rest), fc)

    @classmethod
    def parse(cls, text: str, fc: Optional[str] = None) -> Reference:
        """``LD/LN.DO.DA``, optionally followed by ``[FC]``, or the MMS form ``LD/LN$FC$DO$DA``."""
        text = text.strip()
        if match := _WITH_FC.match(text):
            if fc is not None and fc.upper() != match["fc"].upper():
                raise ValueError(f"{text!r} says FC {match['fc']}, not {fc}")
            text, fc = match["ref"], match["fc"]
        ld, slash, rest = text.partition("/")
        if not slash:
            raise ValueError(f"expected LD/LN..., got {text!r}")
        if "$" in rest:
            ref = cls.from_object_name(ObjectName(rest, ld))
            if fc is not None and ref.fc != fc.upper():
                raise ValueError(f"{text!r} is in FC {ref.fc}, not {fc}")
            return ref
        ln, *path = rest.split(".")
        return cls(ld, ln, tuple(path), fc.upper() if fc else None)


Name = Union[ObjectName, Reference, str]


def to_object_name(name: Name) -> ObjectName:
    """The MMS variable meant by an ObjectName, a Reference or its text (either notation).

    Text in the MMS notation (``LD/ITEM`` with a ``$``) is taken as it is,
    so that any MMS name, a data set's for instance, goes through.
    """
    if isinstance(name, ObjectName):
        return name
    if isinstance(name, str):
        domain, slash, item = name.strip().partition("/")
        if slash and "$" in item and "[" not in item:
            return ObjectName(item, domain)
        name = Reference.parse(name)
    return name.object_name


def data_set_object_name(name: Name) -> ObjectName:
    """The MMS named variable list of a data set: ``LD/LLN0.DS1`` is ``LLN0$DS1`` in domain ``LD``."""
    if isinstance(name, str):
        domain, slash, item = name.strip().partition("/")
        if slash and "$" in item:
            return ObjectName(item, domain)
        name = Reference.parse(name)
    if isinstance(name, Reference):
        if name.fc is not None or len(name.path) != 1:
            raise ValueError(f"{name} is not a data set reference (LD/LN.DataSetName)")
        return ObjectName(f"{name.ln}${name.path[0]}", name.ld)
    return name
