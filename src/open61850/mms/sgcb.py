# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Setting group control blocks (IEC 61850-7-2 SGCB over MMS, IEC 61850-8-1).

A logical device has at most one, ``LLN0$SP$SGCB``. Its services are
writes of its attributes: SelectActiveSG writes ``ActSG``, SelectEditSG
``EditSG`` (then the edited group's values are FC SE, written as any
variable), ConfirmEditSGValues TRUE to ``CnfEdit``. A refusal raises the
server's :class:`~.errors.DataAccessError` (temporarily-unavailable while
another client edits).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ..data import BoolData, IntData, StructureData, TimestampData, UIntData
from .client import MmsClient
from .pdu import ObjectName

__all__ = ["SgcbStatus", "read_sgcb", "select_active_sg", "select_edit_sg", "confirm_edit_sg_values"]


def _name(ld: str, attribute: str = "") -> ObjectName:
    return ObjectName("LLN0$SP$SGCB" + (f"${attribute}" if attribute else ""), ld)


@dataclass
class SgcbStatus:
    num_of_sg: int
    act_sg: int
    edit_sg: int
    cnf_edit: bool
    l_act_tm: Optional[datetime]
    resv_tms: Optional[int]  # edition 2


def read_sgcb(client: MmsClient, ld: str) -> SgcbStatus:
    """The SGCB of a logical device, read in one request."""
    value = client.read(_name(ld))
    members = value.members if isinstance(value, StructureData) else []
    if len(members) < 5:
        raise ValueError(f"{ld}/LLN0.SGCB: not an SGCB ({value!r})")

    def number(i: int) -> int:
        member = members[i]
        return member.value if isinstance(member, (UIntData, IntData)) else 0

    cnf, tm = members[3], members[4]
    return SgcbStatus(number(0), number(1), number(2), isinstance(cnf, BoolData) and cnf.value,
                      tm.value if isinstance(tm, TimestampData) else None, number(5) if len(members) > 5 else None)


def select_active_sg(client: MmsClient, ld: str, group: int) -> None:
    client.write(_name(ld, "ActSG"), UIntData(group))


def select_edit_sg(client: MmsClient, ld: str, group: int) -> None:
    """Edit a group (its values are then FC SE); 0 ends the edit without a confirmation."""
    client.write(_name(ld, "EditSG"), UIntData(group))


def confirm_edit_sg_values(client: MmsClient, ld: str) -> None:
    client.write(_name(ld, "CnfEdit"), BoolData(True))
