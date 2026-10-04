# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Setting groups of the MMS server (IEC 61850-7-2 clause 16, IEC 61850-8-1 clause 16).

A :class:`SettingGroupEngine` attached to an :class:`~.server.MmsServer`
makes the setting group control blocks (``LLN0$SP$SGCB``) of its model
work, as libiec61850 does:

- SelectActiveSG, a write of ``ActSG`` (1 to NumOfSG; the same group is
  done at once): the group's values go into FC SG, LActTm is the time;
- SelectEditSG, a write of ``EditSG``: the group's values go into FC SE,
  which only this client may then write (another client's write gets
  temporarily-unavailable, and so does its SelectEditSG); 0 ends the
  edit. The edit lapses after ResvTms seconds, and when the client goes;
- ConfirmEditSGValues, a write of TRUE to ``CnfEdit``: SE's values become
  the group's (and SG's when it is the active group), and the edit ends.

The values of each group are :attr:`~.model.IedModel.setting_groups`. The
application follows the changes with :attr:`SettingGroupEngine.on_active`,
:attr:`~SettingGroupEngine.on_edit` and :attr:`~SettingGroupEngine.on_confirm`,
called before the change with the client, the logical device and the
group: None lets it happen, a DataAccessError code refuses it. It changes
the groups itself with :meth:`SettingGroupEngine.select_active` and
:meth:`SettingGroupEngine.set_values`.

The other attributes of an SGCB are read-only (object-access-denied).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any, Optional, Union

from ..data import BoolData, IECData, IntData, TimestampData, UIntData
from ..mms.pdu import ObjectName
from .model import (
    ACCESS_OBJECT_ACCESS_DENIED,
    ACCESS_OBJECT_NON_EXISTENT,
    ACCESS_OBJECT_VALUE_INVALID,
    ACCESS_TEMPORARILY_UNAVAILABLE,
    ACCESS_TYPE_INCONSISTENT,
    IedModel,
    Node,
    SettingGroups,
    _fits,
    group_key,
    to_data,
)

__all__ = ["SettingGroupEngine", "GroupHandler"]

SGCB = "LLN0$SP$SGCB"

# (client or None, logical device, group) -> None to go on, or a DataAccessError code to refuse
GroupHandler = Callable[[Optional[object], str, int], Optional[int]]


class _Block:
    """The state of one SGCB that is not in its attributes: who edits, until when."""

    def __init__(self, domain: str, groups: SettingGroups, sg: dict[str, Node], se: dict[str, Node]) -> None:
        self.domain = domain
        self.groups = groups
        self.sg = sg  # group key -> the SG leaf
        self.se = se  # group key -> the SE leaf
        self.editor: Optional[object] = None
        self.until = 0.0


class SettingGroupEngine:
    """The setting group control blocks of a server's model."""

    def __init__(self, server: object) -> None:
        from .server import MmsServer

        assert isinstance(server, MmsServer)
        self.server = server
        self.model: IedModel = server.model
        self.on_active: Optional[GroupHandler] = None
        self.on_edit: Optional[GroupHandler] = None
        self.on_confirm: Optional[GroupHandler] = None
        self.blocks: dict[str, _Block] = {}
        for domain, groups in self.model.setting_groups.items():
            leaves: dict[str, dict[str, Node]] = {"SG": {}, "SE": {}}
            for ln in self.model.logical_devices[domain].values():
                for fc, found in leaves.items():
                    fc_node = ln.child(fc)
                    found.update((group_key(leaf), leaf) for leaf in (fc_node.leaves() if fc_node is not None else ()))
            self.blocks[domain] = _Block(domain, groups, leaves["SG"], leaves["SE"])
        self._lock = threading.RLock()
        server.write_hooks.insert(0, self._on_write)
        server.read_hooks.append(self._on_read)
        server.close_hooks.append(self._on_close)

    # --- the application -------------------------------------------------------------

    def active(self, domain: str) -> int:
        """ActSG of a logical device."""
        return self._uint(domain, "ActSG")

    def values(self, domain: str, group: int) -> dict[str, IECData]:
        """The values of one group, by ``LN.DO.DA``."""
        with self._lock:
            return dict(self._block(domain).groups.values[group])

    def set_values(self, domain: str, group: int, values: Mapping[str, Any]) -> None:
        """Change values of one group (``LN.DO.DA`` -> a value :meth:`IedModel.set` takes); SG follows for the active group."""
        with self._lock:
            block = self._block(domain)
            stored = block.groups.values[group]
            converted = {}
            for key, value in values.items():
                leaf = block.sg.get(key)
                if leaf is None:
                    raise KeyError(f"no setting {key} in {domain}'s groups")
                data = to_data(leaf.mms_type, value)
                if not _fits(leaf.mms_type, data):
                    raise TypeError(f"{data!r} does not fit {key} ({leaf.mms_type})")
                converted[key] = data
            stored.update(converted)
            if group == self.active(domain):
                self._load(block, block.sg, group)

    def select_active(self, domain: str, group: int) -> None:
        """Make a group the active one, from the application (no handler is called)."""
        with self._lock:
            block = self._block(domain)
            if not 1 <= group <= block.groups.count:
                raise ValueError(f"{domain} has groups 1 to {block.groups.count}")
            if group != self.active(domain):
                self._activate(block, group)

    # --- helpers -------------------------------------------------------------------

    def _block(self, domain: str) -> _Block:
        block = self.blocks.get(domain)
        if block is None:
            raise KeyError(f"no setting groups in {domain}")
        return block

    def _uint(self, domain: str, attribute: str) -> int:
        value = self.model.get(ObjectName(f"{SGCB}${attribute}", domain))
        return value.value if isinstance(value, (UIntData, IntData)) else 0

    def _set(self, domain: str, attribute: str, value: IECData) -> None:
        if self.model.node(ObjectName(f"{SGCB}${attribute}", domain)) is not None:
            self.model.set(ObjectName(f"{SGCB}${attribute}", domain), value)

    def _load(self, block: _Block, leaves: dict[str, Node], group: int) -> None:
        """A group's values into SG or SE leaves (the listeners are told)."""
        values = block.groups.values[group]
        for key, leaf in leaves.items():
            if key in values:
                self.model.set(ObjectName(leaf.item, block.domain), values[key])

    def _activate(self, block: _Block, group: int) -> None:
        self._set(block.domain, "ActSG", UIntData(group))
        self._set(block.domain, "LActTm", TimestampData(datetime.now(timezone.utc)))
        self._load(block, block.sg, group)

    def _release(self, block: _Block) -> None:
        block.editor = None
        self._set(block.domain, "EditSG", UIntData(0))
        self._set(block.domain, "ResvTms", UIntData(0))

    def _expire(self, block: _Block) -> None:
        if block.editor is not None and time.monotonic() >= block.until:
            self._release(block)

    # --- reads, writes, clients going ----------------------------------------------------

    def _on_read(self, connection: object, name: ObjectName) -> Optional[Union[IECData, int]]:
        block = self.blocks.get(name.domain or "")
        if block is not None and name.item.startswith("LLN0"):
            with self._lock:
                self._expire(block)  # EditSG and ResvTms as they are now
        return None

    def _on_write(self, connection: object, name: ObjectName, value: IECData) -> Optional[Union[int, bool]]:
        block = self.blocks.get(name.domain or "")
        if block is None:
            return None
        parts = name.item.split("$")
        with self._lock:
            self._expire(block)
            if len(parts) >= 3 and parts[1] == "SE":
                return None if block.editor is connection else ACCESS_TEMPORARILY_UNAVAILABLE
            if not (name.item == SGCB or name.item.startswith(SGCB + "$")):
                return None
            if self.model.node(name) is None:
                return ACCESS_OBJECT_NON_EXISTENT
            attribute = parts[3] if len(parts) == 4 else ""
            if attribute == "ActSG":
                return self._write_active(connection, block, value)
            if attribute == "EditSG":
                return self._write_edit(connection, block, value)
            if attribute == "CnfEdit":
                return self._write_confirm(connection, block, value)
            return ACCESS_OBJECT_ACCESS_DENIED

    def _write_active(self, connection: object, block: _Block, value: IECData) -> Union[int, bool]:
        if not isinstance(value, (UIntData, IntData)):
            return ACCESS_TYPE_INCONSISTENT
        group = value.value
        if not 1 <= group <= block.groups.count:
            return ACCESS_OBJECT_VALUE_INVALID
        if group == self.active(block.domain):
            return True
        refused = self.on_active(connection, block.domain, group) if self.on_active is not None else None
        if refused is not None:
            return refused
        self._activate(block, group)
        return True

    def _write_edit(self, connection: object, block: _Block, value: IECData) -> Union[int, bool]:
        if not isinstance(value, (UIntData, IntData)):
            return ACCESS_TYPE_INCONSISTENT
        if block.editor is not None and block.editor is not connection:
            return ACCESS_TEMPORARILY_UNAVAILABLE
        group = value.value
        if group == 0:
            self._release(block)
            return True
        if not 1 <= group <= block.groups.count:
            return ACCESS_OBJECT_VALUE_INVALID
        refused = self.on_edit(connection, block.domain, group) if self.on_edit is not None else None
        if refused is not None:
            return refused
        block.editor = connection
        block.until = time.monotonic() + block.groups.resv_tms
        self._set(block.domain, "EditSG", UIntData(group))
        self._set(block.domain, "ResvTms", UIntData(block.groups.resv_tms))
        self._load(block, block.se, group)
        return True

    def _write_confirm(self, connection: object, block: _Block, value: IECData) -> Union[int, bool]:
        if not isinstance(value, BoolData):
            return ACCESS_TYPE_INCONSISTENT
        if not value.value:
            return ACCESS_OBJECT_VALUE_INVALID
        group = self._uint(block.domain, "EditSG")
        if group == 0 or block.editor is not connection:
            return ACCESS_OBJECT_ACCESS_DENIED
        refused = self.on_confirm(connection, block.domain, group) if self.on_confirm is not None else None
        if refused is not None:
            return refused
        stored = block.groups.values[group]
        for key, leaf in block.se.items():
            if key in stored:
                stored[key] = self.model.get(ObjectName(leaf.item, block.domain))
        if group == self.active(block.domain):
            self._load(block, block.sg, group)
        self._release(block)
        return True

    def _on_close(self, connection: object) -> None:
        with self._lock:
            for block in self.blocks.values():
                if block.editor is connection:
                    self._release(block)
