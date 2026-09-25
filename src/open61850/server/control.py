# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Controls of the MMS server (IEC 61850-7-2 clause 20, IEC 61850-8-1 clause 20).

A :class:`ControlEngine` attached to an :class:`~.server.MmsServer` runs the
commands clients send to controllable data objects (``LN$CO$DO``), in the
object's control model (``LN$CF$DO$ctlModel``):

- direct-with-normal-security: an Oper write executes;
- sbo-with-normal-security: a read of SBO selects (it returns the object
  reference, or an empty string when refused), then Oper executes;
- direct-with-enhanced-security: Oper executes, then a CommandTermination
  (an informationReport of the Oper value) follows the write response;
- sbo-with-enhanced-security: an SBOw write selects, then Oper executes,
  and the CommandTermination follows; Cancel releases the selection.

An Oper whose operTm (time-activated control) lies in the future is
accepted at once and executed at that time; its CommandTermination, in
enhanced security, comes after the execution.

A selection belongs to its client and lapses after sboTimeout (``CF``,
30 s by default). A refused command gets a LastApplError informationReport,
then the negative write response; a failed execution in enhanced security
a negative CommandTermination (LastApplError and Oper).

What a command does is up to a handler (:meth:`ControlEngine.set_handler`):
it receives a :class:`Command` and returns None (done) or an AddCause. The
default handler copies ctlVal to ``ST$DO$stVal`` (a Dbpos gets on or off from
a boolean) and stamps ``t``, ``origin`` and ``ctlNum`` when present, which is
what a simulated switch or output does. A command with Test set is checked
but not executed.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union

from ..data import (
    BitStringData,
    BoolData,
    IECData,
    IntData,
    OctetStringData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
)
from ..mms.pdu import ObjectName
from ..mms.types import PrimitiveType
from . import protocol
from .model import ACCESS_OBJECT_ACCESS_DENIED, ACCESS_OBJECT_NON_EXISTENT, ACCESS_TYPE_INCONSISTENT, IedModel, to_data

__all__ = [
    "ADD_CAUSE_NOT_SUPPORTED",
    "ADD_CAUSE_BLOCKED_BY_INTERLOCKING",
    "ADD_CAUSE_OBJECT_NOT_SELECTED",
    "ADD_CAUSE_OBJECT_ALREADY_SELECTED",
    "Command",
    "ControlHandler",
    "ControlEngine",
]

ADD_CAUSE_UNKNOWN = 0
ADD_CAUSE_NOT_SUPPORTED = 1
ADD_CAUSE_BLOCKED_BY_INTERLOCKING = 10
ADD_CAUSE_COMMAND_IN_EXECUTION = 12
ADD_CAUSE_OBJECT_NOT_SELECTED = 18
ADD_CAUSE_OBJECT_ALREADY_SELECTED = 19
ADD_CAUSE_INCONSISTENT_PARAMETERS = 26
_ERROR_UNKNOWN = 1  # LastApplError.Error

STATUS_ONLY, DIRECT_NORMAL, SBO_NORMAL, DIRECT_ENHANCED, SBO_ENHANCED = range(5)
DEFAULT_SBO_TIMEOUT_MS = 30000
_DBPOS_OFF, _DBPOS_ON = 1, 2


@dataclass(frozen=True)
class Command:
    """One command, as the handler sees it."""

    domain: str
    object_item: str  # LN$CO$DO
    ctl_val: IECData
    origin: Optional[IECData]
    ctl_num: int
    test: bool
    interlock_check: bool
    synchro_check: bool
    client: object  # the ServerConnection

    @property
    def reference(self) -> str:
        return f"{self.domain}/{self.object_item}"


ControlHandler = Callable[[Command], Optional[int]]  # None: done; an int: the AddCause of a refusal


@dataclass
class _Selection:
    client: object
    until: float


class ControlEngine:
    """Runs commands on the controllable objects of a server's model."""

    def __init__(self, server: object) -> None:
        from .server import MmsServer

        assert isinstance(server, MmsServer)
        self.server = server
        self.model: IedModel = server.model
        self.handlers: dict[tuple[str, str], ControlHandler] = {}
        self._selections: dict[tuple[str, str], _Selection] = {}
        self._lock = threading.RLock()
        server.write_hooks.insert(0, self._on_write)
        server.read_hooks.append(self._on_read)
        server.close_hooks.append(self._on_close)

    def set_handler(self, reference: str, handler: ControlHandler) -> None:
        """The handler of an object: ``LD/LN.DO`` or ``LD/LN$CO$DO``."""
        domain, _, item = reference.partition("/")
        if "$" not in item:
            ln, _, do = item.partition(".")
            item = f"{ln}$CO${do}"
        self.handlers[(domain, item)] = handler

    # --- helpers -------------------------------------------------------------------

    def _ctl_model(self, domain: str, ln: str, do: str) -> int:
        node = self.model.node(ObjectName(f"{ln}$CF${do}$ctlModel", domain))
        value = node.data() if node is not None else None
        return value.value if isinstance(value, IntData) else STATUS_ONLY

    def _sbo_timeout(self, domain: str, ln: str, do: str) -> float:
        node = self.model.node(ObjectName(f"{ln}$CF${do}$sboTimeout", domain))
        value = node.data() if node is not None else None
        ms = value.value if isinstance(value, (UIntData, IntData)) and value.value > 0 else DEFAULT_SBO_TIMEOUT_MS
        return ms / 1000

    def _selected_by(self, key: tuple[str, str]) -> Optional[object]:
        selection = self._selections.get(key)
        if selection is None or time.monotonic() > selection.until:
            self._selections.pop(key, None)
            return None
        return selection.client

    # --- reads: SBO ----------------------------------------------------------------------

    def _on_read(self, connection: object, name: ObjectName) -> Optional[Union[IECData, int]]:
        parts = name.item.split("$")
        if len(parts) != 4 or parts[1] != "CO" or parts[3] != "SBO":
            return None
        domain, key = name.domain or "", (name.domain or "", "$".join(parts[:3]))
        if self.model.node(name) is None:
            return ACCESS_OBJECT_NON_EXISTENT
        with self._lock:
            if self._ctl_model(domain, parts[0], parts[2]) != SBO_NORMAL:
                return VisibleStringData("")
            holder = self._selected_by(key)
            if holder is not None and holder is not connection:
                return VisibleStringData("")
            self._selections[key] = _Selection(connection, time.monotonic() + self._sbo_timeout(domain, parts[0], parts[2]))
            return VisibleStringData(f"{domain}/{key[1]}")

    # --- writes: SBOw, Oper, Cancel ----------------------------------------------------------

    def _on_write(self, connection: object, name: ObjectName, value: IECData) -> Optional[Union[int, bool]]:
        parts = name.item.split("$")
        if len(parts) < 3 or parts[1] != "CO":
            return None
        if len(parts) != 4 or parts[3] not in ("Oper", "SBOw", "Cancel"):
            return ACCESS_OBJECT_ACCESS_DENIED
        node = self.model.node(name)
        if node is None:
            return ACCESS_OBJECT_NON_EXISTENT
        if not isinstance(value, StructureData) or len(value.members) != len(node.children):
            return ACCESS_TYPE_INCONSISTENT
        domain, service = name.domain or "", parts[3]
        key = (domain, "$".join(parts[:3]))
        model = self._ctl_model(domain, parts[0], parts[2])
        fields = dict(zip(node.children, value.members))
        command = Command(
            domain=domain, object_item=key[1], ctl_val=fields.get("ctlVal", BoolData(False)),
            origin=fields.get("origin"), ctl_num=_int(fields.get("ctlNum")),
            test=_bool(fields.get("Test")),
            interlock_check=_check_bit(fields.get("Check"), 1), synchro_check=_check_bit(fields.get("Check"), 0),
            client=connection,
        )
        with self._lock:
            if model == STATUS_ONLY:
                return self._refuse(connection, name, command, ADD_CAUSE_NOT_SUPPORTED)
            if service == "Cancel":
                if self._selected_by(key) is connection:
                    self._selections.pop(key, None)
                return True
            if service == "SBOw":
                if model != SBO_ENHANCED:
                    return self._refuse(connection, name, command, ADD_CAUSE_NOT_SUPPORTED)
                holder = self._selected_by(key)
                if holder is not None and holder is not connection:
                    return self._refuse(connection, name, command, ADD_CAUSE_OBJECT_ALREADY_SELECTED)
                self._selections[key] = _Selection(connection, time.monotonic() + self._sbo_timeout(domain, parts[0], parts[2]))
                node.assign(value)
                return True
            # Oper
            if model in (SBO_NORMAL, SBO_ENHANCED) and self._selected_by(key) is not connection:
                return self._refuse(connection, name, command, ADD_CAUSE_OBJECT_NOT_SELECTED)
            if not self._fits_value(domain, key[1], command.ctl_val):
                return self._refuse(connection, name, command, ADD_CAUSE_INCONSISTENT_PARAMETERS)
            node.assign(value)
            self._selections.pop(key, None)
            delay = _delay(fields.get("operTm"))
            if delay > 0:  # time-activated: accepted now, executed at operTm
                if model in (DIRECT_NORMAL, SBO_NORMAL):
                    _later(delay, lambda: self._execute(command))
                else:
                    connection.after_response.append(  # type: ignore[attr-defined]
                        lambda: _later(delay, lambda: self._terminate(connection, name, command, value)))
                return True
            if model in (DIRECT_NORMAL, SBO_NORMAL):
                cause = self._execute(command)
                if cause is not None:
                    return self._refuse(connection, name, command, cause)
                return True
            # enhanced security: positive response now, execution and termination after it
            connection.after_response.append(lambda: self._terminate(connection, name, command, value))  # type: ignore[attr-defined]
            return True

    def _fits_value(self, domain: str, item: str, ctl_val: IECData) -> bool:
        node = self.model.node(ObjectName(f"{item}$Oper$ctlVal", domain))
        if node is None or not isinstance(node.mms_type, PrimitiveType):
            return True
        try:
            to_data(node.mms_type, ctl_val)
        except TypeError:
            return False
        return type(ctl_val) is type(node.data())

    def _execute(self, command: Command) -> Optional[int]:
        if command.test:
            return None
        handler = self.handlers.get((command.domain, command.object_item), self.default_handler)
        try:
            return handler(command)
        except Exception:
            return ADD_CAUSE_UNKNOWN

    def _terminate(self, connection: object, name: ObjectName, command: Command, oper: IECData) -> None:
        cause = self._execute(command)
        variables = [name]
        values: list[Union[IECData, int]] = [oper]
        if cause is not None:
            variables = [ObjectName("LastApplError"), name]
            values = [self._last_appl_error(name, command, cause), oper]
        self.server.broadcast(protocol.information_report(values, variables=variables), to=connection)  # type: ignore[arg-type]

    def _refuse(self, connection: object, name: ObjectName, command: Command, cause: int) -> int:
        """Send the LastApplError, then refuse the write (object-access-denied)."""
        report = protocol.information_report([self._last_appl_error(name, command, cause)],
                                             variables=[ObjectName("LastApplError")])
        self.server.broadcast(report, to=connection)  # type: ignore[arg-type]
        return ACCESS_OBJECT_ACCESS_DENIED

    @staticmethod
    def _last_appl_error(name: ObjectName, command: Command, cause: int) -> StructureData:
        origin = command.origin if command.origin is not None else StructureData([IntData(0), OctetStringData(b"")])
        return StructureData([VisibleStringData(f"{name.domain}/{name.item}"), IntData(_ERROR_UNKNOWN), origin,
                              UIntData(command.ctl_num), IntData(cause)])

    def _on_close(self, connection: object) -> None:
        with self._lock:
            for key in [k for k, s in self._selections.items() if s.client is connection]:
                del self._selections[key]

    # --- the default handler ----------------------------------------------------------------

    def default_handler(self, command: Command) -> Optional[int]:
        """Copy ctlVal to ST$DO$stVal and stamp t, origin and ctlNum."""
        ln, _, do = command.object_item.split("$", 2)
        base = f"{command.domain}/{ln}$ST${do}"
        st_val = self.model.node(f"{base}$stVal")
        if st_val is None:
            return ADD_CAUSE_NOT_SUPPORTED
        value: object = command.ctl_val
        if isinstance(st_val.mms_type, PrimitiveType) and st_val.mms_type.kind == "bit-string" and isinstance(value, BoolData):
            value = _DBPOS_ON if value.value else _DBPOS_OFF
        elif isinstance(value, (BoolData, IntData, UIntData)):
            value = value.value
        with self.model.lock:
            changes: list[tuple[str, object]] = [(f"{base}$stVal", value)]
            if self.model.node(f"{base}$t") is not None:
                changes.append((f"{base}$t", TimestampData(datetime.now(timezone.utc))))
            if command.origin is not None and self.model.node(f"{base}$origin") is not None:
                changes.append((f"{base}$origin", command.origin))
            if self.model.node(f"{base}$ctlNum") is not None:
                changes.append((f"{base}$ctlNum", UIntData(command.ctl_num)))
        for reference, new in changes:
            self.model.set(reference, new)
        return None


def _delay(oper_tm: Optional[IECData]) -> float:
    """Seconds until an operTm, 0 when absent or past."""
    if not isinstance(oper_tm, TimestampData):
        return 0.0
    when = oper_tm.value if oper_tm.value.tzinfo else oper_tm.value.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _later(delay: float, action: Callable[[], object]) -> None:
    timer = threading.Timer(delay, action)
    timer.daemon = True
    timer.start()


def _bool(value: Optional[IECData]) -> bool:
    return isinstance(value, BoolData) and value.value


def _int(value: Optional[IECData]) -> int:
    return value.value if isinstance(value, (IntData, UIntData)) else 0


def _check_bit(value: Optional[IECData], bit: int) -> bool:
    if not isinstance(value, BitStringData) or not value.value:
        return False
    return bool(value.value[0] & (0x80 >> bit))

