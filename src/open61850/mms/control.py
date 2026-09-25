# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""IEC 61850 controls over MMS (IEC 61850-7-2 clause 20, 61850-8-1 clause 20).

:func:`operate` runs one command on a controllable data object such as
``CBCSWI1$CO$Pos`` according to its control model:

- direct-with-normal-security: one Oper write;
- sbo-with-normal-security: a read of SBO (the selection), then Oper;
- direct-with-enhanced-security: Oper, then the CommandTermination;
- sbo-with-enhanced-security: an SBOw write, then Oper, then the CommandTermination.

A refused command raises :class:`ControlError` with the LastApplError the
server sent (its AddCause says why).

Example::

    with MmsClient.connect("10.0.0.2") as client:
        operate(client, ObjectName("CBCSWI1$CO$Pos", "IED1BayLD"), True)  # close
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Union

from ..data import (
    BitStringData,
    BoolData,
    FloatData,
    IECData,
    IntData,
    OctetStringData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
)
from .client import MmsClient
from .errors import DataAccessError, MmsError
from .pdu import InformationReport, ObjectName
from .reference import Name, Reference, to_object_name

__all__ = [
    "OR_CAT_NOT_SUPPORTED",
    "OR_CAT_BAY_CONTROL",
    "OR_CAT_STATION_CONTROL",
    "OR_CAT_REMOTE_CONTROL",
    "OR_CAT_AUTOMATIC_BAY",
    "OR_CAT_AUTOMATIC_STATION",
    "OR_CAT_AUTOMATIC_REMOTE",
    "OR_CAT_MAINTENANCE",
    "OR_CAT_PROCESS",
    "CTL_MODEL_STATUS_ONLY",
    "CTL_MODEL_DIRECT_NORMAL",
    "CTL_MODEL_SBO_NORMAL",
    "CTL_MODEL_DIRECT_ENHANCED",
    "CTL_MODEL_SBO_ENHANCED",
    "CTL_MODELS",
    "ADD_CAUSES",
    "CONTROL_ERRORS",
    "DEFAULT_TIME_QUALITY",
    "LAST_APPL_ERROR",
    "CtlValue",
    "Origin",
    "LastApplError",
    "ControlError",
    "ControlResult",
    "control_object_name",
    "ctl_model_name",
    "read_ctl_model",
    "oper_value",
    "operate",
]


OR_CAT_NOT_SUPPORTED = 0
OR_CAT_BAY_CONTROL = 1
OR_CAT_STATION_CONTROL = 2
OR_CAT_REMOTE_CONTROL = 3
OR_CAT_AUTOMATIC_BAY = 4
OR_CAT_AUTOMATIC_STATION = 5
OR_CAT_AUTOMATIC_REMOTE = 6
OR_CAT_MAINTENANCE = 7
OR_CAT_PROCESS = 8

CTL_MODEL_STATUS_ONLY = 0
CTL_MODEL_DIRECT_NORMAL = 1
CTL_MODEL_SBO_NORMAL = 2
CTL_MODEL_DIRECT_ENHANCED = 3
CTL_MODEL_SBO_ENHANCED = 4

CTL_MODELS = {
    0: "status-only",
    1: "direct-with-normal-security",
    2: "sbo-with-normal-security",
    3: "direct-with-enhanced-security",
    4: "sbo-with-enhanced-security",
}

# IEC 61850-7-2 Ed2, AddCause.
ADD_CAUSES = {
    0: "unknown", 1: "not-supported", 2: "blocked-by-switching-hierarchy", 3: "select-failed",
    4: "invalid-position", 5: "position-reached", 6: "parameter-change-in-execution", 7: "step-limit",
    8: "blocked-by-mode", 9: "blocked-by-process", 10: "blocked-by-interlocking",
    11: "blocked-by-synchrocheck", 12: "command-already-in-execution", 13: "blocked-by-health",
    14: "1-of-n-control", 15: "abortion-by-cancel", 16: "time-limit-over", 17: "abortion-by-trip",
    18: "object-not-selected", 19: "object-already-selected", 20: "no-access-authority",
    21: "ended-with-overshoot", 22: "abortion-due-to-deviation", 23: "abortion-by-communication-loss",
    24: "blocked-by-command", 25: "none", 26: "inconsistent-parameters", 27: "locked-by-other-client",
}

# LastApplError.Error
CONTROL_ERRORS = {0: "no-error", 1: "unknown", 2: "timeout-test-not-ok", 3: "operator-test-not-ok"}

# Clock not synchronized, accuracy unspecified: what IEDscout sends.
DEFAULT_TIME_QUALITY = 0x3F

LAST_APPL_ERROR = ObjectName("LastApplError")
_CONTROL_ATTRIBUTES = ("Oper", "SBOw", "SBO", "Cancel")

CtlValue = Union[IECData, bool, int, float]


@dataclass(frozen=True)
class Origin:
    """Who issues the command (originator category and identification)."""

    category: int = OR_CAT_STATION_CONTROL
    ident: bytes = b""

    def to_data(self) -> StructureData:
        return StructureData([IntData(self.category), OctetStringData(self.ident)])


@dataclass(frozen=True)
class LastApplError:
    """The reason a server gives for refusing or aborting a command."""

    control_object: str
    error: int
    origin: Optional[Origin]
    ctl_num: int
    add_cause: int

    @property
    def add_cause_name(self) -> str:
        return ADD_CAUSES.get(self.add_cause, str(self.add_cause))

    def __str__(self) -> str:
        error = CONTROL_ERRORS.get(self.error, str(self.error))
        return f"{self.control_object}: {error}, AddCause {self.add_cause} ({self.add_cause_name}), ctlNum {self.ctl_num}"

    @classmethod
    def from_data(cls, value: IECData) -> LastApplError:
        """Decode {CntrlObj, Error, Origin, ctlNum, AddCause}."""
        if not isinstance(value, StructureData) or len(value.members) < 5:
            raise ValueError(f"unexpected LastApplError value: {value!r}")
        obj, error, origin, ctl_num, add_cause = value.members[:5]
        decoded_origin = None
        if isinstance(origin, StructureData) and len(origin.members) >= 2:
            cat, ident = origin.members[:2]
            decoded_origin = Origin(int(getattr(cat, "value", 0)), bytes(getattr(ident, "value", b"")))
        return cls(
            control_object=str(getattr(obj, "value", "")),
            error=int(getattr(error, "value", 0)),
            origin=decoded_origin,
            ctl_num=int(getattr(ctl_num, "value", 0)),
            add_cause=int(getattr(add_cause, "value", 0)),
        )


class ControlError(MmsError):
    """The server refused or aborted the command."""

    def __init__(self, stage: str, message: str, last_appl_error: Optional[LastApplError] = None) -> None:
        self.stage = stage
        self.last_appl_error = last_appl_error
        detail = f" [{last_appl_error}]" if last_appl_error is not None else ""
        super().__init__(f"{stage}: {message}{detail}")


@dataclass
class ControlResult:
    ctl_model: int
    ctl_num: int
    terminated: bool  # a positive CommandTermination arrived (enhanced security only)
    duration: float  # seconds from the first request to the end of the command

    def __str__(self) -> str:
        end = ", CommandTermination received" if self.terminated else ""
        return f"{CTL_MODELS.get(self.ctl_model, self.ctl_model)}, ctlNum {self.ctl_num}{end}, {self.duration * 1000:.0f} ms"


def control_object_name(name: Name) -> ObjectName:
    """The data object of a control reference (``X$CO$Pos$Oper`` becomes ``X$CO$Pos``).

    An IEC 61850 reference without FC (``LD/CSWI1.Pos``) is taken in FC CO.
    """
    if isinstance(name, str) and "$" not in name:
        name = Reference.parse(name)
    if isinstance(name, Reference) and name.fc is None:
        name = name.with_fc("CO")
    name = to_object_name(name)
    head, _, last = name.item.rpartition("$")
    if head and last in _CONTROL_ATTRIBUTES:
        return ObjectName(head, name.domain)
    return name


def _attribute(obj: ObjectName, attribute: str) -> ObjectName:
    return ObjectName(f"{obj.item}${attribute}", obj.domain)


def ctl_model_name(obj: ObjectName) -> ObjectName:
    """``X$CO$Pos`` gives ``X$CF$Pos$ctlModel``."""
    ln, sep, rest = obj.item.partition("$CO$")
    if not sep:
        raise ValueError(f"{obj} is not a control object (no $CO$)")
    return ObjectName(f"{ln}$CF${rest}$ctlModel", obj.domain)


def read_ctl_model(client: MmsClient, obj: Name) -> int:
    name = ctl_model_name(control_object_name(obj))
    try:
        value = client.read(name)
    except DataAccessError as exc:
        raise ControlError("check", f"cannot read {name} ({exc})") from exc
    return int(getattr(value, "value", value))  # type: ignore[arg-type]


def _ctl_value(value: CtlValue) -> IECData:
    if isinstance(value, bool):
        return BoolData(value)
    if isinstance(value, int):
        return IntData(value)
    if isinstance(value, float):
        return FloatData(value)
    return value


def oper_value(
    ctl_val: CtlValue,
    *,
    origin: Origin = Origin(),
    ctl_num: int = 0,
    test: bool = False,
    interlock_check: bool = True,
    synchro_check: bool = True,
    t: Optional[datetime] = None,
    time_quality: int = DEFAULT_TIME_QUALITY,
    oper_tm: Optional[datetime] = None,
) -> StructureData:
    """The Oper / SBOw structure {ctlVal, [operTm], origin, ctlNum, T, Test, Check}.

    ``oper_tm`` is for time-activated controls, whose Oper carries operTm:
    the time the command is to execute.
    """
    check = (0x80 if synchro_check else 0) | (0x40 if interlock_check else 0)
    activation = [TimestampData(oper_tm, quality=time_quality)] if oper_tm is not None else []
    return StructureData([
        _ctl_value(ctl_val),
        *activation,
        origin.to_data(),
        UIntData(ctl_num & 0xFF),
        TimestampData(t or datetime.now(timezone.utc), quality=time_quality),
        BoolData(test),
        BitStringData(bytes([check]), 6),
    ])


@dataclass
class _Watch:
    """InformationReports about one control object, collected on the receive thread."""

    obj: ObjectName
    oper: ObjectName
    cond: threading.Condition = field(default_factory=threading.Condition)
    errors: list[LastApplError] = field(default_factory=list)
    terminations: list[Optional[LastApplError]] = field(default_factory=list)  # None = positive

    def _concerns(self, error: LastApplError) -> bool:
        prefix = str(self.obj)
        return error.control_object == prefix or error.control_object.startswith(prefix + "$")

    def __call__(self, report: InformationReport) -> None:
        if report.list_name is not None:
            return
        error = None
        for name, result in zip(report.variables, report.results):
            if name == LAST_APPL_ERROR and not isinstance(result, DataAccessError):
                try:
                    error = LastApplError.from_data(result)
                except ValueError:
                    continue
        if error is not None and not self._concerns(error):
            return
        with self.cond:
            if self.oper in report.variables:
                self.terminations.append(error)
            elif error is not None:
                self.errors.append(error)
            else:
                return
            self.cond.notify_all()

    def last_error(self, grace: float) -> Optional[LastApplError]:
        """LastApplError precedes the negative response; allow a short delay anyway."""
        with self.cond:
            self.cond.wait_for(lambda: bool(self.errors), timeout=grace)
            return self.errors[-1] if self.errors else None

    def termination(self, timeout: float) -> Optional[list[Optional[LastApplError]]]:
        with self.cond:
            if not self.cond.wait_for(lambda: bool(self.terminations), timeout=timeout):
                return None
            return list(self.terminations)


def _write(client: MmsClient, watch: _Watch, stage: str, name: ObjectName, value: IECData, grace: float) -> None:
    try:
        client.write(name, value)
    except DataAccessError as exc:
        raise ControlError(stage, f"write refused ({exc})", watch.last_error(grace)) from exc


def operate(
    client: MmsClient,
    name: Name,
    ctl_val: CtlValue,
    *,
    origin: Origin = Origin(),
    ctl_num: int = 0,
    test: bool = False,
    interlock_check: bool = True,
    synchro_check: bool = True,
    ctl_model: Optional[int] = None,
    termination_timeout: float = 5.0,
    error_grace: float = 0.5,
    oper_tm: Optional[datetime] = None,
) -> ControlResult:
    """Run one command on ``name`` (``X$CO$Pos``, ``X$CO$Pos$Oper`` or ``LD/X.Pos``).

    ``ctl_model`` is read from ``X$CF$Pos$ctlModel`` when not given;
    ``oper_tm`` makes a time-activated command (an Oper with operTm). Raises
    :class:`ControlError` when the server refuses the command or reports a
    negative CommandTermination, or when no termination arrives in time.
    """
    obj = control_object_name(name)
    if ctl_model is None:
        ctl_model = read_ctl_model(client, obj)
    if ctl_model not in CTL_MODELS or ctl_model == CTL_MODEL_STATUS_ONLY:
        raise ControlError("check", f"{obj} cannot be operated (ctlModel {ctl_model})")

    oper = _attribute(obj, "Oper")
    watch = _Watch(obj, oper)
    client.add_report_listener(watch)
    start = time.monotonic()
    try:
        def value() -> StructureData:
            return oper_value(
                ctl_val, origin=origin, ctl_num=ctl_num, test=test,
                interlock_check=interlock_check, synchro_check=synchro_check, oper_tm=oper_tm,
            )

        if ctl_model == CTL_MODEL_SBO_NORMAL:
            try:
                selected = client.read(_attribute(obj, "SBO"))
            except DataAccessError as exc:
                raise ControlError("select", f"read of SBO refused ({exc})", watch.last_error(error_grace)) from exc
            if not (isinstance(selected, VisibleStringData) and selected.value):
                raise ControlError("select", "the server did not select the object")
        elif ctl_model == CTL_MODEL_SBO_ENHANCED:
            _write(client, watch, "select", _attribute(obj, "SBOw"), value(), error_grace)

        _write(client, watch, "operate", oper, value(), error_grace)

        terminated = False
        if ctl_model in (CTL_MODEL_DIRECT_ENHANCED, CTL_MODEL_SBO_ENHANCED):
            terminations = watch.termination(termination_timeout)
            if terminations is None:
                raise ControlError("termination", f"no CommandTermination within {termination_timeout:g} s")
            if terminations[0] is not None:
                raise ControlError("termination", "negative CommandTermination", terminations[0])
            terminated = True
        return ControlResult(ctl_model, ctl_num & 0xFF, terminated, time.monotonic() - start)
    finally:
        client.remove_report_listener(watch)
