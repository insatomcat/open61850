# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850.mms.control: Oper encoding checked on a capture, control models against a fake IED."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from typing import Optional

import pytest
from conftest import DATA_DIR
from test_mms import FakeModel, FakeServer, serve  # noqa: F401 - fixture

from open61850 import ber
from open61850.data import (
    BoolData,
    IECData,
    IntData,
    OctetStringData,
    StructureData,
    UIntData,
    VisibleStringData,
    decode_data_sequence,
    encode_data,
)
from open61850.mms import MmsClient, ObjectName, pdu
from open61850.mms import control
from open61850.mms.control import ControlError, LastApplError, Origin, operate

CAPTURE = json.loads((DATA_DIR / "iedscout_reports_control.json").read_text())
LD = "IED01_BayLD"
POS = ObjectName("CBCSWI1$CO$Pos", LD)
OPER = ObjectName("CBCSWI1$CO$Pos$Oper", LD)


def _captured_oper() -> tuple[bytes, StructureData]:
    request = ber.decode_tlv(pdu.unwrap(bytes.fromhex(CAPTURE["oper_write_req"])))
    service = list(ber.iter_tlvs(request.value))[1]
    data = list(ber.iter_tlvs(service.value))[1]
    (value,) = decode_data_sequence(data.value)
    assert isinstance(value, StructureData)
    return data.value, value  # listOfData holds the one Oper structure


def test_oper_value_matches_iedscout() -> None:
    raw, captured = _captured_oper()
    t = captured.members[3]
    value = control.oper_value(
        True, origin=Origin(2, bytes.fromhex("13d5c007")), ctl_num=0, t=t.value, time_quality=t.quality  # type: ignore[attr-defined]
    )
    assert value == captured
    # Same bytes except TRUE (IEDscout sends 01, the library ff as in DER; the VMC7
    # accepts both) and the 24-bit fraction of T, which datetime rounds to 1 us.
    expected = bytes.fromhex("a2228301ff") + raw[5:]
    encoded = encode_data(value)
    fraction = slice(25, 28)
    assert raw[fraction] == bytes.fromhex("002440")
    assert encoded[:25] + encoded[28:] == expected[:25] + expected[28:]


def test_oper_value_fields() -> None:
    value = control.oper_value(False, ctl_num=260, test=True, interlock_check=False, synchro_check=True)
    ctl_val, origin, ctl_num, t, test, check = value.members
    assert ctl_val == BoolData(False)
    assert origin == StructureData([IntData(2), OctetStringData(b"")])  # station-control by default
    assert ctl_num == UIntData(4)
    assert test == BoolData(True)
    assert check.value == b"\x80" and check.unused_bits == 6  # type: ignore[attr-defined]
    assert t.quality == control.DEFAULT_TIME_QUALITY  # type: ignore[attr-defined]


def test_names() -> None:
    assert control.control_object_name(OPER) == POS
    assert control.control_object_name(POS) == POS
    assert control.ctl_model_name(POS) == ObjectName("CBCSWI1$CF$Pos$ctlModel", LD)
    with pytest.raises(ValueError):
        control.ctl_model_name(ObjectName("CBCSWI1$ST$Pos", LD))


def _last_appl_error(add_cause: int, obj: str = f"{LD}/CBCSWI1$CO$Pos$Oper", error: int = 1) -> bytes:
    return encode_data(StructureData([
        VisibleStringData(obj), IntData(error),
        StructureData([IntData(2), OctetStringData(b"po")]), UIntData(0), IntData(add_cause),
    ]))


def _report(names: list[ObjectName], values: list[bytes]) -> bytes:
    body = pdu._variable_list(names) + ber.encode_tlv(0xA0, b"".join(values))
    return ber.encode_tlv(0xA3, ber.encode_tlv(0xA0, body))


class ControlIed(FakeModel):
    """A breaker with a configurable control model and scripted reactions to Oper."""

    def __init__(self, ctl_model: int, on_oper: Optional[Callable[[FakeServer, IECData], Optional[bytes]]] = None) -> None:
        super().__init__({"CBCSWI1$CF$Pos$ctlModel": IntData(ctl_model), "CBCSWI1$CO$Pos$SBO": VisibleStringData("")})
        self.on_oper = on_oper

    def __call__(self, invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        if service == pdu.SERVICE_WRITE and self.on_oper is not None:
            spec, data = list(ber.iter_tlvs(content))[:2]
            name = pdu._decode_variable_list(spec.value)[0]
            if name.item.endswith("$Oper"):
                (value,) = decode_data_sequence(data.value)
                self.writes.append((name.item, value))
                response = self.on_oper(server, value)
                server.respond(invoke_id, service, response or bytes.fromhex("8100"))
                return
        super().__call__(invoke_id, service, content, server)


def _terminate(server: FakeServer, _value: IECData) -> None:
    # The write response goes first, the captured CommandTermination 50 ms later.
    threading.Timer(0.05, lambda: server.conn.send(bytes.fromhex(CAPTURE["command_termination"]))).start()


def test_direct_enhanced_waits_for_termination(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    ied = ControlIed(control.CTL_MODEL_DIRECT_ENHANCED, _terminate)
    client, _ = serve(ied)
    result = operate(client, OPER, True, ctl_num=7)
    assert result.terminated and result.ctl_model == 3 and result.ctl_num == 7
    assert result.duration >= 0.04
    assert [name for name, _ in ied.writes] == ["CBCSWI1$CO$Pos$Oper"]
    assert ied.writes[0][1].members[0] == BoolData(True)  # type: ignore[attr-defined]


def test_refused_oper_carries_last_appl_error(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    def refuse(server: FakeServer, _value: IECData) -> bytes:
        server.send_mms(_report([control.LAST_APPL_ERROR], [_last_appl_error(10)]))
        return bytes.fromhex("800103")  # object-access-denied

    client, _ = serve(ControlIed(control.CTL_MODEL_DIRECT_ENHANCED, refuse))
    with pytest.raises(ControlError) as info:
        operate(client, POS, False)
    assert info.value.stage == "operate"
    error = info.value.last_appl_error
    assert error is not None and error.add_cause == 10 and error.add_cause_name == "blocked-by-interlocking"
    assert error.origin == Origin(2, b"po")


def test_negative_termination(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    def abort(server: FakeServer, value: IECData) -> None:
        report = _report([control.LAST_APPL_ERROR, OPER], [_last_appl_error(16), encode_data(value)])
        threading.Timer(0.05, lambda: server.send_mms(report)).start()

    client, _ = serve(ControlIed(control.CTL_MODEL_DIRECT_ENHANCED, abort))
    with pytest.raises(ControlError, match="time-limit-over") as info:
        operate(client, POS, True)
    assert info.value.stage == "termination"


def test_missing_termination_times_out(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    client, _ = serve(ControlIed(control.CTL_MODEL_DIRECT_ENHANCED, lambda *_: None))
    with pytest.raises(ControlError, match="no CommandTermination"):
        operate(client, POS, True, termination_timeout=0.2)


def test_other_objects_are_ignored(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    def noise(server: FakeServer, _value: IECData) -> None:
        other = f"{LD}/CBCSWI10$CO$Pos$Oper"  # shares the prefix
        server.send_mms(_report([control.LAST_APPL_ERROR], [_last_appl_error(12, other)]))
        _terminate(server, _value)

    client, _ = serve(ControlIed(control.CTL_MODEL_DIRECT_ENHANCED, noise))
    assert operate(client, POS, True).terminated


def test_direct_normal_does_not_wait(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    client, _ = serve(ControlIed(control.CTL_MODEL_DIRECT_NORMAL, lambda *_: None))
    result = operate(client, POS, True, termination_timeout=5)
    assert not result.terminated and result.duration < 1


def test_sbo_enhanced_selects_first(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    ied = ControlIed(control.CTL_MODEL_SBO_ENHANCED, _terminate)
    client, _ = serve(ied)
    assert operate(client, POS, False, ctl_num=3).terminated
    assert [name for name, _ in ied.writes] == ["CBCSWI1$CO$Pos$SBOw", "CBCSWI1$CO$Pos$Oper"]
    sbow, oper = (value for _, value in ied.writes)
    assert sbow.members[2] == oper.members[2] == UIntData(3)  # type: ignore[attr-defined]


def test_sbo_normal_needs_a_selection(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    ied = ControlIed(control.CTL_MODEL_SBO_NORMAL, lambda *_: None)
    client, _ = serve(ied)
    with pytest.raises(ControlError, match="select"):
        operate(client, POS, True)
    ied.values["CBCSWI1$CO$Pos$SBO"] = VisibleStringData(f"{LD}/CBCSWI1$CO$Pos")
    assert not operate(client, POS, True).terminated
    assert [name for name, _ in ied.writes] == ["CBCSWI1$CO$Pos$Oper"]


def test_status_only_is_refused(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:  # noqa: F811
    client, _ = serve(ControlIed(control.CTL_MODEL_STATUS_ONLY))
    with pytest.raises(ControlError, match="cannot be operated"):
        operate(client, POS, True)


def test_last_appl_error_decoding() -> None:
    (value,) = decode_data_sequence(_last_appl_error(12))
    error = LastApplError.from_data(value)
    assert str(error) == f"{LD}/CBCSWI1$CO$Pos$Oper: unknown, AddCause 12 (command-already-in-execution), ctlNum 0"
