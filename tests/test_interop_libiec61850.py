# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Interoperability with libiec61850's example servers and publishers.

Run by ``tools/interop/run.sh`` (Docker, and CI): the example programs are
on the PATH there. Elsewhere these tests skip. The GOOSE and SV tests
capture on ``lo`` and need Linux and root.

- ``server_example_basic_io`` (port 10102): model, reads, types, reports;
- ``server_example_control`` (port 10103): GGIO1.SPCSO1..4 in the four
  control models, SPCSO9 whose handler refuses every command;
- ``server_example_goose`` (port 102, GOOSE on ``lo``): gcbEvents and
  gcbAnalogValues, whose AnIn1 changes every second;
- ``sv_publisher_example lo``: two ASDUs (svpub1, svpub2) every 50 ms;
- ``goose_subscriber_example lo``: prints what it receives for
  simpleIOGenericIO/LLN0$GO$gcbAnalogValues (APPID 1000), which our
  GoosePublisher sends.
"""

from __future__ import annotations

import os
import queue
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator

import pytest

from open61850.data import FloatData
from open61850.mms import (
    ControlError,
    MmsClient,
    ObjectName,
    decode_report,
    discover,
    is_report,
    operate,
    rcb,
)
from open61850.mms.types import describe

pytestmark = pytest.mark.skipif(
    shutil.which("server_example_basic_io") is None, reason="libiec61850 examples not installed (tools/interop/run.sh)"
)
needs_raw = pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.geteuid() != 0, reason="capture on lo needs Linux and root"
)

LD = "simpleIOGenericIO"
BASIC_IO, CONTROL = 10102, 10103


def _wait_port(port: int, timeout: float = 5.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nothing listens on port {port}")


def _server(*command: str, port: int) -> Iterator[None]:
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_port(port)
        yield
    finally:
        process.terminate()
        process.wait(5)


@pytest.fixture(scope="module")
def basic_io() -> Iterator[None]:
    yield from _server("server_example_basic_io", str(BASIC_IO), port=BASIC_IO)


@pytest.fixture(scope="module")
def control_server() -> Iterator[None]:
    yield from _server("server_example_control", str(CONTROL), port=CONTROL)


def test_association(basic_io) -> None:
    with MmsClient.connect("127.0.0.1", BASIC_IO) as client:
        association = client.association
        assert association is not None
        assert association.max_outstanding_calling >= 1 and association.nesting_level >= 5


def test_model_discovery_and_references(basic_io) -> None:
    with MmsClient.connect("127.0.0.1", BASIC_IO) as client:
        model = discover(client, types=True)
        assert list(model.logical_devices) == [LD]
        assert set(model.logical_devices[LD].logical_nodes) == {"LLN0", "LPHD1", "GGIO1"}
        ref = model.resolve(f"{LD}/GGIO1.AnIn1.mag.f")
        assert str(ref) == f"{LD}/GGIO1.AnIn1.mag.f [MX]"
        ggio = model.logical_node(LD, "GGIO1")
        assert describe(ggio.type_of(ref)) == "float32"
        assert "SPCSO1" in ggio.data_objects()
        lln0 = model.logical_node(LD, "LLN0")
        blocks = {str(b) for b in lln0.control_blocks()}
        assert f"{LD}/LLN0.EventsRCB01 [RP]" in blocks and f"{LD}/LLN0.Measurements01 [BR]" in blocks
        assert {"Events", "Measurements"} <= set(lln0.data_sets)

        value = client.read(ref)
        assert isinstance(value, FloatData)
        assert client.read_many([ref, f"{LD}/LLN0$ST$Mod$stVal", f"{LD}/GGIO1.NamPlt.vendor[DC]"])[1].value == 1
        members = client.get_data_set_members(f"{LD}/LLN0.Measurements")
        assert ObjectName("GGIO1$MX$AnIn1$mag$f", LD) in members


def test_buffered_report(basic_io) -> None:
    reports: queue.Queue = queue.Queue()
    with MmsClient.connect("127.0.0.1", BASIC_IO, on_information_report=reports.put) as client:
        instances = [ObjectName(f"LLN0$BR$Measurements0{i}", LD) for i in (1, 2, 3)]
        free = rcb.find_free(client, instances)
        assert free is not None and free.dat_set == f"{LD}/LLN0$Measurements"
        rcb.enable(client, free.rcb, rcb.RcbSettings(intg_pd_ms=500, purge_buf=True))
        try:
            end = time.monotonic() + 5
            decoded = []
            while time.monotonic() < end and len(decoded) < 3:
                try:
                    message = reports.get(timeout=0.5)
                except queue.Empty:
                    continue
                if is_report(message):
                    decoded.append(decode_report(message))
            assert len(decoded) >= 3
            assert all(r.rpt_id and r.entries for r in decoded)
            seq = [r.seq_num for r in decoded]
            assert seq == sorted(seq)
        finally:
            rcb.disable(client, free.rcb)
        assert rcb.read_status(client, free.rcb).rpt_ena is False


@pytest.mark.parametrize("do, model", [
    ("SPCSO1", "direct-with-normal-security"),
    ("SPCSO2", "sbo-with-normal-security"),
    ("SPCSO3", "direct-with-enhanced-security"),
    ("SPCSO4", "sbo-with-enhanced-security"),
])
def test_control_models(control_server, do: str, model: str) -> None:
    with MmsClient.connect("127.0.0.1", CONTROL) as client:
        for value in (True, False):
            result = operate(client, f"{LD}/GGIO1.{do}", value)
            assert str(result).startswith(model)
            assert result.terminated == ("enhanced" in model)
            assert client.read(f"{LD}/GGIO1.{do}.stVal[ST]").value is value


def test_refused_control_reports_the_cause(control_server) -> None:
    with MmsClient.connect("127.0.0.1", CONTROL) as client:
        with pytest.raises(ControlError) as refused:
            operate(client, f"{LD}/GGIO1.SPCSO9", True)
        assert refused.value.last_appl_error is not None


def test_browse_command_line(basic_io) -> None:
    out = subprocess.run(
        [sys.executable, "-m", "open61850.mms", f"127.0.0.1:{BASIC_IO}", "browse", f"{LD}/GGIO1", "--flat", "--types"],
        capture_output=True, text=True, check=True, env={**os.environ, "PYTHONPATH": "src"},
    ).stdout.splitlines()
    assert f"{LD}/GGIO1.AnIn1.mag.f [MX] float32" in out
    assert f"{LD}/GGIO1.SPCSO1.Oper.ctlVal [CO] boolean" in out


def _capture(seconds: float, ethertype: int):
    from open61850.capture import PacketCapture

    frames = []
    with PacketCapture("lo", (ethertype,), outgoing=False) as cap:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            frame = cap.recv()
            if frame is not None:
                frames.append(frame)
    return frames


@needs_raw
def test_goose_publisher_supervised() -> None:
    from open61850 import goose
    from open61850.ethernet import ETHERTYPE_GOOSE
    from open61850.supervision import EventKind, GooseSupervisor

    process = subprocess.Popen(["server_example_goose", "--ifc", "lo"], stdout=subprocess.DEVNULL)
    try:
        _wait_port(102)
        frames = _capture(3.5, ETHERTYPE_GOOSE)
    finally:
        process.terminate()
        process.wait(5)
    sup = GooseSupervisor()
    events = []
    for frame in frames:
        decoded = goose.decode_goose_frame(frame.data)
        assert decoded is not None
        events += sup.feed(decoded[1], frame.timestamp, decoded[0])
    assert set(sup.streams) == {f"{LD}/LLN0$GO$gcbEvents", f"{LD}/LLN0$GO$gcbAnalogValues"}
    analog = sup.streams[f"{LD}/LLN0$GO$gcbAnalogValues"]
    assert analog.app_id == 0x1000 and analog.last.conf_rev == 2
    assert analog.events[EventKind.STATE_CHANGE] >= 2  # AnIn1 changes every second
    kinds = {e.kind for e in events}
    assert not kinds & {EventKind.GAP, EventKind.DUPLICATE, EventKind.OUT_OF_ORDER, EventKind.RESTART,
                        EventKind.DATA_WITHOUT_STATE_CHANGE, EventKind.INCONSISTENT}


@needs_raw
def test_sv_publisher_supervised() -> None:
    from open61850 import sv
    from open61850.ethernet import ETHERTYPE_SV
    from open61850.supervision import EventKind, SvSupervisor

    process = subprocess.Popen(["sv_publisher_example", "lo"], stdout=subprocess.DEVNULL)
    try:
        frames = _capture(2.0, ETHERTYPE_SV)
    finally:
        process.terminate()
        process.wait(5)
    assert len(frames) >= 20  # one frame every 50 ms
    sup = SvSupervisor(timeout=0.5)
    events = []
    for frame in frames:
        eth, pdu = sv.decode_sv_frame(frame.data)
        assert [a.sv_id for a in pdu.asdus] == ["svpub1", "svpub2"]
        assert len(pdu.asdus[0].sample) == 4 + 4 + 8  # two FLOAT32 and a timestamp
        events += sup.feed(pdu, frame.timestamp, eth)
    assert {e.kind for e in events} == {EventKind.NEW_STREAM}
    assert sup.streams["svpub1"].samples == len(frames)


@needs_raw
def test_libiec61850_subscribes_to_our_goose() -> None:
    import re
    import signal

    from open61850.data import BoolData
    from open61850.goose_publisher import GooseControl, GoosePublisher

    subscriber = subprocess.Popen(["goose_subscriber_example", "lo"], stdout=subprocess.PIPE, text=True)
    control = GooseControl(f"{LD}/LLN0$GO$gcbAnalogValues", f"{LD}/LLN0$AnalogValues", app_id=1000,
                           dst_mac="01:0c:cd:01:00:01", src_mac="02:00:00:00:00:01", min_time_ms=20, max_time_ms=200)
    try:
        time.sleep(0.5)  # the receiver thread starts
        with GoosePublisher("lo", control, [FloatData(1.5), BoolData(False)]) as publisher:
            publisher.start()
            time.sleep(0.5)
            publisher.publish([FloatData(-2.25), BoolData(True)])
            time.sleep(0.5)
    finally:
        subscriber.send_signal(signal.SIGINT)  # a clean exit flushes its output
        out, _ = subscriber.communicate(timeout=5)
    # On lo every frame arrives twice: libiec61850 flags the second copy (same sqNum) INVALID.
    first: dict[tuple[int, int], tuple[bool, str, int]] = {}
    for block in out.split("GOOSE event:")[1:]:
        st, sq = (int(x) for x in re.search(r"stNum: (\d+) sqNum: (\d+)", block).groups())
        valid = "message is valid" in block
        data = re.search(r"allData: (.*)", block).group(1)
        ttl = int(re.search(r"timeToLive: (\d+)", block).group(1))
        first.setdefault((st, sq), (valid, data, ttl))
    assert (1, 0) in first and (2, 3) in first  # repetitions 20, 40, 80 ms after the change
    assert all(valid for valid, _data, _ttl in first.values())
    assert first[(1, 0)][1] == "{1.500000,false}" and first[(2, 0)][1] == "{-2.250000,true}"
    assert [first[(2, n)][2] for n in range(4)] == [60, 120, 240, 480]
