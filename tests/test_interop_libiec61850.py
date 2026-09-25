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


SCL_DIR = "/usr/local/share/libiec61850"


@pytest.mark.parametrize("cid, port", [("simpleIO_direct_control.cid", BASIC_IO), ("simpleIO_control_tests.cid", CONTROL)])
def test_scl_model_matches_the_server(basic_io, control_server, cid: str, port: int) -> None:
    from open61850.mms.model import compare
    from open61850.scl import load_model

    expected = load_model(f"{SCL_DIR}/{cid}")
    with MmsClient.connect("127.0.0.1", port) as client:
        live = discover(client)
    assert compare(expected, live) == []
    assert sum(len(n.references()) for n in live.logical_nodes()) > 100


def test_scl_goose_and_sv_blocks() -> None:
    from open61850.scl import load_ieds

    (ied,) = load_ieds(f"{SCL_DIR}/simpleIO_direct_control_goose.cid")
    analog = next(g for g in ied.goose_controls if g.name == "gcbAnalogValues")
    control = analog.goose_control("02:00:00:00:00:01")
    # what server_example_goose sends (test_goose_publisher_supervised): APPID 0x1000, confRev 2
    assert (control.gocb_ref, control.app_id, control.conf_rev, control.go_id) == (
        f"{LD}/LLN0$GO$gcbAnalogValues", 0x1000, 2, "analog")
    assert (control.dst_mac, control.vlan_id, control.vlan_priority) == ("01:0c:cd:01:00:01", 1, 4)
    events = next(g for g in ied.goose_controls if g.name == "gcbEvents")
    assert (events.address.min_time_ms, events.address.max_time_ms) == (1000, 3000)
    (mu,) = load_ieds(f"{SCL_DIR}/sv.icd")
    (msvcb,) = mu.sv_controls
    assert (msvcb.sv_id, msvcb.smp_rate, msvcb.smp_mod, msvcb.samples_per_second(50)) == ("xxxxMUnn01", 80, "SmpPerPeriod", 4000)
    assert msvcb.address.app_id == 0x1001  # "1001" in the file: hexadecimal


def test_compare_scl_command_line(basic_io) -> None:
    run = subprocess.run(
        [sys.executable, "-m", "open61850.mms", f"127.0.0.1:{BASIC_IO}", "compare-scl", f"{SCL_DIR}/simpleIO_direct_control.cid"],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "src"},
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.startswith("0 differences (1 logical devices, 106 attributes")
    run = subprocess.run(  # the control example's SCL against the basic I/O server: they differ
        [sys.executable, "-m", "open61850.mms", f"127.0.0.1:{BASIC_IO}", "compare-scl", f"{SCL_DIR}/simpleIO_control_tests.cid"],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": "src"},
    )
    assert run.returncode == 1 and "missing attribute" in run.stdout


def _example(name: str, *args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, f"examples/{name}", *args], capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "PYTHONPATH": "src"})


def test_examples_against_the_servers(basic_io, control_server) -> None:
    run = _example("browse_and_read.py", "127.0.0.1", "--port", str(BASIC_IO))
    assert run.returncode == 0, run.stderr
    assert run.stdout.startswith(f"{LD}: LLN0, LPHD1, GGIO1") or run.stdout.startswith(f"{LD}: GGIO1")
    assert f"{LD}/GGIO1.AnIn1.mag.f [MX] = " in run.stdout

    run = _example("operate.py", "127.0.0.1", f"{LD}/GGIO1.SPCSO4", "true", "--port", str(CONTROL))
    assert run.returncode == 0 and run.stdout.startswith("sbo-with-enhanced-security"), run.stdout + run.stderr

    run = _example("check_ied_against_scl.py", "127.0.0.1", f"{SCL_DIR}/simpleIO_direct_control.cid", "--port", str(BASIC_IO))
    assert run.returncode == 0 and run.stdout.strip() == "the IED matches its SCL", run.stdout + run.stderr

    run = _example("subscribe_reports.py", "127.0.0.1", f"{LD}/LLN0$BR$Measurements", "--port", str(BASIC_IO),
                   "--seconds", "3")
    assert run.returncode == 0, run.stderr
    lines = run.stdout.splitlines()
    assert lines[0].startswith(f"enabled {LD}/LLN0$BR$Measurements0") and lines[-1].startswith("released")
    assert len(lines) >= 4  # at least two reports in 3 s (integrity every 2 s, plus the GI)


@needs_raw
def test_publishing_examples_on_lo() -> None:
    from open61850 import goose, sv
    from open61850.capture import PacketCapture

    with PacketCapture("lo", (0x88B8, 0x88BA), outgoing=False) as cap:
        trip = subprocess.Popen([sys.executable, "examples/goose_trip.py", "lo", f"{SCL_DIR}/simpleIO_direct_control_goose.cid",
                                 "gcbAnalogValues", "02:00:00:00:00:01", "--after", "0.5"],
                                env={**os.environ, "PYTHONPATH": "src"}, stdout=subprocess.DEVNULL)
        mu = subprocess.Popen([sys.executable, "examples/merging_unit.py", "lo", "--seconds", "2"],
                              env={**os.environ, "PYTHONPATH": "src"}, stdout=subprocess.DEVNULL)
        frames = []
        end = time.monotonic() + 4.5
        while time.monotonic() < end:
            frame = cap.recv()
            if frame is not None:
                frames.append(frame.data)
        assert trip.wait(10) == 0 and mu.wait(10) == 0
    states = {}
    sv_ids = set()
    for raw in frames:
        if (g := goose.decode_goose_frame(raw)) is not None:
            states.setdefault(g[1].st_num, [d.value for d in g[1].all_data])
        elif (s := sv.decode_sv_frame(raw)) is not None:
            sv_ids.update(a.sv_id for a in s[1].asdus)
    assert states[1] == [False] * 4 and states[2] == [True, False, False, False]  # AnalogValues has 4 members
    assert sv_ids == {"IED01_MU01_SV1"}


# --- libiec61850's clients against the open61850 server -------------------------------

OUR_PORT = 10200


@pytest.fixture
def our_server():
    from open61850.server import IedModel, MmsServer

    model = IedModel.from_scl(f"{SCL_DIR}/simpleIO_direct_control.cid", brcb_resv_tms=True)
    with MmsServer(model, "127.0.0.1", OUR_PORT) as server:
        server.start()
        yield server


def _client(*command: str, timeout: float = 10) -> str:
    try:
        run = subprocess.run(["stdbuf", "-oL", *command], capture_output=True, text=True, timeout=timeout)
        return run.stdout
    except subprocess.TimeoutExpired as exc:  # some examples sleep a minute at the end
        out = exc.stdout or b""
        return out.decode() if isinstance(out, bytes) else out


def test_libiec61850_mms_utility_on_our_server(our_server) -> None:
    out = _client("mms_utility", "-h", "127.0.0.1", "-p", str(OUR_PORT), "-i")
    assert "vendor:\topen61850" in out and "revision:" in out
    out = _client("mms_utility", "-h", "127.0.0.1", "-p", str(OUR_PORT), "-d")
    assert out.strip().splitlines()[-1] == LD


def test_libiec61850_browses_our_server(our_server) -> None:
    out = _client("iec61850_client_example2", "127.0.0.1", str(OUR_PORT))
    assert f"LD: {LD}" in out
    for line in ("LN: GGIO1", "DO: SPCSO1", "DA: ctlModel", "DA: orIdent", "LN: LLN0", "LN: LPHD1"):
        assert line in out, line


def test_libiec61850_reads_and_writes_our_server(our_server) -> None:
    our_server.model.set(f"{LD}/GGIO1.AnIn1.mag.f[MX]", 1.5)
    out = _client("iec61850_client_example1", "127.0.0.1", str(OUR_PORT), timeout=4)
    assert "Connected" in out and "read float value: 1.500000" in out
    assert "failed to write" not in out and "failed to read dataset" not in out
    assert "RptEna = 0" in out
    assert our_server.model.get(f"{LD}/GGIO1.NamPlt.vendor[DC]").value == "libiec61850.com"
