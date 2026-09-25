# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The MMS server (open61850.server), with the open61850 client on loopback.

tests/test_interop_libiec61850.py runs libiec61850's clients against it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from conftest import DATA_DIR

from open61850 import ber, scl
from open61850.data import BoolData, IntData, OctetStringData, VisibleStringData
from open61850.mms import (
    OBJECT_CLASS_DOMAIN,
    OBJECT_CLASS_NAMED_VARIABLE,
    OBJECT_CLASS_NAMED_VARIABLE_LIST,
    DataAccessError,
    MmsClient,
    MmsReject,
    ObjectName,
    ServiceError,
    discover,
    pdu,
)
from open61850.mms.model import compare
from open61850.mms.types import PrimitiveType, StructureType
from open61850.server import IedModel, MmsServer

SCD = DATA_DIR / "goose_sv.scd.xml"
PROT = "IED01_Protection"


@pytest.fixture
def model() -> IedModel:
    return IedModel.from_scl(SCD)


@pytest.fixture
def server(model: IedModel) -> Iterator[MmsServer]:
    with MmsServer(model, "127.0.0.1", 0) as srv:
        srv.start()
        yield srv


def test_model_from_scl(model: IedModel) -> None:
    assert list(model.logical_devices) == [PROT, "IED01MU"]
    lln0 = model.node(f"{PROT}/LLN0")
    assert [fc for fc in lln0.children] == ["ST", "CO", "CF", "BR", "GO"]  # libiec61850's order
    assert model.get(f"{PROT}/LLN0.brcbTrip01.RptID[BR]") == VisibleStringData(f"{PROT}/LLN0$BR$brcbTrip01")
    assert model.get(f"{PROT}/LLN0$BR$brcbTrip02$DatSet") == VisibleStringData(f"{PROT}/LLN0$DS_TRIP")
    assert model.get(f"{PROT}/LLN0$GO$gcbTrip$GoID") == VisibleStringData("TRIP_GOOSE")
    assert model.data_sets[ObjectName("LLN0$DS_TRIP", PROT)] == [
        ObjectName("PTRC1$ST$Tr$general", PROT), ObjectName("IMMXU1$MX$A$phsA", "IED01MU")]
    assert model.node(f"{PROT}/PTRC1$ST$Tr$general").triggers == frozenset({"dchg"})
    with pytest.raises(KeyError):
        model.get(f"{PROT}/LLN0$ST$Nope")


def test_set_checks_types_and_notifies(model: IedModel) -> None:
    seen = []
    model.add_listener(lambda nodes: seen.append([n.item for n in nodes]))
    model.set(f"{PROT}/PTRC1.Tr.general[ST]", True)
    model.set(f"{PROT}/PTRC1.Tr.general[ST]", True)  # no change, no notification
    model.set("IED01MU/IMMXU1.A.phsA.cVal.mag.f[MX]", 12.5)
    assert seen == [["PTRC1$ST$Tr$general"], ["IMMXU1$MX$A$phsA$cVal$mag$f"]]
    with pytest.raises(TypeError):
        model.set(f"{PROT}/PTRC1.Tr.general[ST]", VisibleStringData("x"))
    with pytest.raises(TypeError):
        model.set(f"{PROT}/PTRC1.Tr.q[ST]", OctetStringData(b"x"))


def test_association_names_and_model(server: MmsServer) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as client:
        association = client.association
        assert association is not None and association.max_pdu_size == 65000 and association.supports(4)
        assert client.get_name_list(OBJECT_CLASS_DOMAIN) == ["IED01MU", PROT]
        assert client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE_LIST, PROT) == ["LLN0$DS_TRIP"]
        assert compare(scl.load_model(SCD), discover(client, types=True)) == []
        with pytest.raises(ServiceError):
            client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE, "NO_SUCH_LD")


def test_name_list_pages(model: IedModel) -> None:
    with MmsServer(model, "127.0.0.1", 0, max_pdu_size=300) as server:
        server.start()
        with MmsClient.connect("127.0.0.1", server.port) as client:
            names = client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE, PROT)  # several pages, continueAfter
    assert names == model.names(PROT) and len(names) > 40


def test_read_write_rules(server: MmsServer, model: IedModel) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as client:
        model.set(f"{PROT}/PTRC1.Tr.general[ST]", True)
        results = client.read_many([f"{PROT}/PTRC1.Tr.general[ST]", f"{PROT}/PTRC1$ST$Nope", f"{PROT}/LLN0.Mod.stVal[ST]"])
        assert results[0] == BoolData(True) and isinstance(results[1], DataAccessError) and results[1].code == 10
        errors = client.write_many([f"{PROT}/LLN0$CF$Mod$ctlModel", f"{PROT}/LLN0$ST$Mod$stVal", f"{PROT}/LLN0$CF$Mod$ctlModel"],
                                   [IntData(4), IntData(1), BoolData(True)])
        assert errors[0] is None
        assert [e.code for e in errors[1:]] == [3, 7]  # access denied (ST), type inconsistent
        assert client.read(f"{PROT}/LLN0.Mod.ctlModel[CF]") == IntData(4)
        assert client.get_data_set_members(f"{PROT}/LLN0.DS_TRIP")[1] == ObjectName("IMMXU1$MX$A$phsA", "IED01MU")
        mod = client.get_type(f"{PROT}/LLN0$ST$Mod")
        assert mod == StructureType([("stVal", PrimitiveType("integer", 8)), ("q", PrimitiveType("bit-string", -13))])
        with pytest.raises(ServiceError):
            client.get_type(f"{PROT}/LLN0$ST$Nope")


def test_raw_services(server: MmsServer, model: IedModel) -> None:
    """Read of a data set by its list name, Identify, an unknown service, Conclude."""
    with MmsClient.connect("127.0.0.1", server.port) as client:
        list_name = ber.encode_tlv(0xA1, pdu.encode_object_name(ObjectName("LLN0$DS_TRIP", PROT)))
        read = ber.encode_tlv(0xA4, ber.encode_tlv(0x80, b"\xff") + ber.encode_tlv(0xA1, list_name))
        response = client.request(read)
        assert response.service == pdu.SERVICE_READ
        assert len(pdu.read_response(response.content)) == 2
        identify = client.request(ber.encode_tlv(0x82))
        fields = {t.tag: t.value for t in ber.iter_tlvs(identify.content)}
        assert fields[0x80] == b"open61850" and fields[0x82].decode() == __import__("open61850").__version__
        with pytest.raises(MmsReject):
            client.request(ber.encode_tlv(0xBF48, b""))  # fileOpen: not served
        assert client.read(f"{PROT}/LLN0.Mod.stVal[ST]") == IntData(0)  # still usable after a reject


def test_server_stop_closes_clients(model: IedModel) -> None:
    server = MmsServer(model, "127.0.0.1", 0)
    server.start()
    client = MmsClient.connect("127.0.0.1", server.port)
    assert len(server.connections) == 1
    server.stop()
    assert client.wait_closed(5) is not None or not client.is_connected
    client.close()


# --- reports -----------------------------------------------------------------------

import queue  # noqa: E402
import time  # noqa: E402

from open61850.mms import decode_report, rcb  # noqa: E402

BRCBS = [ObjectName(f"LLN0$BR$brcbTrip0{i}", PROT) for i in (1, 2)]
TRIP = f"{PROT}/PTRC1.Tr.general[ST]"


def _reports(q: queue.Queue, wait: float = 0.3) -> list:
    time.sleep(wait)
    out = []
    while not q.empty():
        out.append(decode_report(q.get()))
    return out


def _reasons(report) -> list[list[str]]:
    return [[k for k, v in vars(e.reason).items() if v] for e in report.entries]


def test_brcb_gi_change_integrity_and_release(server: MmsServer, model: IedModel) -> None:
    q: queue.Queue = queue.Queue()
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        free = rcb.find_free(client, BRCBS)
        assert free.rcb == BRCBS[0]
        rcb.enable(client, free.rcb, rcb.RcbSettings(intg_pd_ms=300, purge_buf=True))
        (gi,) = _reports(q, 0.1)
        assert gi.rpt_id == f"{PROT}/LLN0$BR$brcbTrip01" and _reasons(gi) == [["general_interrogation"]] * 2
        model.set(TRIP, True)
        model.set(f"{PROT}/PTRC1.Tr.q[ST]", 0x0800)  # q is not in the data set: nothing
        (change,) = _reports(q, 0.1)
        assert [(e.index, e.value) for e in change.entries] == [(0, BoolData(True))] and _reasons(change) == [["data_change"]]
        integrity = _reports(q, 0.35)
        assert integrity and _reasons(integrity[0]) == [["integrity"]] * 2
        seq = [gi.seq_num, change.seq_num, integrity[0].seq_num]
        assert seq == [0, 1, 2] and int.from_bytes(change.entry_id, "big") == int.from_bytes(gi.entry_id, "big") + 1
        with MmsClient.connect("127.0.0.1", server.port) as other:
            with pytest.raises(rcb.RcbError):  # reserved by the first client
                rcb.enable(other, free.rcb)
            assert rcb.find_free(other, BRCBS).rcb == BRCBS[1]
            with pytest.raises(DataAccessError):  # configuration is frozen while enabled
                client.write(f"{PROT}/LLN0$BR$brcbTrip01$IntgPd", __import__("open61850").data.UIntData(1000))
        rcb.disable(client, free.rcb)
    status = model.get(f"{PROT}/LLN0$BR$brcbTrip01$RptEna")
    assert status == BoolData(False)


def test_buftm_gathers_changes(server: MmsServer, model: IedModel) -> None:
    q: queue.Queue = queue.Queue()
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, buf_tm_ms=150, general_interrogation=False))
        model.set(TRIP, True)
        model.set("IED01MU/IMMXU1.A.phsA.q[MX]", 0x0800)  # no qchg on this q in the SCL: not reported
        model.set(TRIP, False)  # the same member again: the first entry goes at once
        reports = _reports(q, 0.3)
        assert [[(e.index, e.value) for e in r.entries] for r in reports] == [[(0, BoolData(True))], [(0, BoolData(False))]]


def test_buffered_entries_replayed_from_entry_id(server: MmsServer, model: IedModel) -> None:
    q: queue.Queue = queue.Queue()
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, purge_buf=True, resv_tms=2))
        (gi,) = _reports(q, 0.1)
    # the client is gone; the block keeps buffering and stays reserved for its address
    model.set(TRIP, True)
    model.set(TRIP, False)
    with MmsClient.connect("127.0.0.1", server.port, on_information_report=q.put) as client:
        settings = rcb.RcbSettings(intg_pd_ms=0, entry_id=gi.entry_id, general_interrogation=False)
        rcb.enable(client, BRCBS[0], settings)  # same address: its reservation
        replay = _reports(q, 0.2)
        assert [r.entries[0].value for r in replay] == [BoolData(True), BoolData(False)]
        rcb.disable(client, BRCBS[0])
        client.write(f"{PROT}/LLN0$BR$brcbTrip01$PurgeBuf", BoolData(True))
        rcb.enable(client, BRCBS[0], rcb.RcbSettings(intg_pd_ms=0, entry_id=bytes(8), general_interrogation=False))
        assert _reports(q, 0.2) == []  # purged


def test_disconnect_disables_the_block(server: MmsServer, model: IedModel) -> None:
    client = MmsClient.connect("127.0.0.1", server.port)
    rcb.enable(client, BRCBS[1], rcb.RcbSettings(intg_pd_ms=0, resv_tms=0, general_interrogation=False))
    assert model.get(f"{PROT}/LLN0$BR$brcbTrip02$RptEna") == BoolData(True)
    client.close()
    deadline = time.monotonic() + 2
    while model.get(f"{PROT}/LLN0$BR$brcbTrip02$RptEna") == BoolData(True) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert model.get(f"{PROT}/LLN0$BR$brcbTrip02$RptEna") == BoolData(False)
    with MmsClient.connect("127.0.0.1", server.port) as other:
        assert rcb.find_free(other, [BRCBS[1]]) is not None  # ResvTms 0: released at once


# --- command line --------------------------------------------------------------------


def test_server_command_line() -> None:
    import os
    import re
    import subprocess
    import sys

    from conftest import ROOT

    process = subprocess.Popen(
        [sys.executable, "-m", "open61850.server", str(SCD), "--host", "127.0.0.1", "--port", "0", "--duration", "10"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    try:
        banner = process.stderr.readline()
        port = int(re.search(r":(\d+)$", banner.strip()).group(1))
        assert banner.startswith("open61850-server: IED01 (IED01_Protection, IED01MU) on 127.0.0.1:")
        process.stdin.write(f"{TRIP} true\nIED01MU/IMMXU1.A.phsA.cVal.mag.f[MX] 42.5\n{PROT}/NOPE[ST] 1\n")
        process.stdin.flush()
        assert process.stdout.readline().strip() == f"{TRIP} = bool(True)"
        assert process.stdout.readline().strip().endswith("= float32(42.5)")
        assert "no " in process.stderr.readline()
        with MmsClient.connect("127.0.0.1", port) as client:
            assert client.read(TRIP) == BoolData(True)
    finally:
        process.terminate()
        process.wait(10)
