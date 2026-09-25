# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for iec61850.mms: PDUs against IEDscout captures, reports, client and RCBs."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import Optional

import pytest
from conftest import DATA_DIR

from iec61850 import ber
from iec61850.data import (
    BitStringData,
    BoolData,
    IECData,
    IntData,
    OctetStringData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
    encode_data,
)
from iec61850.mms import (
    OBJECT_CLASS_DOMAIN,
    DataAccessError,
    InformationReport,
    MmsClient,
    MmsConnectionError,
    MmsReject,
    MmsTimeout,
    ObjectName,
    OptFlds,
    ReasonCode,
    ServiceError,
    TrgOps,
    association,
    decode_report,
    pdu,
    rcb,
    transport,
)
from iec61850.mms.report import ReportDecodeError, bits_of, bitstring_of

SERVICES = json.loads((DATA_DIR / "iedscout_services.json").read_text())
NAMES = json.loads((DATA_DIR / "iedscout_getnamelist.json").read_text())
ASSOCIATION = json.loads((DATA_DIR / "association_responses.json").read_text())


def _mms(hex_user_data: str) -> bytes:
    return pdu.unwrap(bytes.fromhex(hex_user_data))


def _request_service(hex_user_data: str) -> bytes:
    """The ConfirmedServiceRequest TLV of a captured request."""
    request = ber.decode_tlv(_mms(hex_user_data))
    service = list(ber.iter_tlvs(request.value))[1]
    return ber.encode_tlv(service.tag, service.value)


# --- PDUs against the capture -------------------------------------------------


def test_requests_match_iedscout() -> None:
    assert pdu.get_name_list_request(OBJECT_CLASS_DOMAIN) == _request_service(NAMES["gnl_domains_req"])
    assert pdu.get_name_list_request(0, "IED01_LD0") == _request_service(NAMES["gnl_vars_req"])
    assert pdu.get_named_variable_list_attributes_request(
        ObjectName("LLN0$DS_DATASET1_ABC", "IED01_LD0")
    ) == _request_service(SERVICES["gnvla_req"])
    # IEDscout also sends specificationWithResult = FALSE (80 01 00), the default.
    captured = _request_service(SERVICES["read_req"]).replace(bytes.fromhex("800100"), b"")
    ours = pdu.read_request([ObjectName("LLN0$SP$SGCB$NumOfSG", "IED01_BayLD")])
    assert ours[2:] == captured[2:]


def test_envelope_round_trip() -> None:
    user_data = bytes.fromhex(SERVICES["read_resp"])
    assert pdu.wrap(pdu.unwrap(user_data)) == user_data


def test_decode_responses_from_capture() -> None:
    read = pdu.decode_pdu(_mms(SERVICES["read_resp"]))
    assert isinstance(read, pdu.ConfirmedResponse) and read.service == pdu.SERVICE_READ
    assert pdu.read_response(read.content) == [UIntData(8)]

    gnvla = pdu.decode_pdu(_mms(SERVICES["gnvla_resp"]))
    assert isinstance(gnvla, pdu.ConfirmedResponse)
    assert pdu.get_named_variable_list_attributes_response(gnvla.content) == [
        ObjectName("BAYMMXU1$ST$Beh", "IED01_BayLD")  # a member in another domain
    ]

    error = pdu.decode_pdu(_mms(SERVICES["gnl_error_resp"]))
    assert error == pdu.ConfirmedError(invoke_id=642, error_class=7, code=2)


def test_access_results_and_write_response() -> None:
    content = ber.encode_tlv(0xA1, encode_data(BoolData(True)) + bytes.fromhex("80010a"))
    assert pdu.read_response(content) == [BoolData(True), DataAccessError(10)]
    assert pdu.write_response(bytes.fromhex("8100" "800103")) == [None, DataAccessError(3)]


def test_information_report_forms() -> None:
    rpt = ber.encode_tlv(0xA1, ber.encode_tlv(0x80, b"RPT")) + ber.encode_tlv(0xA0, encode_data(BoolData(True)))
    decoded = pdu.decode_pdu(ber.encode_tlv(0xA3, ber.encode_tlv(0xA0, rpt)))
    assert decoded == InformationReport(ObjectName("RPT"), [], [BoolData(True)])

    oper = ObjectName("CBCSWI1$CO$Pos$Oper", "LD0")
    spec = ber.encode_tlv(0xA0, ber.encode_tlv(0x30, ber.encode_tlv(0xA0, pdu.encode_object_name(oper))))
    body = spec + ber.encode_tlv(0xA0, encode_data(IntData(1)))
    decoded = pdu.decode_pdu(ber.encode_tlv(0xA3, ber.encode_tlv(0xA0, body)))
    assert decoded == InformationReport(None, [oper], [IntData(1)])


# --- reports -----------------------------------------------------------------


def test_flag_bit_strings() -> None:
    # The OptFlds and TrgOps that po writes today.
    assert OptFlds.from_bitstring(BitStringData(bytes.fromhex("7b00"), 6)) == OptFlds(
        sequence_number=True, report_time_stamp=True, reason_for_inclusion=True, data_set_name=True,
        buffer_overflow=True, entry_id=True,
    )
    assert TrgOps.from_bitstring(BitStringData(b"\x0c", 2)) == TrgOps(integrity=True, general_interrogation=True)
    assert TrgOps(data_change=True, integrity=True).to_bitstring() == BitStringData(b"\x48", 2)
    assert bits_of(bitstring_of([True, False, True])) == [True, False, True]


def _report_message(opt: OptFlds, inclusion: list[bool], *, values: list[IECData], extra: list[IECData]) -> InformationReport:
    results: list[IECData] = [VisibleStringData("RPT_ID"), opt.to_bitstring()]
    results += extra
    results.append(bitstring_of(inclusion))
    included = sum(inclusion)
    if opt.data_reference:
        results += [VisibleStringData(f"LD0/X{i}") for i, b in enumerate(inclusion) if b]
    results += values
    if opt.reason_for_inclusion:
        results += [ReasonCode(data_change=True).to_bitstring()] * included
    return InformationReport(ObjectName("RPT"), results=results)


def test_report_with_po_opt_flds() -> None:
    opt = OptFlds.from_bitstring(BitStringData(bytes.fromhex("7b00"), 6))
    toe = datetime(2026, 3, 1, 1, tzinfo=timezone.utc)
    extra = [UIntData(42), TimestampData(toe), VisibleStringData("IED1LD0/LLN0$DS1"), BoolData(False), OctetStringData(bytes(8))]
    member = StructureData([BoolData(True), BitStringData(b"\x00\x00", 3)])
    report = decode_report(_report_message(opt, [False, True, False], values=[member], extra=extra))
    assert (report.rpt_id, report.seq_num, report.time_of_entry, report.data_set) == ("RPT_ID", 42, toe, "IED1LD0/LLN0$DS1")
    assert report.buf_ovfl is False and report.entry_id == bytes(8) and report.conf_rev is None
    assert [(e.index, e.value, e.reason) for e in report.entries] == [(1, member, ReasonCode(data_change=True))]


def test_report_with_references_conf_rev_and_segmentation() -> None:
    opt = OptFlds(data_reference=True, conf_revision=True, segmentation=True)
    report = decode_report(
        _report_message(opt, [True, True], values=[IntData(1), IntData(2)], extra=[UIntData(7), UIntData(0), BoolData(True)])
    )
    assert report.conf_rev == 7 and report.sub_seq_num == 0 and report.more_segments_follow is True
    assert [(e.index, e.reference, e.value, e.reason) for e in report.entries] == [
        (0, "LD0/X0", IntData(1), None),
        (1, "LD0/X1", IntData(2), None),
    ]


def test_report_minimal() -> None:
    report = decode_report(_report_message(OptFlds(), [True], values=[BoolData(False)], extra=[]))
    assert report.seq_num is None and report.entries[0].value == BoolData(False)


def test_report_errors() -> None:
    with pytest.raises(ReportDecodeError, match="truncated"):
        decode_report(_report_message(OptFlds(), [True, True], values=[IntData(1)], extra=[]))
    with pytest.raises(ReportDecodeError, match="trailing"):
        decode_report(_report_message(OptFlds(), [True], values=[IntData(1), IntData(2)], extra=[]))
    with pytest.raises(ReportDecodeError, match="SeqNum should be UIntData"):
        decode_report(_report_message(OptFlds(sequence_number=True), [True], values=[IntData(1)], extra=[BoolData(True)]))
    with pytest.raises(ReportDecodeError, match="not an informationReport on RPT"):
        decode_report(InformationReport(None, [ObjectName("X")], []))


# --- fake server ---------------------------------------------------------------

Handler = Callable[[int, int, bytes, "FakeServer"], None]


class FakeServer:
    """A scripted MMS server on a socketpair. ``handler(invoke_id, service, content, server)``."""

    def __init__(self, handler: Handler, tpdu_size: int = 1024, accept: str = "vmc7_accept") -> None:
        self.handler = handler
        self.accept = bytes.fromhex(ASSOCIATION[accept])
        self.client_sock, self.sock = socket.socketpair()
        self.conn = transport.IsoConnection(self.sock, tpdu_size=tpdu_size)
        self.errors: list[BaseException] = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            cr = transport.recv_tpkt(self.sock)
            assert cr is not None and cr[1] == 0xE0
            transport.send_tpkt(self.sock, bytes.fromhex("0bd00000000100c0010a"))  # CC, 1024-byte TPDUs
            assert self.conn.recv() == association.association_request()
            self.conn.send(self.accept)
            while True:
                user_data = self.conn.recv()
                if user_data is None:
                    return
                request = ber.decode_tlv(pdu.unwrap(user_data))
                invoke, service = list(ber.iter_tlvs(request.value))[:2]
                self.handler(ber.decode_unsigned(invoke.value), ber.tag_number(service.tag), service.value, self)
        except OSError:
            pass
        except BaseException as exc:  # noqa: BLE001 - reported by the fixture
            self.errors.append(exc)

    def respond(self, invoke_id: int, service: int, content: bytes) -> None:
        body = ber.encode_tlv(0x02, ber.encode_unsigned(invoke_id)) + ber.encode_tlv(ber.make_tag(service, constructed=True), content)
        self.conn.send(pdu.wrap(ber.encode_tlv(0xA1, body)))

    def send_mms(self, mms_pdu: bytes) -> None:
        self.conn.send(pdu.wrap(mms_pdu))

    def close(self) -> None:
        self.conn.close()


@pytest.fixture
def serve(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., tuple[MmsClient, FakeServer]]]:
    servers: list[FakeServer] = []
    clients: list[MmsClient] = []

    def start(handler: Handler, on_report: object = None, **kwargs: object) -> tuple[MmsClient, FakeServer]:
        server = FakeServer(handler, **kwargs)  # type: ignore[arg-type]
        servers.append(server)
        monkeypatch.setattr(transport.socket, "create_connection", lambda *_a, **_k: server.client_sock)
        client = MmsClient.connect("ied", timeout=2, on_information_report=on_report)  # type: ignore[arg-type]
        clients.append(client)
        return client, server

    yield start
    for c in clients:
        c.close()
    for s in servers:
        s.close()
        s.thread.join(timeout=2)
        if s.errors:
            raise s.errors[0]


def _read_names(content: bytes) -> list[ObjectName]:
    spec = next(t for t in ber.iter_tlvs(content) if t.tag == 0xA1)
    return pdu._decode_variable_list(ber.decode_tlv(spec.value).value)


def _read_ok(values: list[bytes]) -> bytes:
    return ber.encode_tlv(0xA1, b"".join(values))


def test_concurrent_requests_are_matched_by_invoke_id(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    held: list[tuple[int, str]] = []
    lock = threading.Lock()

    def handler(invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        with lock:
            held.append((invoke_id, _read_names(content)[0].item))
            if len(held) < 3:
                return
            batch = list(reversed(held))
            held.clear()
        for inv, item in batch:  # answer in reverse order
            server.respond(inv, service, _read_ok([encode_data(VisibleStringData(item))]))

    client, _ = serve(handler)
    results: dict[str, IECData] = {}

    def worker(item: str) -> None:
        results[item] = client.read(ObjectName(item, "LD0"))

    threads = [threading.Thread(target=worker, args=(f"V{i}",)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert results == {f"V{i}": VisibleStringData(f"V{i}") for i in range(3)}


def test_requests_wait_for_a_slot_when_the_server_accepts_one(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    in_flight: list[int] = []
    peak = [0]
    lock = threading.Lock()

    def handler(invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        with lock:
            in_flight.append(invoke_id)
            peak[0] = max(peak[0], len(in_flight))

        def answer() -> None:
            time.sleep(0.05)
            with lock:
                in_flight.remove(invoke_id)
            server.respond(invoke_id, service, _read_ok([encode_data(UIntData(invoke_id))]))

        threading.Thread(target=answer, daemon=True).start()

    client, _ = serve(handler, accept="ssc600_accept")
    assert client.association is not None and client.association.max_outstanding_calling == 1
    threads = [threading.Thread(target=client.read, args=(ObjectName(f"V{i}", "LD0"),)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert peak[0] == 1


def test_reports_are_delivered_while_a_request_waits(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    reports: list[InformationReport] = []

    def handler(invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        rpt = ber.encode_tlv(0xA1, ber.encode_tlv(0x80, b"RPT")) + ber.encode_tlv(0xA0, encode_data(BoolData(True)))
        server.send_mms(ber.encode_tlv(0xA3, ber.encode_tlv(0xA0, rpt)))
        server.respond(invoke_id, service, _read_ok([encode_data(UIntData(1))]))

    client, _ = serve(handler, on_report=reports.append)
    assert client.read(ObjectName("X", "LD0")) == UIntData(1)
    assert reports == [InformationReport(ObjectName("RPT"), [], [BoolData(True)])]


def test_errors(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    def handler(invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        item = _read_names(content)[0].item
        if item == "missing":
            server.respond(invoke_id, service, _read_ok([bytes.fromhex("80010a")]))
        elif item == "service-error":
            body = ber.encode_tlv(0x80, ber.encode_unsigned(invoke_id)) + ber.encode_tlv(0xA2, bytes.fromhex("a003870102"))
            server.send_mms(ber.encode_tlv(0xA2, body))
        elif item == "reject":
            server.send_mms(ber.encode_tlv(0xA4, ber.encode_tlv(0x80, ber.encode_unsigned(invoke_id)) + bytes.fromhex("810101")))
        # "silent": no answer

    client, _ = serve(handler)
    with pytest.raises(DataAccessError) as access:
        client.read(ObjectName("missing", "LD0"))
    assert access.value.code == 10
    with pytest.raises(ServiceError) as service_error:
        client.read(ObjectName("service-error", "LD0"))
    assert (service_error.value.error_class, service_error.value.code) == (7, 2)
    with pytest.raises(MmsReject):
        client.read(ObjectName("reject", "LD0"))
    client.request_timeout = 0.2
    with pytest.raises(MmsTimeout):
        client.read(ObjectName("silent", "LD0"))
    assert client.is_connected


def test_connection_loss_fails_pending_requests(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    def handler(invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        server.close()

    client, _ = serve(handler)
    with pytest.raises(MmsConnectionError):
        client.read(ObjectName("X", "LD0"))
    assert isinstance(client.wait_closed(timeout=2), MmsConnectionError)
    with pytest.raises(MmsConnectionError):
        client.read(ObjectName("X", "LD0"))


def test_segmentation_both_ways(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    long_name = "LLN0$" + "X" * 60

    def handler(invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        names = _read_names(content)
        server.respond(invoke_id, service, _read_ok([encode_data(VisibleStringData(n.item)) for n in names]))

    client, _ = serve(handler, tpdu_size=128)
    names = [ObjectName(f"{long_name}{i}", "LD0") for i in range(40)]  # request and response > 2 KB
    assert client.read_many(names) == [VisibleStringData(n.item) for n in names]


def test_get_name_list_pages(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    pages = {None: (["A", "B"], True), "B": (["C"], False)}

    def handler(invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        fields = {t.tag: t.value for t in ber.iter_tlvs(content)}
        after = fields[0x82].decode() if 0x82 in fields else None
        names, more = pages[after]
        body = ber.encode_tlv(0xA0, b"".join(ber.encode_tlv(0x1A, n.encode()) for n in names))
        server.respond(invoke_id, service, body + ber.encode_tlv(0x81, ber.encode_boolean(more)))

    client, _ = serve(handler)
    assert client.get_name_list(OBJECT_CLASS_DOMAIN) == ["A", "B", "C"]


# --- report control blocks ----------------------------------------------------------


class FakeModel:
    """Variables of a fake server; unknown ones answer object-non-existent."""

    def __init__(self, values: dict[str, IECData], refuse: frozenset[str] = frozenset()) -> None:
        self.values = values
        self.refuse = refuse
        self.writes: list[tuple[str, IECData]] = []

    def __call__(self, invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        if service == pdu.SERVICE_READ:
            out = []
            for n in _read_names(content):
                v = self.values.get(n.item)
                out.append(encode_data(v) if v is not None else bytes.fromhex("80010a"))
            server.respond(invoke_id, service, _read_ok(out))
        elif service == pdu.SERVICE_WRITE:
            spec, data = list(ber.iter_tlvs(content))[:2]
            name = pdu._decode_variable_list(spec.value)[0].item
            from iec61850.data import decode_data_sequence

            (value,) = decode_data_sequence(data.value)
            if name.rsplit("$", 1)[1] in self.refuse:
                server.respond(invoke_id, service, bytes.fromhex("800103"))
                return
            self.writes.append((name, value))
            self.values[name] = value
            server.respond(invoke_id, service, bytes.fromhex("8100"))


BRCB = "LLN0$BR$CB_X0"


def _brcb_values(instance: int, *, enabled: bool, resv_tms: int = 0) -> dict[str, IECData]:
    base = f"{BRCB}{instance}"
    return {
        f"{base}$RptEna": BoolData(enabled),
        f"{base}$ResvTms": IntData(resv_tms),
        f"{base}$RptID": VisibleStringData(f"id{instance}"),
        f"{base}$DatSet": VisibleStringData("LD0/LLN0$DS1"),
    }


def test_rcb_names_and_groups() -> None:
    assert rcb.is_rcb_name("LLN0$BR$CB01") and rcb.is_rcb_name("LLN0$RP$URCB")
    assert not rcb.is_rcb_name("LLN0$BR$CB01$RptID")
    groups = rcb.group_instances([ObjectName(f"LLN0$BR$CB_A0{i}", "LD0") for i in (2, 1)] + [ObjectName("LLN0$RP$U01", "LD0")])
    assert groups[("LD0", "LLN0$BR$CB_A")] == [ObjectName("LLN0$BR$CB_A01", "LD0"), ObjectName("LLN0$BR$CB_A02", "LD0")]
    assert list(groups) == [("LD0", "LLN0$BR$CB_A"), ("LD0", "LLN0$RP$U")]
    # The instance number is two digits: a block name may end with a digit of its own.
    assert rcb.instance_base("LLN0$BR$CB_ADD_DEP102") == "LLN0$BR$CB_ADD_DEP1"
    assert rcb.instance_base("LLN0$BR$CB_ADD_DEP201") == "LLN0$BR$CB_ADD_DEP2"


def test_find_free_instance(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    values = {**_brcb_values(1, enabled=True), **_brcb_values(2, enabled=False, resv_tms=30), **_brcb_values(3, enabled=False)}
    client, _ = serve(FakeModel(values))
    candidates = [ObjectName(f"{BRCB}{i}", "LD0") for i in (1, 2, 3)]
    status = rcb.find_free(client, candidates)
    assert status is not None and status.rcb == candidates[2]
    assert (status.rpt_id, status.dat_set, status.owner) == ("id3", "LD0/LLN0$DS1", None)
    assert rcb.read_status(client, candidates[1]).describe() == "reserved 30s"


def test_find_free_reclaims_our_own_reservation(
    serve: Callable[..., tuple[MmsClient, FakeServer]], monkeypatch: pytest.MonkeyPatch
) -> None:
    ours, theirs = bytes([192, 0, 2, 71]), bytes([192, 0, 2, 253])
    values = {
        **_brcb_values(1, enabled=False, resv_tms=5), f"{BRCB}1$Owner": OctetStringData(theirs),
        **_brcb_values(2, enabled=True, resv_tms=5), f"{BRCB}2$Owner": OctetStringData(ours),
        **_brcb_values(3, enabled=False, resv_tms=-1), f"{BRCB}3$Owner": OctetStringData(ours),
        **_brcb_values(4, enabled=False, resv_tms=5), f"{BRCB}4$Owner": OctetStringData(ours),
    }
    client, _ = serve(FakeModel(values))
    monkeypatch.setattr(MmsClient, "local_address", property(lambda _self: "192.0.2.71"))
    candidates = [ObjectName(f"{BRCB}{i}", "LD0") for i in (1, 2, 3, 4)]
    # 1 reserved by someone else, 2 enabled by us (running), 3 assigned by configuration: only 4.
    status = rcb.find_free(client, candidates)
    assert status is not None and status.rcb == candidates[3]
    assert rcb.find_free(client, candidates, reclaim_own=False) is None


def test_edition_1_brcb_without_resv_tms(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    values = {k: v for k, v in _brcb_values(1, enabled=False).items() if not k.endswith("$ResvTms")}

    class Edition1(FakeModel):
        def __call__(self, invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
            if service == pdu.SERVICE_WRITE and b"ResvTms" in content:
                server.respond(invoke_id, service, bytes.fromhex("80010a"))  # object-non-existent
                return
            super().__call__(invoke_id, service, content, server)

    model = Edition1(values)
    client, _ = serve(model)
    block = ObjectName(f"{BRCB}1", "LD0")
    assert rcb.read_status(client, block).free
    rcb.enable(client, block)
    assert [n.rsplit("$", 1)[1] for n, _ in model.writes][:2] == ["IntgPd", "TrgOps"]
    rcb.disable(client, block)
    assert model.writes[-1] == (f"{BRCB}1$RptEna", BoolData(False))


def test_disable_releases_a_brcb(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    model = FakeModel(_brcb_values(1, enabled=True, resv_tms=5))
    client, _ = serve(model)
    rcb.disable(client, ObjectName(f"{BRCB}1", "LD0"))
    assert model.writes == [(f"{BRCB}1$RptEna", BoolData(False)), (f"{BRCB}1$ResvTms", IntData(0))]


def test_status_description() -> None:
    brcb = ObjectName("LLN0$BR$CB01", "LD0")
    assert rcb.RcbStatus(brcb, rpt_ena=False, resv_tms=0).describe() == "free"
    assert rcb.RcbStatus(brcb, rpt_ena=True, resv_tms=-1, owner=bytes([10, 1, 2, 3])).describe() == (
        "enabled, assigned by configuration, owner 10.1.2.3"
    )
    assert not rcb.RcbStatus(brcb, rpt_ena=False, resv_tms=-1, owner=bytes(4)).free


def test_enable_writes_typed_values_in_order(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    model = FakeModel(_brcb_values(1, enabled=False))
    client, _ = serve(model)
    settings = rcb.RcbSettings(purge_buf=True, entry_id=bytes(8), resv_tms=5)
    rcb.enable(client, ObjectName(f"{BRCB}1", "LD0"), settings)
    base = f"{BRCB}1$"
    assert [(n[len(base):], v) for n, v in model.writes] == [
        ("ResvTms", IntData(5)),
        ("IntgPd", UIntData(2000)),
        ("TrgOps", BitStringData(b"\x6c", 2)),  # dchg, qchg, integrity, GI
        ("OptFlds", BitStringData(b"\x7b\x80", 6)),
        ("PurgeBuf", BoolData(True)),
        ("EntryID", OctetStringData(bytes(8))),
        ("RptEna", BoolData(True)),
        ("GI", BoolData(True)),
    ]


def test_enable_reserves_a_brcb_first_by_default(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    model = FakeModel(_brcb_values(1, enabled=False))
    client, _ = serve(model)
    rcb.enable(client, ObjectName(f"{BRCB}1", "LD0"))
    assert model.writes[0] == (f"{BRCB}1$ResvTms", IntData(5))


def test_enable_reports_the_failing_attribute(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    client, _ = serve(FakeModel(_brcb_values(1, enabled=False), refuse=frozenset({"OptFlds"})))
    with pytest.raises(rcb.RcbError) as err:
        rcb.enable(client, ObjectName(f"{BRCB}1", "LD0"))
    assert err.value.attribute == "OptFlds" and err.value.cause.code == 3


def test_urcb_reservation(serve: Callable[..., tuple[MmsClient, FakeServer]]) -> None:
    model = FakeModel({"LLN0$RP$U01$RptEna": BoolData(False), "LLN0$RP$U01$Resv": BoolData(False)})
    client, _ = serve(model)
    urcb = ObjectName("LLN0$RP$U01", "LD0")
    assert rcb.read_status(client, urcb).free
    rcb.enable(client, urcb, rcb.RcbSettings(intg_pd_ms=None, trg_ops=None, opt_flds=None, general_interrogation=False))
    assert [n for n, _ in model.writes] == ["LLN0$RP$U01$Resv", "LLN0$RP$U01$RptEna"]
    assert not rcb.read_status(client, urcb).free
    rcb.disable(client, urcb)
    assert rcb.read_status(client, urcb).free
