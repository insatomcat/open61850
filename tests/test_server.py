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
    assert model.node(f"{PROT}/PTRC1$ST$Tr$general").triggers == frozenset()
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
