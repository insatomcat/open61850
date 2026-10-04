# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Setting groups of the MMS server (open61850.server.settings), with the open61850 client on loopback."""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from conftest import DATA_DIR

from open61850.data import BoolData, FloatData, IntData, UIntData
from open61850.mms import (
    DataAccessError,
    MmsClient,
    confirm_edit_sg_values,
    discover,
    read_sgcb,
    select_active_sg,
    select_edit_sg,
)
from open61850.mms.model import compare
from open61850.scl import load_model
from open61850.server import IedModel, MmsServer

SCL = DATA_DIR / "setting_groups.cid.xml"
LD = "IED01PROT"
STR_SG, STR_SE = f"{LD}/PTOC1$SG$StrVal$setMag$f", f"{LD}/PTOC1$SE$StrVal$setMag$f"
DELAY_SG, DELAY_SE = f"{LD}/PTOC1$SG$OpDlTmms$setVal", f"{LD}/PTOC1$SE$OpDlTmms$setVal"
TEMPORARILY_UNAVAILABLE, ACCESS_DENIED, VALUE_INVALID = 2, 3, 11


@pytest.fixture
def model() -> IedModel:
    return IedModel.from_scl(SCL)


@pytest.fixture
def server(model: IedModel) -> Iterator[MmsServer]:
    with MmsServer(model, "127.0.0.1", 0) as srv:
        srv.start()
        yield srv


def test_model_from_setting_control(model: IedModel, tmp_path) -> None:
    lln0 = model.node(f"{LD}/LLN0")
    assert list(lln0.children) == ["ST", "SP"] and list(lln0.children["SP"].children) == ["SGCB"]
    assert list(model.node(f"{LD}/LLN0$SP$SGCB").children) == ["NumOfSG", "ActSG", "EditSG", "CnfEdit", "LActTm", "ResvTms"]
    assert model.get(f"{LD}/LLN0$SP$SGCB$NumOfSG") == UIntData(3) and model.get(f"{LD}/LLN0$SP$SGCB$ActSG") == UIntData(2)
    groups = model.setting_groups[LD]
    assert groups.count == 3 and groups.resv_tms == 60
    # sGroup values, else the attribute's own (the DOType's Val for OpDlTmms)
    assert groups.values == {
        1: {"PTOC1.StrVal.setMag.f": FloatData(100.0), "PTOC1.OpDlTmms.setVal": IntData(500)},
        2: {"PTOC1.StrVal.setMag.f": FloatData(200.0), "PTOC1.OpDlTmms.setVal": IntData(500)},
        3: {"PTOC1.StrVal.setMag.f": FloatData(300.0), "PTOC1.OpDlTmms.setVal": IntData(750)}}
    assert model.get(STR_SG) == model.get(STR_SE) == FloatData(200.0)  # the active group
    assert model.get(f"{LD}/PTOC1$SP$TmMult$setMag$f") == FloatData(0.5)
    edition1 = tmp_path / "ed1.cid"
    edition1.write_text(SCL.read_text().replace('version="2007" revision="B"', ""))
    sgcb = IedModel.from_scl(edition1).node(f"{LD}/LLN0$SP$SGCB")
    assert "ResvTms" not in sgcb.children


def test_select_active_group(server: MmsServer, model: IedModel) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as client:
        status = read_sgcb(client, LD)
        assert (status.num_of_sg, status.act_sg, status.edit_sg, status.cnf_edit, status.resv_tms) == (3, 2, 0, False, 0)
        select_active_sg(client, LD, 3)
        assert client.read(STR_SG) == FloatData(300.0) and client.read(DELAY_SG) == IntData(750)
        status = read_sgcb(client, LD)
        assert status.act_sg == 3 and status.l_act_tm is not None and status.l_act_tm.year > 2000
        for group in (0, 4):
            with pytest.raises(DataAccessError) as refused:
                select_active_sg(client, LD, group)
            assert refused.value == DataAccessError(VALUE_INVALID)
        for attribute, value in (("NumOfSG", UIntData(5)), ("ResvTms", UIntData(1))):
            with pytest.raises(DataAccessError) as refused:
                client.write(f"{LD}/LLN0$SP$SGCB${attribute}", value)
            assert refused.value == DataAccessError(ACCESS_DENIED)
        with pytest.raises(DataAccessError):
            client.write(STR_SG, FloatData(1.0))  # SG is read-only
    assert server.setting_groups is not None and server.setting_groups.active(LD) == 3


def test_edit_reserved_and_confirmed(server: MmsServer, model: IedModel) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as a, MmsClient.connect("127.0.0.1", server.port) as b:
        with pytest.raises(DataAccessError) as refused:
            a.write(STR_SE, FloatData(1.0))  # nobody edits
        assert refused.value == DataAccessError(TEMPORARILY_UNAVAILABLE)
        with pytest.raises(DataAccessError) as refused:
            confirm_edit_sg_values(a, LD)
        assert refused.value == DataAccessError(ACCESS_DENIED)
        select_edit_sg(a, LD, 1)
        assert a.read(STR_SE) == FloatData(100.0)
        assert (read_sgcb(b, LD).edit_sg, read_sgcb(b, LD).resv_tms) == (1, 60)
        for attempt in (lambda: b.write(STR_SE, FloatData(9.0)), lambda: select_edit_sg(b, LD, 3)):
            with pytest.raises(DataAccessError) as refused:
                attempt()
            assert refused.value == DataAccessError(TEMPORARILY_UNAVAILABLE)
        a.write(STR_SE, FloatData(150.0))
        with pytest.raises(DataAccessError) as refused:
            a.write(f"{LD}/LLN0$SP$SGCB$CnfEdit", BoolData(False))
        assert refused.value == DataAccessError(VALUE_INVALID)
        confirm_edit_sg_values(a, LD)
        assert read_sgcb(a, LD).edit_sg == 0
        assert model.setting_groups[LD].values[1]["PTOC1.StrVal.setMag.f"] == FloatData(150.0)
        assert a.read(STR_SG) == FloatData(200.0)  # group 2 stays active
        # the active group edited: SG follows on confirmation, not before
        select_edit_sg(b, LD, 2)
        b.write(STR_SE, FloatData(250.0))
        assert b.read(STR_SG) == FloatData(200.0)
        confirm_edit_sg_values(b, LD)
        assert b.read(STR_SG) == FloatData(250.0)
        # an edit left without a confirmation keeps the group's values
        select_edit_sg(a, LD, 3)
        a.write(DELAY_SE, IntData(1))
        select_edit_sg(a, LD, 0)
        assert model.setting_groups[LD].values[3]["PTOC1.OpDlTmms.setVal"] == IntData(750)


def test_edit_lapses_and_ends_with_the_client(server: MmsServer, model: IedModel) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as a:
        select_edit_sg(a, LD, 1)
    with MmsClient.connect("127.0.0.1", server.port) as b:
        for _ in range(50):  # the server sees the first client go
            if read_sgcb(b, LD).edit_sg == 0:
                break
            time.sleep(0.02)
        assert read_sgcb(b, LD).edit_sg == 0
        model.setting_groups[LD].resv_tms = 0  # lapses at once
        select_edit_sg(b, LD, 1)
        status = read_sgcb(b, LD)
        assert (status.edit_sg, status.resv_tms) == (0, 0)
        with pytest.raises(DataAccessError):
            b.write(STR_SE, FloatData(1.0))


def test_handlers_and_application(server: MmsServer, model: IedModel) -> None:
    engine = server.setting_groups
    assert engine is not None
    seen = []

    def active(client, ld, group):
        seen.append(("active", ld, group))
        return ACCESS_DENIED if group == 1 else None

    def confirm(client, ld, group):
        seen.append(("confirm", ld, group, model.get(STR_SE)))
        return None

    engine.on_active, engine.on_confirm = active, confirm
    with MmsClient.connect("127.0.0.1", server.port) as client:
        with pytest.raises(DataAccessError) as refused:
            select_active_sg(client, LD, 1)
        assert refused.value == DataAccessError(ACCESS_DENIED) and engine.active(LD) == 2
        select_active_sg(client, LD, 2)  # the same group: done, no handler
        select_active_sg(client, LD, 3)
        select_edit_sg(client, LD, 3)
        client.write(STR_SE, FloatData(330.0))
        confirm_edit_sg_values(client, LD)
        assert seen == [("active", LD, 1), ("active", LD, 3), ("confirm", LD, 3, FloatData(330.0))]
        engine.set_values(LD, 3, {"PTOC1.StrVal.setMag.f": 333.0})
        assert client.read(STR_SG) == FloatData(333.0)
        engine.set_values(LD, 1, {"PTOC1.OpDlTmms.setVal": 10})
        assert engine.values(LD, 1)["PTOC1.OpDlTmms.setVal"] == IntData(10) and client.read(DELAY_SG) == IntData(750)
        engine.select_active(LD, 1)
        assert client.read(DELAY_SG) == IntData(10) and read_sgcb(client, LD).act_sg == 1
    with pytest.raises(KeyError):
        engine.set_values(LD, 1, {"PTOC1.Nope.setVal": 1})
    with pytest.raises(ValueError):
        engine.select_active(LD, 4)


def test_discovered_model_matches_the_scl(server: MmsServer) -> None:
    with MmsClient.connect("127.0.0.1", server.port) as client:
        live = discover(client)
    expected = load_model(SCL)
    assert compare(expected, live) == []
    assert [str(r) for r in live.logical_devices[LD].logical_nodes["LLN0"].control_blocks()] == [f"{LD}/LLN0.SGCB [SP]"]


def test_no_engine_without_setting_control() -> None:
    with MmsServer(IedModel.from_scl(DATA_DIR / "goose_sv.scd.xml"), "127.0.0.1", 0) as srv:
        srv.start()
        assert srv.setting_groups is None
