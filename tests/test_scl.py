# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850.scl: IEDs, addresses and report control blocks of an SCL file."""

from __future__ import annotations

import pytest
from conftest import DATA_DIR

from open61850 import scl
from open61850.mms import ObjectName

SCD = DATA_DIR / "two_ieds.scd.xml"


def test_ieds_and_addresses() -> None:
    ieds = scl.load_ieds(SCD)
    assert [(i.name, i.addresses) for i in ieds] == [("IED01_A", ["192.0.2.10"]), ("IED01_B", ["192.0.2.11"])]
    assert scl.find_ied(ieds, "192.0.2.11") is ieds[1]
    assert scl.find_ied(ieds, "198.51.100.1") is None  # two IEDs, none at that address
    assert scl.find_ied(ieds[:1], "198.51.100.1") is ieds[0]  # a CID: its only IED (tunnel, NAT)


def test_report_control_blocks() -> None:
    (ied, _) = scl.load_ieds(SCD)
    blocks = {b.name: b for b in ied.report_controls}
    px = blocks["CB_LDPX_DQPO_DEP1"]
    assert px.base == ObjectName("LLN0$BR$CB_LDPX_DQPO_DEP1", "IED01_ALD0")
    assert px.instances()[-1] == ObjectName("LLN0$BR$CB_LDPX_DQPO_DEP103", "IED01_ALD0")
    assert px.data_set_reference == "IED01_ALD0/LLN0$DS_PX_DEP1"
    assert blocks["URCB_SINGLE"].instances() == [ObjectName("LLN0$RP$URCB_SINGLE", "IED01_ALD0")]
    assert blocks["CB_POS"].instances() == [ObjectName("CBCSWI1$BR$CB_POS01", "IED01_ACTRL")]


def test_not_scl(tmp_path) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "x.cid"
    bad.write_text("<html/>")
    with pytest.raises(scl.SclError):
        scl.load_ieds(bad)
    with pytest.raises(scl.SclError):
        scl.load_ieds(tmp_path / "missing.cid")


# --- GOOSE, SV, data sets and the data model (goose_sv.scd.xml) ---------------------

GOOSE_SV = DATA_DIR / "goose_sv.scd.xml"


def test_goose_control_block_and_address() -> None:
    (ied,) = scl.load_ieds(GOOSE_SV)
    assert ied.domains == ["IED01_Protection", "IED01MU"]  # ldName, then IED name + inst
    (gcb,) = ied.goose_controls
    assert gcb.gocb_ref == "IED01_Protection/LLN0$GO$gcbTrip"
    assert gcb.data_set_reference == "IED01_Protection/LLN0$DS_TRIP"
    assert gcb.address == scl.GseAddress("01:0c:cd:01:00:2a", 0x2A, 100, 4, 4, 1000)  # APPID and VLAN-ID in hex
    control = gcb.goose_control("02:00:00:00:00:01")
    assert (control.go_id, control.conf_rev, control.min_time_ms, control.max_time_ms) == ("TRIP_GOOSE", 7, 4, 1000)
    assert (control.vlan_id, control.vlan_priority, control.app_id) == (100, 4, 0x2A)
    (rcb,) = ied.report_controls
    assert rcb.instances()[0] == ObjectName("LLN0$BR$brcbTrip01", "IED01_Protection")


def test_sv_control_block() -> None:
    (ied,) = scl.load_ieds(GOOSE_SV)
    (msvcb,) = ied.sv_controls
    assert (msvcb.sv_id, msvcb.nof_asdu, msvcb.conf_rev, msvcb.multicast) == ("IED01MU01", 2, 1, True)
    assert msvcb.samples_per_second() == 4800 and msvcb.reference == ObjectName("LLN0$MS$msvcb01", "IED01MU")
    assert (msvcb.address.mac, msvcb.address.app_id, msvcb.address.vlan_id) == ("01:0c:cd:04:00:01", 0x4000, None)


def test_data_set_members_as_references() -> None:
    (ied,) = scl.load_ieds(GOOSE_SV)
    (ds,) = ied.data_sets
    assert ds.object_name == ObjectName("LLN0$DS_TRIP", "IED01_Protection")
    assert [str(r) for r in ds.references()] == [
        "IED01_Protection/PTRC1.Tr.general [ST]",
        "IED01MU/IMMXU1.A.phsA [MX]",  # a member in the other logical device
    ]


def test_model_from_templates() -> None:
    model = scl.load_model(GOOSE_SV)
    assert list(model.logical_devices) == ["IED01_Protection", "IED01MU"]
    mmxu = model.logical_node("IED01MU", "IMMXU1")
    assert [str(r) for r in mmxu.references()] == [
        "IED01MU/IMMXU1.A.angRef [CF]",
        "IED01MU/IMMXU1.A.phsA.cVal.mag.f [MX]",
        "IED01MU/IMMXU1.A.phsA.hist [MX]",  # an array: a leaf
        "IED01MU/IMMXU1.A.phsA.q [MX]",
    ]
    assert model.resolve("IED01MU/IMMXU1.A.phsA.cVal.mag.f").fc == "MX"
    lln0 = model.logical_node("IED01_Protection", "LLN0")
    assert "IED01_Protection/LLN0.Mod.Oper.origin.orCat [CO]" in [str(r) for r in lln0.references()]
    assert [str(b) for b in lln0.control_blocks()] == [
        "IED01_Protection/LLN0.brcbTrip01 [BR]", "IED01_Protection/LLN0.brcbTrip02 [BR]",
        "IED01_Protection/LLN0.gcbTrip [GO]",
    ]
    assert lln0.data_sets == ["DS_TRIP"]
    assert [str(b) for b in model.logical_node("IED01MU", "LLN0").control_blocks()] == ["IED01MU/LLN0.msvcb01 [MS]"]


def test_compare_with_a_server_model() -> None:
    from open61850.mms.model import compare, logical_device_from_names

    expected = scl.load_model(GOOSE_SV)
    assert compare(expected, expected) == []
    live = scl.load_model(GOOSE_SV)
    del live.logical_devices["IED01MU"].logical_nodes["IMMXU1"]
    live.logical_devices["IED01_Protection"].logical_nodes["PTRC1"].items.remove("ST$Tr$q")
    live.logical_devices["IED01_Protection"].logical_nodes["PTRC1"].items.append("ST$Tr$extra")
    live.logical_devices["IED02"] = logical_device_from_names("IED02", ["LLN0"])
    assert compare(expected, live) == [
        "extra logical device IED02",
        "missing attribute IED01_Protection/PTRC1.Tr.q [ST]",
        "extra attribute IED01_Protection/PTRC1.Tr.extra [ST]",
        "missing logical node IED01MU/IMMXU1",
    ]


def test_ied_must_be_named_when_several() -> None:
    with pytest.raises(scl.SclError, match="several"):
        scl.load_model(SCD)
    assert list(scl.load_model(SCD, "IED01_B").logical_devices) == ["IED01_BLD0"]
