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
