# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for open61850.mms.reference and open61850.mms.model.

The names come from the first GetNameList page of a VMC7 logical device,
captured with IEDscout (``iedscout_getnamelist.json``, anonymized).
"""

from __future__ import annotations

import json

import pytest
from conftest import DATA_DIR

from open61850.mms import ObjectName, Reference, discover, pdu, to_object_name
from open61850.mms.__main__ import model_lines
from open61850.mms.control import control_object_name
from open61850.mms.errors import DataAccessError
from open61850.mms.model import logical_device_from_names
from open61850.mms.reference import data_set_object_name
from open61850.mms.types import PrimitiveType, StructureType, describe


def _captured_names() -> list[str]:
    capture = json.loads((DATA_DIR / "iedscout_getnamelist.json").read_text())
    raw = b"".join(bytes.fromhex(segment) for segment, _eot in capture["gnl_vars_resp_segments"])
    names, more_follows = pdu.get_name_list_response(pdu.decode_pdu(pdu.unwrap(raw)).content)
    assert more_follows and len(names) == 100
    return names


NAMES = _captured_names()


# --- references ------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "IED01_LD0/LLN0.Mod.stVal[ST]",
    "IED01_LD0/LLN0.Mod.stVal [st]",
    " IED01_LD0/LLN0$ST$Mod$stVal ",
])
def test_both_notations(text: str) -> None:
    ref = Reference.parse(text)
    assert ref == Reference("IED01_LD0", "LLN0", ("Mod", "stVal"), "ST")
    assert str(ref) == "IED01_LD0/LLN0.Mod.stVal [ST]"
    assert ref.object_name == ObjectName("LLN0$ST$Mod$stVal", "IED01_LD0")
    assert to_object_name(text) == ref.object_name


def test_reference_levels() -> None:
    assert Reference.parse("IED01_LD0/LLN0").object_name == ObjectName("LLN0", "IED01_LD0")
    assert Reference.from_object_name(ObjectName("LLN0$CF", "LD")) == Reference("LD", "LLN0", (), "CF")
    brcb = Reference.from_object_name(ObjectName("LLN0$BR$brcbMeas01", "LD"))
    assert str(brcb) == "LD/LLN0.brcbMeas01 [BR]"
    assert Reference.parse("LD/MMXU1.TotW", fc="mx").child("mag").child("f").object_name.item == "MMXU1$MX$TotW$mag$f"


@pytest.mark.parametrize("text", ["LLN0.Mod", "LD/LLN0..stVal", "LD/LLN0.Mod[XYZ]"])
def test_bad_references(text: str) -> None:
    with pytest.raises(ValueError):
        Reference.parse(text)


def test_conflicting_fc_and_missing_fc() -> None:
    with pytest.raises(ValueError, match="says FC ST"):
        Reference.parse("LD/LLN0.Mod.stVal[ST]", fc="MX")
    with pytest.raises(ValueError, match="needs a functional constraint"):
        to_object_name("LD/LLN0.Mod.stVal")


def test_mms_text_goes_through_unchanged() -> None:
    assert to_object_name("LD/LLN0$DS1") == ObjectName("LLN0$DS1", "LD")
    assert data_set_object_name("LD/LLN0.DS1") == ObjectName("LLN0$DS1", "LD")
    assert data_set_object_name("LD/LLN0$DS1") == ObjectName("LLN0$DS1", "LD")
    with pytest.raises(ValueError):
        data_set_object_name("LD/LLN0.Mod.stVal")


def test_control_references() -> None:
    expected = ObjectName("CBCSWI1$CO$Pos", "IED01_BayLD")
    for text in ("IED01_BayLD/CBCSWI1.Pos", "IED01_BayLD/CBCSWI1.Pos[CO]", "IED01_BayLD/CBCSWI1$CO$Pos$Oper"):
        assert control_object_name(text) == expected


# --- model -----------------------------------------------------------------------


def _device():
    extra = ["LLN0$BR", "LLN0$BR$brcbMeas01", "LLN0$BR$brcbMeas01$RptID", "LLN0$GO", "LLN0$GO$gcb1"]
    return logical_device_from_names("IED01_LD0", NAMES + extra, ["LLN0$DS_MEAS"])


def test_model_from_captured_names() -> None:
    device = _device()
    (node,) = device.logical_nodes.values()
    assert node.functional_constraints() == ["SP", "CF", "DC", "EX", "CO", "BR", "GO"]
    assert node.data_objects()[:6] == ["CustDoA", "CustDoBB", "CustDoCCCC", "CustDoDDDDD", "CustDoEEEE", "Mod"]
    cf = [str(r) for r in node.references("CF")]
    assert "IED01_LD0/LLN0.CustDoCCCC.units.SIUnit [CF]" in cf
    assert "IED01_LD0/LLN0.CustDoCCCC.units [CF]" not in cf  # not a leaf
    assert "IED01_LD0/LLN0.CustDoCCCC.units [CF]" in [str(r) for r in node.references("CF", leaves=False)]
    assert [str(b) for b in node.control_blocks()] == ["IED01_LD0/LLN0.brcbMeas01 [BR]", "IED01_LD0/LLN0.gcb1 [GO]"]
    assert all(r.fc not in ("BR", "GO") for r in node.references())
    assert node.data_sets == ["DS_MEAS"]


def test_resolve() -> None:
    from open61850.mms.model import ServerModel

    model = ServerModel({"IED01_LD0": _device()})
    assert model.resolve("IED01_LD0/LLN0.CustDoA.setVal") == Reference("IED01_LD0", "LLN0", ("CustDoA", "setVal"), "SP")
    assert model.resolve("IED01_LD0/LLN0.Mod.ctlModel").fc == "CF"
    assert model.resolve("IED01_LD0/LLN0.Mod.Oper.origin.orCat").fc == "CO"
    with pytest.raises(ValueError, match="CF, DC, CO"):
        model.resolve("IED01_LD0/LLN0.Mod")
    with pytest.raises(KeyError):
        model.resolve("IED01_LD0/LLN0.Mod.stVal[MX]")
    with pytest.raises(KeyError):
        model.resolve("IED01_LD0/MMXU1.TotW")
    assert len(list(model.references())) == len(model.logical_node("IED01_LD0", "LLN0").references())


class FakeClient:
    """The GetNameList and GetVariableAccessAttributes answers of a small server."""

    TYPE = StructureType([
        ("ST", StructureType([("Mod", StructureType([("stVal", PrimitiveType("integer", 8))]))])),
        ("MX", StructureType([("A", StructureType([("phsA", StructureType([("cVal", StructureType([
            ("mag", StructureType([("f", PrimitiveType("float", 32))]))]))]))]))])),
    ])

    def get_name_list(self, object_class: int, domain=None) -> list[str]:
        if object_class == pdu.OBJECT_CLASS_DOMAIN:
            return ["IED01_LD0", "IED01_LD1"]
        if object_class == pdu.OBJECT_CLASS_NAMED_VARIABLE_LIST:
            raise DataAccessError(2)
        return ["LLN0", "LLN0$ST", "LLN0$ST$Mod", "LLN0$ST$Mod$stVal", "MMXU1", "MMXU1$MX", "MMXU1$MX$A",
                "MMXU1$MX$A$phsA", "MMXU1$MX$A$phsA$cVal", "MMXU1$MX$A$phsA$cVal$mag", "MMXU1$MX$A$phsA$cVal$mag$f"]

    def get_type(self, name: ObjectName):
        if name.item == "MMXU1":
            raise DataAccessError(10)
        return self.TYPE


def test_discover_and_browse_text() -> None:
    model = discover(FakeClient(), types=True)
    assert list(model.logical_devices) == ["IED01_LD0", "IED01_LD1"]
    node = model.logical_node("IED01_LD0", "LLN0")
    assert describe(node.type_of(Reference.parse("IED01_LD0/LLN0.Mod.stVal[ST]"))) == "integer8"
    assert model.logical_node("IED01_LD0", "MMXU1").type is None  # refused: kept going
    lines = model_lines(model)
    assert lines[:8] == [
        "IED01_LD0", "  LLN0", "    Mod", "      stVal [ST] integer8",
        "  MMXU1", "    A", "      phsA.cVal.mag.f [MX]", "IED01_LD1",
    ]
    assert model_lines(model, fc="MX", flat=True) == [
        "IED01_LD0/MMXU1.A.phsA.cVal.mag.f [MX]", "IED01_LD1/MMXU1.A.phsA.cVal.mag.f [MX]",
    ]
    assert model_lines(model, fc="ST", flat=True)[0] == "IED01_LD0/LLN0.Mod.stVal [ST] integer8"


@pytest.mark.parametrize("mms_type, text", [
    (PrimitiveType("integer", 32), "integer32"),
    (PrimitiveType("visible-string", -255), "visible-string(<=255)"),
    (PrimitiveType("bit-string", 13), "bit-string(13)"),
    (PrimitiveType("utc-time"), "utc-time"),
    (None, "?"),
])
def test_describe(mms_type, text: str) -> None:
    assert describe(mms_type) == text
