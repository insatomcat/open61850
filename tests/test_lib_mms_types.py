# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Type descriptions, value labelling and quality decoding."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from conftest import DATA_DIR

from iec61850 import ber
from iec61850.data import BitStringData, BoolData, FloatData, IntData, StructureData, TimestampData
from iec61850.mms import ObjectName, pdu
from iec61850.mms.types import (
    PrimitiveType,
    StructureType,
    decode_type_description,
    get_variable_access_attributes_response,
    label,
)
from iec61850.quality import Quality, TimeQuality

from iec61850.display import format_value

SERVICES = json.loads((DATA_DIR / "iedscout_services.json").read_text())


def test_request_matches_iedscout() -> None:
    captured = ber.decode_tlv(pdu.unwrap(bytes.fromhex(SERVICES["gvaa_req"])))
    service = list(ber.iter_tlvs(captured.value))[1]
    assert pdu.get_variable_access_attributes_request(ObjectName("CBCILO1", "IED01_BayLD")) == ber.encode_tlv(
        service.tag, service.value
    )


def test_captured_logical_node_type() -> None:
    response = pdu.decode_pdu(pdu.unwrap(bytes.fromhex(SERVICES["gvaa_resp"])))
    ln = get_variable_access_attributes_response(response.content)  # type: ignore[union-attr]
    assert isinstance(ln, StructureType)
    assert [name for name, _ in ln.components] == ["DC", "ST"]
    beh = ln.component("ST").component("Beh")  # type: ignore[union-attr]
    assert beh == StructureType([
        ("stVal", PrimitiveType("integer", 8)),
        ("q", PrimitiveType("bit-string", -13)),
        ("t", PrimitiveType("utc-time")),
    ])
    vendor = ln.component("DC").component("NamPlt").component("vendor")  # type: ignore[union-attr]
    assert vendor == PrimitiveType("visible-string", -255)


def test_array_and_float_types() -> None:
    float_type = ber.encode_tlv(0xA7, bytes.fromhex("020120020108"))
    array = ber.encode_tlv(0xA1, bytes.fromhex("810104") + ber.encode_tlv(0xA2, float_type))
    decoded = decode_type_description(ber.decode_tlv(array))
    assert decoded.count == 4 and decoded.element == PrimitiveType("float", 32)  # type: ignore[union-attr]


# The shape of a CMV member (phsA) in the VMC7 reports.
CMV_TYPE = StructureType([
    ("cVal", StructureType([
        ("mag", StructureType([("f", PrimitiveType("float", 32))])),
        ("ang", StructureType([("f", PrimitiveType("float", 32))])),
    ])),
    ("range", PrimitiveType("integer", 8)),
    ("rangeAng", PrimitiveType("integer", 8)),
    ("q", PrimitiveType("bit-string", -13)),
    ("t", PrimitiveType("utc-time")),
])
T = datetime(2026, 9, 24, 9, 19, 15, 501570, tzinfo=timezone.utc)
CMV_VALUE = StructureData([
    StructureData([StructureData([FloatData(0.0)]), StructureData([FloatData(0.0)])]),
    IntData(0),
    IntData(0),
    BitStringData(b"\x42\x00", 3),
    TimestampData(T, quality=0x67),
])


def test_label_names_every_leaf() -> None:
    assert [path for path, _ in label(CMV_VALUE, CMV_TYPE)] == [
        "cVal.mag.f", "cVal.ang.f", "range", "rangeAng", "q", "t",
    ]
    # Without a type, leaves are numbered.
    assert [path for path, _ in label(CMV_VALUE, None)][:2] == ["0.0.0", "0.1.0"]
    assert label(BoolData(True), None) == [("", BoolData(True))]


def test_quality_and_time_quality() -> None:
    assert str(Quality.from_bitstring(BitStringData(b"\x42\x00", 3))) == "invalid,failure"
    assert str(Quality.from_bitstring(BitStringData(b"\x40\x00", 3))) == "invalid"
    assert str(Quality.from_bitstring(BitStringData(b"\xc0\x30", 3))) == "questionable,substituted,test"
    assert str(Quality.from_bitstring(BitStringData(b"\x00\x00", 3))) == "good"
    assert str(TimeQuality.from_octet(0x67)) == "clock-failure,not-synchronized,accuracy=7bits"
    assert str(TimeQuality.from_octet(0x0A)) == "accuracy=10bits"


def test_format_value() -> None:
    assert format_value(CMV_VALUE, CMV_TYPE) == (
        "cVal.mag.f=0.0  cVal.ang.f=0.0  range=0  rangeAng=0  q=invalid,failure  "
        "t=2026-09-24 09:19:15.501 [clock-failure,not-synchronized,accuracy=7bits]"
    )
