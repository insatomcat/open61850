# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""open61850.mms.association: the association request and the server's answer."""

from __future__ import annotations

import json

import pytest
from conftest import DATA_DIR

from open61850 import ber
from open61850.mms import MmsProtocolError
from open61850.mms.association import (
    AssociationError,
    AssociationParameters,
    aarq,
    association_request,
    decode_association_response,
    decode_initiate_response,
)

RESPONSES = json.loads((DATA_DIR / "association_responses.json").read_text())

# The association po replayed from a capture before the encoder existed; the
# IEDs accept it, so the default parameters must still give these bytes.
REPLAYED_REQUEST = bytes.fromhex(
    "0db20506130100160102140200023302000134020001"
    "c19c318199a003800101a28191810400000001820400000001"
    "a423300f0201010604520100013004060251013010020103"
    "060528ca220201300406025101615e305c020101a0576055"
    "a107060528ca220203a20706052901876701a30302010c"
    "a606060429018767a70302010c"
    "be2f282d020103a028a826"
    "800300fde881010582010583010a"
    "a416800101810305f100"
    "820c03ee1c00000408000079ef18"
)


def _response(name: str) -> bytes:
    return bytes.fromhex(RESPONSES[name])


def test_default_request_is_the_replayed_one() -> None:
    assert association_request() == REPLAYED_REQUEST


def test_request_parameters() -> None:
    params = AssociationParameters(
        max_pdu_size=None, max_outstanding=2, nesting_level=None,
        calling_ap_title=None, calling_ae_qualifier=None, called_ap_title=None, called_ae_qualifier=None,
    )
    apdu = ber.decode_tlv(aarq(params))
    assert [t.tag for t in ber.iter_tlvs(apdu.value)] == [0xA1, 0xBE]  # context name and user-information only
    initiate = ber.decode_tlv(apdu.value, len(ber.encode_tlv(0xA1, b"\x06\x05" + bytes(5))))
    external = ber.decode_tlv(initiate.value)
    single = [t for t in ber.iter_tlvs(external.value) if t.tag == 0xA0][0]
    fields = {t.tag: t.value for t in ber.iter_tlvs(ber.decode_tlv(single.value).value)}
    assert fields[0x81] == fields[0x82] == b"\x02" and 0x80 not in fields and 0x83 not in fields


def test_long_session_user_data_uses_the_three_byte_length() -> None:
    request = association_request(AssociationParameters(called_session_selector=bytes(2), calling_ap_title=(1, 1) + (999,) * 60))
    assert request[0] == 0x0D and request[1] == 0xFF
    assert int.from_bytes(request[2:4], "big") == len(request) - 4


@pytest.mark.parametrize(
    ("name", "outstanding", "nesting", "reports"),
    [("vmc7_accept", 5, 7, True), ("ssc600_accept", 1, 5, False)],
)
def test_accepted_associations(name: str, outstanding: int, nesting: int, reports: bool) -> None:
    accepted = decode_association_response(_response(name))
    assert accepted.max_pdu_size == 65000
    assert accepted.max_outstanding_calling == accepted.max_outstanding_called == outstanding
    assert accepted.nesting_level == nesting and accepted.version == 1
    assert accepted.parameter_cbb == bytes.fromhex("f100")
    for service in (0, 1, 2, 4, 5, 6, 12):  # status, getNameList, identify, read, write, GVAA, GNVLA
        assert accepted.supports(service)
    assert not accepted.supports(3)  # rename
    assert accepted.supports(79) is reports  # informationReport bit
    assert not accepted.supports(500)


def test_refusals() -> None:
    with pytest.raises(AssociationError, match="session refused"):
        decode_association_response(bytes.fromhex("0c033201" "02"))
    with pytest.raises(AssociationError, match="aborted"):
        decode_association_response(bytes.fromhex("1900"))
    rejected = _response("vmc7_accept").replace(bytes.fromhex("a203020100a305a103020100"), bytes.fromhex("a203020101a305a103020102"))
    with pytest.raises(AssociationError, match=r"rejected \(permanent\), diagnostic 2"):
        decode_association_response(rejected)
    error = ber.encode_tlv(0xAA, ber.encode_tlv(0xA0, ber.encode_tlv(0x88, b"\x01")))
    with pytest.raises(AssociationError, match="error class 8, code 1"):
        decode_initiate_response(error)


def test_malformed_responses() -> None:
    with pytest.raises(MmsProtocolError):
        decode_association_response(b"")
    with pytest.raises(MmsProtocolError, match="unexpected"):
        decode_association_response(bytes.fromhex("0100"))
    with pytest.raises(MmsProtocolError):
        decode_association_response(_response("vmc7_accept")[:60])
