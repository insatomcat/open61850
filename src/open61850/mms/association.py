# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""MMS association: the Initiate exchange and the layers that carry it.

An IEC 61850-8-1 client associates with one request that nests four
protocols, each in the user data of the one below::

    Session CONNECT SPDU (ISO 8327-1)
      Presentation CP-type (ISO 8823-1), normal mode, two contexts:
        1 = ACSE (2.2.1.0.1), 3 = MMS (1.0.9506.2.1), both BER (2.1.1)
        ACSE AARQ (ISO 8650-1), application context MMS (1.0.9506.2.3)
          user-information EXTERNAL, presentation context 3:
            MMS initiate-RequestPDU (ISO 9506-2)

The server answers with Session ACCEPT / CPA-PPDU / AARE / initiate-ResponsePDU,
which carry the negotiated limits: largest PDU, outstanding requests, data
nesting and the services the server supports. :func:`association_request`
builds the request from :class:`AssociationParameters` (the defaults give
the bytes po has always sent); :func:`decode_association_response` returns
an :class:`Association` or raises :class:`AssociationError`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .. import ber
from .errors import MmsConnectionError, MmsProtocolError

__all__ = [
    "OID_ACSE",
    "OID_MMS_ABSTRACT_SYNTAX",
    "OID_BER",
    "OID_MMS_APPLICATION_CONTEXT",
    "ACSE_CONTEXT",
    "MMS_CONTEXT",
    "SPDU_CONNECT",
    "SPDU_ACCEPT",
    "SPDU_REFUSE",
    "SPDU_ABORT",
    "DEFAULT_PARAMETER_CBB",
    "DEFAULT_SERVICES_SUPPORTED",
    "AARE_RESULTS",
    "AssociationError",
    "AssociationParameters",
    "Association",
    "initiate_request",
    "aarq",
    "cp_type",
    "association_request",
    "decode_initiate_response",
    "decode_aare",
    "decode_association_response",
]


OID_ACSE = (2, 2, 1, 0, 1)
OID_MMS_ABSTRACT_SYNTAX = (1, 0, 9506, 2, 1)
OID_BER = (2, 1, 1)
OID_MMS_APPLICATION_CONTEXT = (1, 0, 9506, 2, 3)
ACSE_CONTEXT = 1
MMS_CONTEXT = 3

# Session SPDU identifiers and parameters (ISO 8327-1)
SPDU_CONNECT = 0x0D
SPDU_ACCEPT = 0x0E
SPDU_REFUSE = 0x0C
SPDU_ABORT = 0x19
_PGI_CONNECT_ACCEPT_ITEM = 5
_PI_PROTOCOL_OPTIONS = 19
_PI_VERSION_NUMBER = 22
_PI_SESSION_REQUIREMENTS = 20
_PI_CALLING_SSEL = 51
_PI_CALLED_SSEL = 52
_PI_REASON_CODE = 50
_PGI_USER_DATA = 193

# MMS ParameterSupportOptions (str1, str2, vnam, valt, vlis) and
# ServiceSupportOptions as po has always proposed them.
DEFAULT_PARAMETER_CBB = (5, bytes.fromhex("f100"))
DEFAULT_SERVICES_SUPPORTED = (3, bytes.fromhex("ee1c00000408000079ef18"))

AARE_RESULTS = {0: "accepted", 1: "rejected (permanent)", 2: "rejected (transient)"}


class AssociationError(MmsConnectionError):
    """The server refused the association, at whichever layer."""


@dataclass(frozen=True)
class AssociationParameters:
    """What the client proposes. ``None`` leaves an optional field out."""

    max_pdu_size: Optional[int] = 65000  # localDetailCalling
    max_outstanding: int = 5  # proposedMaxServOutstandingCalling and ...Called
    nesting_level: Optional[int] = 10  # proposedDataStructureNestingLevel
    version: int = 1
    parameter_cbb: tuple[int, bytes] = DEFAULT_PARAMETER_CBB  # (unused bits, bytes)
    services_supported: tuple[int, bytes] = DEFAULT_SERVICES_SUPPORTED
    calling_ap_title: Optional[tuple[int, ...]] = (1, 1, 1, 999)
    calling_ae_qualifier: Optional[int] = 12
    called_ap_title: Optional[tuple[int, ...]] = (1, 1, 1, 999, 1)
    called_ae_qualifier: Optional[int] = 12
    calling_session_selector: bytes = b"\x00\x01"
    called_session_selector: bytes = b"\x00\x01"
    calling_presentation_selector: bytes = b"\x00\x00\x00\x01"
    called_presentation_selector: bytes = b"\x00\x00\x00\x01"


@dataclass(frozen=True)
class Association:
    """What the server accepted (initiate-ResponsePDU)."""

    max_pdu_size: Optional[int]  # localDetailCalled
    max_outstanding_calling: int  # requests this client may have in flight
    max_outstanding_called: int
    nesting_level: Optional[int]
    version: int
    parameter_cbb: bytes
    services_supported: bytes  # ServiceSupportOptions without the unused-bits octet

    def supports(self, service: int) -> bool:
        """Whether bit ``service`` of ServiceSupportOptions is set (read = 4, write = 5, ...)."""
        byte, bit = divmod(service, 8)
        return byte < len(self.services_supported) and bool(self.services_supported[byte] & (0x80 >> bit))


# --- encoding ----------------------------------------------------------------


def _spdu(si: int, parameters: bytes) -> bytes:
    return bytes([si]) + _session_length(len(parameters)) + parameters


def _session_length(length: int) -> bytes:
    return bytes([length]) if length < 255 else b"\xff" + length.to_bytes(2, "big")


def _session_parameter(code: int, value: bytes) -> bytes:
    return bytes([code]) + _session_length(len(value)) + value


def _bit_string(value: tuple[int, bytes]) -> bytes:
    unused, data = value
    return bytes([unused]) + data


def _context(identifier: int, abstract_syntax: tuple[int, ...]) -> bytes:
    transfer = ber.encode_tlv(0x30, ber.encode_tlv(0x06, ber.encode_oid(OID_BER)))
    return ber.encode_tlv(
        0x30,
        ber.encode_tlv(0x02, ber.encode_integer(identifier))
        + ber.encode_tlv(0x06, ber.encode_oid(abstract_syntax))
        + transfer,
    )


def initiate_request(params: AssociationParameters) -> bytes:
    """MMS initiate-RequestPDU [8]."""
    body = b""
    if params.max_pdu_size is not None:
        body += ber.encode_tlv(0x80, ber.encode_integer(params.max_pdu_size))
    body += ber.encode_tlv(0x81, ber.encode_integer(params.max_outstanding))
    body += ber.encode_tlv(0x82, ber.encode_integer(params.max_outstanding))
    if params.nesting_level is not None:
        body += ber.encode_tlv(0x83, ber.encode_integer(params.nesting_level))
    detail = (
        ber.encode_tlv(0x80, ber.encode_integer(params.version))
        + ber.encode_tlv(0x81, _bit_string(params.parameter_cbb))
        + ber.encode_tlv(0x82, _bit_string(params.services_supported))
    )
    return ber.encode_tlv(0xA8, body + ber.encode_tlv(0xA4, detail))


def aarq(params: AssociationParameters) -> bytes:
    """ACSE AARQ-apdu carrying the MMS initiate-RequestPDU."""
    body = ber.encode_tlv(0xA1, ber.encode_tlv(0x06, ber.encode_oid(OID_MMS_APPLICATION_CONTEXT)))
    if params.called_ap_title is not None:
        body += ber.encode_tlv(0xA2, ber.encode_tlv(0x06, ber.encode_oid(params.called_ap_title)))
    if params.called_ae_qualifier is not None:
        body += ber.encode_tlv(0xA3, ber.encode_tlv(0x02, ber.encode_integer(params.called_ae_qualifier)))
    if params.calling_ap_title is not None:
        body += ber.encode_tlv(0xA6, ber.encode_tlv(0x06, ber.encode_oid(params.calling_ap_title)))
    if params.calling_ae_qualifier is not None:
        body += ber.encode_tlv(0xA7, ber.encode_tlv(0x02, ber.encode_integer(params.calling_ae_qualifier)))
    external = ber.encode_tlv(
        0x28,
        ber.encode_tlv(0x02, ber.encode_integer(MMS_CONTEXT)) + ber.encode_tlv(0xA0, initiate_request(params)),
    )
    body += ber.encode_tlv(0xBE, external)
    return ber.encode_tlv(0x60, body)


def cp_type(params: AssociationParameters) -> bytes:
    """Presentation CP-type (normal mode) carrying the AARQ."""
    contexts = _context(ACSE_CONTEXT, OID_ACSE) + _context(MMS_CONTEXT, OID_MMS_ABSTRACT_SYNTAX)
    pdv = ber.encode_tlv(0x02, ber.encode_integer(ACSE_CONTEXT)) + ber.encode_tlv(0xA0, aarq(params))
    normal = (
        ber.encode_tlv(0x81, params.calling_presentation_selector)
        + ber.encode_tlv(0x82, params.called_presentation_selector)
        + ber.encode_tlv(0xA4, contexts)
        + ber.encode_tlv(0x61, ber.encode_tlv(0x30, pdv))
    )
    mode = ber.encode_tlv(0xA0, ber.encode_tlv(0x80, b"\x01"))  # normal-mode
    return ber.encode_tlv(0x31, mode + ber.encode_tlv(0xA2, normal))


def association_request(params: AssociationParameters = AssociationParameters()) -> bytes:
    """The Session CONNECT SPDU to send as the first COTP data."""
    item = _session_parameter(_PI_PROTOCOL_OPTIONS, b"\x00") + _session_parameter(_PI_VERSION_NUMBER, b"\x02")
    parameters = (
        _session_parameter(_PGI_CONNECT_ACCEPT_ITEM, item)
        + _session_parameter(_PI_SESSION_REQUIREMENTS, b"\x00\x02")  # full duplex
        + _session_parameter(_PI_CALLING_SSEL, params.calling_session_selector)
        + _session_parameter(_PI_CALLED_SSEL, params.called_session_selector)
        + _session_parameter(_PGI_USER_DATA, cp_type(params))
    )
    return _spdu(SPDU_CONNECT, parameters)


# --- decoding ----------------------------------------------------------------


def _session_items(data: bytes, offset: int, end: int) -> dict[int, bytes]:
    items: dict[int, bytes] = {}
    while offset < end:
        if offset + 2 > end:
            raise MmsProtocolError("truncated session parameter")
        code, length = data[offset], data[offset + 1]
        offset += 2
        if length == 0xFF:
            length = int.from_bytes(data[offset : offset + 2], "big")
            offset += 2
        if offset + length > end:
            raise MmsProtocolError("truncated session parameter")
        items[code] = data[offset : offset + length]
        offset += length
    return items


def _parse_spdu(data: bytes) -> tuple[int, dict[int, bytes]]:
    if len(data) < 2:
        raise MmsProtocolError("empty association response")
    si, length, offset = data[0], data[1], 2
    if length == 0xFF:
        length = int.from_bytes(data[2:4], "big")
        offset = 4
    if offset + length > len(data):
        raise MmsProtocolError("truncated session SPDU")
    return si, _session_items(data, offset, offset + length)


def _fields(content: bytes) -> dict[int, bytes]:
    return {t.tag: t.value for t in ber.iter_tlvs(content)}


def decode_initiate_response(mms_pdu: bytes) -> Association:
    """Decode an initiate-ResponsePDU [9]; raise AssociationError on initiate-ErrorPDU [10]."""
    tlv = ber.decode_tlv(mms_pdu)
    if tlv.tag == 0xAA:
        fields = [ber.decode_tlv(t.value) for t in ber.iter_tlvs(tlv.value) if t.tag == 0xA0]
        detail = f" (error class {ber.tag_number(fields[0].tag)}, code {ber.decode_integer(fields[0].value)})" if fields else ""
        raise AssociationError(f"MMS initiate refused{detail}")
    if tlv.tag != 0xA9:
        raise MmsProtocolError(f"expected initiate-ResponsePDU, got tag 0x{tlv.tag:X}")
    f = _fields(tlv.value)
    init_detail = _fields(f.get(0xA4, b""))
    try:
        return Association(
            max_pdu_size=ber.decode_integer(f[0x80]) if 0x80 in f else None,
            max_outstanding_calling=ber.decode_integer(f[0x81]),
            max_outstanding_called=ber.decode_integer(f[0x82]),
            nesting_level=ber.decode_integer(f[0x83]) if 0x83 in f else None,
            version=ber.decode_integer(init_detail[0x80]),
            parameter_cbb=init_detail.get(0x81, b"\x00")[1:],
            services_supported=init_detail.get(0x82, b"\x00")[1:],
        )
    except KeyError as exc:
        raise MmsProtocolError(f"initiate-ResponsePDU without field 0x{exc.args[0]:X}") from exc


def decode_aare(apdu: bytes) -> bytes:
    """Check an ACSE AARE-apdu and return the MMS PDU of its user-information."""
    tlv = ber.expect_tlv(apdu, 0, 0x61)
    f = _fields(tlv.value)
    if 0xA2 in f:
        result = ber.decode_integer(ber.decode_tlv(f[0xA2]).value)
        if result != 0:
            diagnostic = ""
            if 0xA3 in f:
                source = ber.decode_tlv(f[0xA3])
                diagnostic = f", diagnostic {ber.decode_integer(ber.decode_tlv(source.value).value)}"
            raise AssociationError(f"ACSE association {AARE_RESULTS.get(result, result)}{diagnostic}")
    if 0xBE not in f:
        raise MmsProtocolError("AARE without user-information")
    external = ber.expect_tlv(f[0xBE], 0, 0x28)
    single = [t for t in ber.iter_tlvs(external.value) if t.tag == 0xA0]
    if not single:
        raise MmsProtocolError("AARE user-information without single-ASN1-type")
    return single[0].value


def decode_association_response(user_data: bytes) -> Association:
    """Decode the server's answer to :func:`association_request`."""
    si, items = _parse_spdu(user_data)
    if si == SPDU_REFUSE:
        reason = items.get(_PI_REASON_CODE, b"")
        raise AssociationError(f"session refused (reason {reason[:1].hex() or 'none'})")
    if si == SPDU_ABORT:
        raise AssociationError("session aborted by the server")
    if si != SPDU_ACCEPT:
        raise MmsProtocolError(f"unexpected association response SPDU 0x{si:02x}")
    try:
        cp = ber.decode_tlv(items[_PGI_USER_DATA])
        if cp.tag == 0x30:
            raise AssociationError("presentation connection refused (CPR-PPDU)")
        if cp.tag != 0x31:
            raise MmsProtocolError(f"expected CPA-PPDU, got tag 0x{cp.tag:X}")
        normal = _fields(_fields(cp.value)[0xA2])
        pdv = ber.expect_tlv(normal[0x61], 0, 0x30)
        acse = [t for t in ber.iter_tlvs(pdv.value) if t.tag == 0xA0]
        if not acse:
            raise MmsProtocolError("CPA-PPDU without single-ASN1-type")
        return decode_initiate_response(decode_aare(acse[0].value))
    except KeyError as exc:
        raise MmsProtocolError(f"association response without field 0x{exc.args[0]:X}") from exc
    except ber.BerError as exc:
        raise MmsProtocolError(f"bad association response: {exc}") from exc
