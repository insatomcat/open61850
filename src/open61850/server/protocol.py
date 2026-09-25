# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The server side of the MMS protocol stack: what :mod:`open61850.mms` does for a client, reversed.

- COTP: :func:`accept_cotp` answers a connection request (CR) with a confirm (CC).
- Association: :func:`decode_association_request` reads the Session CONNECT /
  Presentation CP / ACSE AARQ / MMS initiate-RequestPDU a client sends, and
  :func:`association_accept` answers it (ACCEPT / CPA / AARE /
  initiate-ResponsePDU), laid out as a Schneider VMC7 answers, with the
  presentation contexts the client proposed.
- MMS: :func:`decode_request` reads confirmed requests; the ``*_response``
  functions, :func:`confirmed_error`, :func:`reject` and
  :func:`information_report` build what goes back.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional, Union

from .. import ber
from ..data import IECData, encode_data
from ..mms import pdu
from ..mms.association import (
    _PGI_USER_DATA,
    MMS_CONTEXT,
    OID_BER,
    OID_MMS_ABSTRACT_SYNTAX,
    OID_MMS_APPLICATION_CONTEXT,
    SPDU_ACCEPT,
    SPDU_CONNECT,
    _fields,
    _parse_spdu,
    _session_parameter,
    _spdu,
)
from ..mms.errors import MmsProtocolError
from ..mms.pdu import ObjectName, _decode_variable_list, decode_object_name, encode_object_name
from ..mms.transport import DEFAULT_TPDU_SIZE_CODE, IsoConnection, TransportError, recv_tpkt, send_tpkt
from ..mms.types import MmsType, encode_type_description

__all__ = [
    "SERVICES_SUPPORTED",
    "accept_cotp",
    "AssociationRequest",
    "decode_association_request",
    "association_accept",
    "ConfirmedRequest",
    "decode_request",
    "confirmed_response",
    "confirmed_error",
    "reject",
    "conclude_response",
    "read_response",
    "write_response",
    "get_name_list_response",
    "identify_response",
    "get_variable_access_attributes_response",
    "get_named_variable_list_attributes_response",
    "information_report",
]

_CR, _CC = 0xE0, 0xD0
_ACSE_ABSTRACT_SYNTAX = (2, 2, 1, 0, 1)

# ServiceSupportOptions bits of what the server answers (ISO 9506-2).
_SERVICES = {0: "status", 1: "getNameList", 2: "identify", 4: "read", 5: "write", 6: "getVariableAccessAttributes",
             12: "getNamedVariableListAttributes", 79: "informationReport", 83: "conclude"}


def _bits(numbers: set[int], size_bits: int) -> tuple[int, bytes]:
    raw = bytearray((size_bits + 7) // 8)
    for n in numbers:
        raw[n // 8] |= 0x80 >> (n % 8)
    return len(raw) * 8 - size_bits, bytes(raw)


SERVICES_SUPPORTED = _bits(set(_SERVICES) - {0}, 85)
PARAMETER_CBB = (5, bytes.fromhex("f100"))  # str1, str2, vnam, valt, vlis


# --- COTP --------------------------------------------------------------------


def accept_cotp(sock: socket.socket, max_tpdu_size_code: int = 0x0B) -> IsoConnection:
    """Read the client's COTP CR and confirm it; the connection then carries TSDUs."""
    cr = recv_tpkt(sock)
    if cr is None:
        raise TransportError("connection closed before COTP CR")
    if len(cr) < 7 or cr[1] & 0xF0 != _CR:
        raise TransportError(f"expected COTP CR, got {cr[:8].hex()}")
    src_ref = cr[4:6]
    size_code = DEFAULT_TPDU_SIZE_CODE
    tsaps = b""
    offset = 7
    while offset + 2 <= len(cr):
        code, length = cr[offset], cr[offset + 1]
        value = cr[offset + 2 : offset + 2 + length]
        if code == 0xC0 and length == 1:
            size_code = min(value[0], max_tpdu_size_code)
        elif code in (0xC1, 0xC2):
            tsaps += bytes([code, length]) + value
        offset += 2 + length
    body = bytes([_CC]) + src_ref + b"\x00\x01" + b"\x00" + bytes([0xC0, 1, size_code]) + tsaps
    send_tpkt(sock, bytes([len(body)]) + body)
    return IsoConnection(sock, tpdu_size=1 << size_code)


# --- association -------------------------------------------------------------


@dataclass
class AssociationRequest:
    """What a client asked for; the context identifiers are its own."""

    max_pdu_size: Optional[int]
    max_outstanding_calling: int
    max_outstanding_called: int
    nesting_level: Optional[int]
    acse_context: int = 1
    mms_context: int = MMS_CONTEXT
    called_presentation_selector: bytes = b"\x00\x00\x00\x01"
    called_ap_title: Optional[bytes] = None  # the encoded OBJECT IDENTIFIER, echoed as the responding title
    called_ae_qualifier: Optional[bytes] = None
    contexts: list[int] = field(default_factory=list)


def decode_association_request(user_data: bytes) -> AssociationRequest:
    """Read a Session CONNECT carrying CP-type / AARQ / initiate-RequestPDU."""
    si, items = _parse_spdu(user_data)
    if si != SPDU_CONNECT:
        raise MmsProtocolError(f"expected Session CONNECT, got SPDU 0x{si:02x}")
    try:
        cp = ber.expect_tlv(items[_PGI_USER_DATA], 0, 0x31)
        normal = _fields(_fields(cp.value)[0xA2])
        contexts: list[int] = []
        acse_context, mms_context = 1, MMS_CONTEXT
        for definition in ber.iter_tlvs(normal.get(0xA4, b"")):
            f = {t.tag: t.value for t in ber.iter_tlvs(definition.value)}
            identifier = ber.decode_integer(f[0x02])
            contexts.append(identifier)
            syntax = ber.decode_oid(f[0x06])
            if syntax == _ACSE_ABSTRACT_SYNTAX:
                acse_context = identifier
            elif syntax == OID_MMS_ABSTRACT_SYNTAX:
                mms_context = identifier
        pdv = ber.expect_tlv(normal[0x61], 0, 0x30)
        aarq = next(t for t in ber.iter_tlvs(pdv.value) if t.tag == 0xA0)
        acse = _fields(ber.expect_tlv(aarq.value, 0, 0x60).value)
        external = ber.expect_tlv(acse[0xBE], 0, 0x28)
        single = next(t for t in ber.iter_tlvs(external.value) if t.tag == 0xA0)
        initiate = ber.expect_tlv(single.value, 0, 0xA8)
        f = _fields(initiate.value)
        return AssociationRequest(
            max_pdu_size=ber.decode_integer(f[0x80]) if 0x80 in f else None,
            max_outstanding_calling=ber.decode_integer(f[0x81]),
            max_outstanding_called=ber.decode_integer(f[0x82]),
            nesting_level=ber.decode_integer(f[0x83]) if 0x83 in f else None,
            acse_context=acse_context, mms_context=mms_context,
            called_presentation_selector=normal.get(0x82, b"\x00\x00\x00\x01"),
            called_ap_title=acse.get(0xA2), called_ae_qualifier=acse.get(0xA3),
            contexts=contexts,
        )
    except (KeyError, StopIteration, ber.BerError) as exc:
        raise MmsProtocolError(f"bad association request: {exc}") from exc


def association_accept(request: AssociationRequest, *, max_pdu_size: int, max_outstanding: int,
                       nesting_level: int) -> tuple[bytes, int]:
    """The ACCEPT SPDU answering ``request``, and the PDU size agreed."""
    pdu_size = min(max_pdu_size, request.max_pdu_size or max_pdu_size)
    detail = (ber.encode_tlv(0x80, ber.encode_integer(1))
              + ber.encode_tlv(0x81, bytes([PARAMETER_CBB[0]]) + PARAMETER_CBB[1])
              + ber.encode_tlv(0x82, bytes([SERVICES_SUPPORTED[0]]) + SERVICES_SUPPORTED[1]))
    initiate = ber.encode_tlv(0xA9, (
        ber.encode_tlv(0x80, ber.encode_integer(pdu_size))
        + ber.encode_tlv(0x81, ber.encode_integer(min(max_outstanding, request.max_outstanding_calling)))
        + ber.encode_tlv(0x82, ber.encode_integer(min(max_outstanding, request.max_outstanding_called)))
        + ber.encode_tlv(0x83, ber.encode_integer(min(nesting_level, request.nesting_level or nesting_level)))
        + ber.encode_tlv(0xA4, detail)
    ))
    external = ber.encode_tlv(0x28, ber.encode_tlv(0x02, ber.encode_integer(request.mms_context))
                              + ber.encode_tlv(0xA0, initiate))
    aare_body = (
        ber.encode_tlv(0x80, b"\x07\x80")  # protocol-version 1
        + ber.encode_tlv(0xA1, ber.encode_tlv(0x06, ber.encode_oid(OID_MMS_APPLICATION_CONTEXT)))
        + ber.encode_tlv(0xA2, ber.encode_tlv(0x02, b"\x00"))  # result: accepted
        + ber.encode_tlv(0xA3, ber.encode_tlv(0xA1, ber.encode_tlv(0x02, b"\x00")))  # acse-service-user: null
    )
    if request.called_ap_title is not None:
        aare_body += ber.encode_tlv(0xA4, request.called_ap_title)
    if request.called_ae_qualifier is not None:
        aare_body += ber.encode_tlv(0xA5, request.called_ae_qualifier)
    aare = ber.encode_tlv(0x61, aare_body + ber.encode_tlv(0xBE, external))
    transfer = ber.encode_tlv(0x81, ber.encode_oid(OID_BER))
    results = b"".join(ber.encode_tlv(0x30, ber.encode_tlv(0x80, b"\x00") + transfer) for _ in request.contexts or [1, 3])
    pdv = ber.encode_tlv(0x02, ber.encode_integer(request.acse_context)) + ber.encode_tlv(0xA0, aare)
    normal = (
        ber.encode_tlv(0x83, request.called_presentation_selector)
        + ber.encode_tlv(0xA5, results)
        + ber.encode_tlv(0x61, ber.encode_tlv(0x30, pdv))
    )
    cpa = ber.encode_tlv(0x31, ber.encode_tlv(0xA0, ber.encode_tlv(0x80, b"\x01")) + ber.encode_tlv(0xA2, normal))
    item = _session_parameter(19, b"\x00") + _session_parameter(22, b"\x02")
    parameters = (_session_parameter(5, item) + _session_parameter(20, b"\x00\x02")
                  + _session_parameter(_PGI_USER_DATA, cpa))
    return _spdu(SPDU_ACCEPT, parameters), pdu_size


# --- requests ----------------------------------------------------------------


@dataclass
class ConfirmedRequest:
    invoke_id: int
    service: int  # ConfirmedServiceRequest tag number
    content: bytes


IncomingRequest = Union[ConfirmedRequest, str]  # or "conclude"


def decode_request(mms_pdu: bytes) -> IncomingRequest:
    try:
        outer = ber.decode_tlv(mms_pdu)
        if outer.tag == pdu.TAG_CONCLUDE_REQUEST:
            return "conclude"
        if outer.tag != pdu.TAG_CONFIRMED_REQUEST:
            raise MmsProtocolError(f"unsupported MMS PDU tag 0x{outer.tag:X}")
        invoke, service = list(ber.iter_tlvs(outer.value))[:2]
        return ConfirmedRequest(ber.decode_unsigned(invoke.value), ber.tag_number(service.tag), service.value)
    except (ber.BerError, ValueError) as exc:
        raise MmsProtocolError(f"undecodable MMS request: {exc}") from exc


def variable_access(content: bytes) -> Union[list[ObjectName], ObjectName]:
    """A VariableAccessSpecification: a list of variables, or the name of a variable list."""
    tlv = ber.decode_tlv(content)
    if tlv.tag == 0xA0:
        return _decode_variable_list(tlv.value)
    if tlv.tag == 0xA1:
        return decode_object_name(ber.decode_tlv(tlv.value))
    raise MmsProtocolError(f"unsupported VariableAccessSpecification 0x{tlv.tag:X}")


def read_request(content: bytes) -> tuple[Union[list[ObjectName], ObjectName], bool]:
    """(variables, specificationWithResult) of a Read-Request."""
    with_result = False
    spec: Optional[bytes] = None
    for tlv in ber.iter_tlvs(content):
        if tlv.tag == 0x80:
            with_result = ber.decode_boolean(tlv.value)
        elif tlv.tag == 0xA1:
            spec = tlv.value
    if spec is None:
        raise MmsProtocolError("Read-Request without variableAccessSpecification")
    return variable_access(spec), with_result


def write_request(content: bytes) -> tuple[Union[list[ObjectName], ObjectName], list[IECData]]:
    from ..data import decode_data_sequence

    spec, data = list(ber.iter_tlvs(content))[:2]
    variables = _decode_variable_list(spec.value) if spec.tag == 0xA0 else decode_object_name(ber.decode_tlv(spec.value))
    return variables, decode_data_sequence(data.value)


def get_name_list_request(content: bytes) -> tuple[int, Optional[str], Optional[str]]:
    """(objectClass, domain or None for vmd scope, continueAfter)."""
    f = _fields(content)
    object_class = ber.decode_unsigned(ber.decode_tlv(f[0xA0]).value)
    scope = ber.decode_tlv(f[0xA1])
    domain = scope.value.decode("ascii") if scope.tag == 0x81 else None
    continue_after = f[0x82].decode("ascii") if 0x82 in f else None
    return object_class, domain, continue_after


def object_name_request(content: bytes) -> ObjectName:
    """The ObjectName of GetVariableAccessAttributes ([0] name) or GetNamedVariableListAttributes."""
    tlv = ber.decode_tlv(content)
    if tlv.tag == 0xA0:  # GetVariableAccessAttributes name [0]
        return decode_object_name(ber.decode_tlv(tlv.value))
    return decode_object_name(tlv)


# --- responses ---------------------------------------------------------------


def confirmed_response(invoke_id: int, service: int, content: bytes, *, constructed: bool = True) -> bytes:
    body = (ber.encode_tlv(0x02, ber.encode_unsigned(invoke_id))
            + ber.encode_tlv(ber.make_tag(service, constructed=constructed), content))
    return ber.encode_tlv(pdu.TAG_CONFIRMED_RESPONSE, body)


def confirmed_error(invoke_id: int, error_class: int, code: int) -> bytes:
    """A confirmed-ErrorPDU (error class: 2 definition, 3 resource, 4 service, 7 access...)."""
    error = ber.encode_tlv(0xA0, ber.encode_tlv(ber.make_tag(error_class), ber.encode_integer(code)))
    body = ber.encode_tlv(0x80, ber.encode_unsigned(invoke_id)) + ber.encode_tlv(0xA2, error)
    return ber.encode_tlv(pdu.TAG_CONFIRMED_ERROR, body)


def reject(invoke_id: Optional[int], reason: int = 1, code: int = 1) -> bytes:
    """A RejectPDU; by default confirmed-requestPDU [1], unrecognized-service (1)."""
    body = b"" if invoke_id is None else ber.encode_tlv(0x80, ber.encode_unsigned(invoke_id))
    return ber.encode_tlv(pdu.TAG_REJECT, body + ber.encode_tlv(ber.make_tag(reason), ber.encode_integer(code)))


def conclude_response() -> bytes:
    return ber.encode_tlv(pdu.TAG_CONCLUDE_RESPONSE)


def _access_results(results: list[Union[IECData, int]]) -> bytes:
    return b"".join(ber.encode_tlv(0x80, ber.encode_integer(r)) if isinstance(r, int) else encode_data(r) for r in results)


def read_response(results: list[Union[IECData, int]], spec: Optional[bytes] = None) -> bytes:
    """Read-Response content; an int in ``results`` is a DataAccessError code."""
    head = ber.encode_tlv(0xA0, spec) if spec is not None else b""
    return head + ber.encode_tlv(0xA1, _access_results(results))


def write_response(errors: list[Optional[int]]) -> bytes:
    return b"".join(ber.encode_tlv(0x81) if e is None else ber.encode_tlv(0x80, ber.encode_integer(e)) for e in errors)


def get_name_list_response(names: list[str], more_follows: bool) -> bytes:
    listed = b"".join(ber.encode_tlv(0x1A, n.encode("ascii")) for n in names)
    return ber.encode_tlv(0xA0, listed) + ber.encode_tlv(0x81, ber.encode_boolean(more_follows))


def identify_response(vendor: str, model: str, revision: str) -> bytes:
    return (ber.encode_tlv(0x80, vendor.encode("ascii")) + ber.encode_tlv(0x81, model.encode("ascii"))
            + ber.encode_tlv(0x82, revision.encode("ascii")))


def get_variable_access_attributes_response(mms_type: MmsType) -> bytes:
    return ber.encode_tlv(0x80, ber.encode_boolean(False)) + ber.encode_tlv(0xA2, encode_type_description(mms_type))


def get_named_variable_list_attributes_response(members: list[ObjectName]) -> bytes:
    items = b"".join(ber.encode_tlv(0x30, ber.encode_tlv(0xA0, encode_object_name(n))) for n in members)
    return ber.encode_tlv(0x80, ber.encode_boolean(False)) + ber.encode_tlv(0xA1, items)


def information_report(values: list[Union[IECData, int]], *, list_name: Optional[str] = None,
                       variables: Optional[list[ObjectName]] = None) -> bytes:
    """An unconfirmed informationReport: on a named list (``RPT``) or on a list of variables."""
    if list_name is not None:
        spec = ber.encode_tlv(0xA1, ber.encode_tlv(0x80, list_name.encode("ascii")))
    else:
        spec = ber.encode_tlv(0xA0, b"".join(ber.encode_tlv(0x30, ber.encode_tlv(0xA0, encode_object_name(n)))
                                             for n in variables or []))
    report = ber.encode_tlv(0xA0, spec + ber.encode_tlv(0xA0, _access_results(values)))
    return ber.encode_tlv(pdu.TAG_UNCONFIRMED, report)
