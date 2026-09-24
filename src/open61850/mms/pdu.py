# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""MMS PDUs (ISO 9506-2) as used by IEC 61850-8-1 clients.

Once associated, every MMS PDU travels as::

    01 00 01 00               Session: Give-Tokens + Data-Transfer SPDUs
    61 L 30 L                 Presentation: fully-encoded-data, PDV-list
       02 01 03               presentation-context-identifier (MMS)
       a0 L <MMS PDU>         single-ASN1-type

:func:`wrap` and :func:`unwrap` handle that envelope. Encoders return the
bare MMS PDU; decoders take it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

from .. import ber
from ..data import IECData, decode_data, encode_data
from .errors import DataAccessError, MmsProtocolError

SESSION_DATA = b"\x01\x00\x01\x00"
MMS_PRESENTATION_CONTEXT = 3

# MMSpdu CHOICE
TAG_CONFIRMED_REQUEST = 0xA0
TAG_CONFIRMED_RESPONSE = 0xA1
TAG_CONFIRMED_ERROR = 0xA2
TAG_UNCONFIRMED = 0xA3
TAG_REJECT = 0xA4
TAG_CONCLUDE_REQUEST = 0x8B
TAG_CONCLUDE_RESPONSE = 0x8C

# ConfirmedServiceRequest / Response CHOICE
SERVICE_GET_NAME_LIST = 1
SERVICE_READ = 4
SERVICE_WRITE = 5
SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES = 6
SERVICE_GET_NAMED_VARIABLE_LIST_ATTRIBUTES = 12

# GetNameList basicObjectClass
OBJECT_CLASS_NAMED_VARIABLE = 0
OBJECT_CLASS_NAMED_VARIABLE_LIST = 2
OBJECT_CLASS_DOMAIN = 9

# Association request replayed from a capture accepted by the target IEDs:
# Session CONNECT, Presentation CP-type, ACSE AARQ (IEC 61850 application
# context) and MMS Initiate-RequestPDU. A built encoder will replace it.
INITIATE_REQUEST = bytes.fromhex(
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
_SPDU_ACCEPT = 0x0E
_SPDU_REFUSE = 0x0C


# --- names -------------------------------------------------------------------


@dataclass(frozen=True)
class ObjectName:
    """An MMS object name: domain-specific when ``domain`` is set, vmd-specific otherwise."""

    item: str
    domain: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.domain}/{self.item}" if self.domain else self.item


def encode_object_name(name: ObjectName) -> bytes:
    if name.domain is None:
        return ber.encode_tlv(0x80, name.item.encode("ascii"))
    ids = ber.encode_tlv(0x1A, name.domain.encode("ascii")) + ber.encode_tlv(0x1A, name.item.encode("ascii"))
    return ber.encode_tlv(0xA1, ids)


def decode_object_name(tlv: ber.Tlv) -> ObjectName:
    if tlv.tag == 0x80:
        return ObjectName(tlv.value.decode("ascii", errors="replace"))
    if tlv.tag == 0xA1:
        domain, item = (t.value.decode("ascii", errors="replace") for t in ber.iter_tlvs(tlv.value))
        return ObjectName(item, domain)
    raise MmsProtocolError(f"unsupported ObjectName tag 0x{tlv.tag:X}")


def _variable_list(names: list[ObjectName]) -> bytes:
    """VariableAccessSpecification listOfVariable [0]."""
    items = b"".join(
        ber.encode_tlv(0x30, ber.encode_tlv(0xA0, encode_object_name(n))) for n in names
    )
    return ber.encode_tlv(0xA0, items)


def _decode_variable_list(content: bytes) -> list[ObjectName]:
    names = []
    for entry in ber.iter_tlvs(content):
        spec = ber.decode_tlv(entry.value)  # variableSpecification
        if spec.tag != 0xA0:
            raise MmsProtocolError(f"unsupported variableSpecification tag 0x{spec.tag:X}")
        names.append(decode_object_name(ber.decode_tlv(spec.value)))
    return names


# --- envelope ----------------------------------------------------------------


def wrap(mms_pdu: bytes) -> bytes:
    """Put an MMS PDU in the session and presentation data envelope."""
    pdv = ber.encode_tlv(0x02, bytes([MMS_PRESENTATION_CONTEXT])) + ber.encode_tlv(0xA0, mms_pdu)
    return SESSION_DATA + ber.encode_tlv(0x61, ber.encode_tlv(0x30, pdv))


def unwrap(user_data: bytes) -> bytes:
    """Extract the MMS PDU from a session data transfer."""
    if not user_data.startswith(SESSION_DATA):
        raise MmsProtocolError(f"not a session data transfer: {user_data[:4].hex()}")
    try:
        pres = ber.expect_tlv(user_data, len(SESSION_DATA), 0x61)
        pdv = ber.expect_tlv(pres.value, 0, 0x30)
        single = [t for t in ber.iter_tlvs(pdv.value) if t.tag == 0xA0]
    except ber.BerError as exc:
        raise MmsProtocolError(f"bad presentation envelope: {exc}") from exc
    if not single:
        raise MmsProtocolError("presentation data without single-ASN1-type")
    return single[0].value


def check_initiate_response(user_data: bytes) -> None:
    """Raise unless the association response is a session ACCEPT."""
    if not user_data:
        raise MmsProtocolError("empty association response")
    if user_data[0] == _SPDU_REFUSE:
        raise MmsProtocolError("association refused (session REFUSE)")
    if user_data[0] != _SPDU_ACCEPT:
        raise MmsProtocolError(f"unexpected association response SPDU 0x{user_data[0]:02x}")


# --- requests ----------------------------------------------------------------


def confirmed_request(invoke_id: int, service: bytes) -> bytes:
    body = ber.encode_tlv(0x02, ber.encode_unsigned(invoke_id)) + service
    return ber.encode_tlv(TAG_CONFIRMED_REQUEST, body)


def conclude_request() -> bytes:
    return ber.encode_tlv(TAG_CONCLUDE_REQUEST)


def read_request(names: list[ObjectName]) -> bytes:
    """Read-Request with specificationWithResult omitted (FALSE)."""
    spec = ber.encode_tlv(0xA1, _variable_list(names))
    return ber.encode_tlv(ber.make_tag(SERVICE_READ, constructed=True), spec)


def write_request(names: list[ObjectName], values: list[IECData]) -> bytes:
    if len(names) != len(values):
        raise ValueError("write needs one value per variable")
    data = ber.encode_tlv(0xA0, b"".join(encode_data(v) for v in values))
    return ber.encode_tlv(ber.make_tag(SERVICE_WRITE, constructed=True), _variable_list(names) + data)


def get_name_list_request(
    object_class: int, domain: Optional[str] = None, continue_after: Optional[str] = None
) -> bytes:
    content = ber.encode_tlv(0xA0, ber.encode_tlv(0x80, ber.encode_unsigned(object_class)))
    scope = ber.encode_tlv(0x80) if domain is None else ber.encode_tlv(0x81, domain.encode("ascii"))
    content += ber.encode_tlv(0xA1, scope)
    if continue_after is not None:
        content += ber.encode_tlv(0x82, continue_after.encode("ascii"))
    return ber.encode_tlv(ber.make_tag(SERVICE_GET_NAME_LIST, constructed=True), content)


def get_variable_access_attributes_request(name: ObjectName) -> bytes:
    """GetVariableAccessAttributes-Request, name [0] form."""
    tag = ber.make_tag(SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES, constructed=True)
    return ber.encode_tlv(tag, ber.encode_tlv(0xA0, encode_object_name(name)))


def get_named_variable_list_attributes_request(name: ObjectName) -> bytes:
    tag = ber.make_tag(SERVICE_GET_NAMED_VARIABLE_LIST_ATTRIBUTES, constructed=True)
    return ber.encode_tlv(tag, encode_object_name(name))


# --- incoming PDUs -----------------------------------------------------------


AccessResult = Union[IECData, DataAccessError]


@dataclass
class ConfirmedResponse:
    invoke_id: int
    service: int  # ConfirmedServiceResponse tag number
    content: bytes


@dataclass
class ConfirmedError:
    invoke_id: int
    error_class: int
    code: int


@dataclass
class Reject:
    invoke_id: Optional[int]
    reason_tag: int
    code: int


@dataclass
class InformationReport:
    """An unconfirmed informationReport.

    IEC 61850 reports use the variable list name ``RPT`` (vmd-specific);
    control notifications (LastApplError, CommandTermination) use a list of
    variables.
    """

    list_name: Optional[ObjectName]
    variables: list[ObjectName] = field(default_factory=list)
    results: list[AccessResult] = field(default_factory=list)


@dataclass
class ConcludeResponse:
    pass


IncomingPdu = Union[ConfirmedResponse, ConfirmedError, Reject, InformationReport, ConcludeResponse]


def _decode_access_results(content: bytes) -> list[AccessResult]:
    results: list[AccessResult] = []
    for tlv in ber.iter_tlvs(content):
        if tlv.tag == 0x80:
            results.append(DataAccessError(ber.decode_integer(tlv.value)))
        else:
            results.append(decode_data(tlv.tag, tlv.value))
    return results


def decode_pdu(mms_pdu: bytes) -> IncomingPdu:
    """Decode an MMS PDU received from a server."""
    try:
        outer = ber.decode_tlv(mms_pdu)
        if outer.tag == TAG_CONFIRMED_RESPONSE:
            invoke, service = list(ber.iter_tlvs(outer.value))[:2]
            return ConfirmedResponse(ber.decode_unsigned(invoke.value), ber.tag_number(service.tag), service.value)
        if outer.tag == TAG_CONFIRMED_ERROR:
            fields = {t.tag: t for t in ber.iter_tlvs(outer.value)}
            error = ber.decode_tlv(fields[0xA2].value)  # errorClass [0]
            klass = ber.decode_tlv(error.value)
            return ConfirmedError(
                ber.decode_unsigned(fields[0x80].value), ber.tag_number(klass.tag), ber.decode_integer(klass.value)
            )
        if outer.tag == TAG_REJECT:
            invoke_id = None
            reason_tag, code = -1, -1
            for t in ber.iter_tlvs(outer.value):
                if t.tag == 0x80:
                    invoke_id = ber.decode_unsigned(t.value)
                else:
                    reason_tag, code = ber.tag_number(t.tag), ber.decode_integer(t.value)
            return Reject(invoke_id, reason_tag, code)
        if outer.tag == TAG_UNCONFIRMED:
            service = ber.decode_tlv(outer.value)
            if service.tag != 0xA0:
                raise MmsProtocolError(f"unsupported unconfirmed service 0x{service.tag:X}")
            spec, results = list(ber.iter_tlvs(service.value))[:2]
            report = InformationReport(None, results=_decode_access_results(results.value))
            if spec.tag == 0xA1:
                report.list_name = decode_object_name(ber.decode_tlv(spec.value))
            elif spec.tag == 0xA0:
                report.variables = _decode_variable_list(spec.value)
            return report
        if outer.tag == TAG_CONCLUDE_RESPONSE:
            return ConcludeResponse()
    except (ber.BerError, KeyError, ValueError) as exc:
        raise MmsProtocolError(f"undecodable MMS PDU: {exc}") from exc
    raise MmsProtocolError(f"unsupported MMS PDU tag 0x{outer.tag:X}")


def read_response(content: bytes) -> list[AccessResult]:
    """Results of a Read-Response, in request order."""
    for tlv in ber.iter_tlvs(content):
        if tlv.tag == 0xA1:
            return _decode_access_results(tlv.value)
    raise MmsProtocolError("Read-Response without listOfAccessResult")


def write_response(content: bytes) -> list[Optional[DataAccessError]]:
    """None for each variable written, a DataAccessError for each failure."""
    out: list[Optional[DataAccessError]] = []
    for tlv in ber.iter_tlvs(content):
        if tlv.tag == 0x80:
            out.append(DataAccessError(ber.decode_integer(tlv.value)))
        elif tlv.tag == 0x81:
            out.append(None)
        else:
            raise MmsProtocolError(f"unexpected Write-Response tag 0x{tlv.tag:X}")
    return out


def get_name_list_response(content: bytes) -> tuple[list[str], bool]:
    names: list[str] = []
    more_follows = True
    for tlv in ber.iter_tlvs(content):
        if tlv.tag == 0xA0:
            names = [n.value.decode("ascii", errors="replace") for n in ber.iter_tlvs(tlv.value)]
        elif tlv.tag == 0x81:
            more_follows = ber.decode_boolean(tlv.value)
    return names, more_follows


def get_named_variable_list_attributes_response(content: bytes) -> list[ObjectName]:
    for tlv in ber.iter_tlvs(content):
        if tlv.tag == 0xA1:
            return _decode_variable_list(tlv.value)
    raise MmsProtocolError("GetNamedVariableListAttributes-Response without listOfVariable")
