# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""MMS client side of IEC 61850-8-1.

- :mod:`.transport`: TPKT and COTP over TCP.
- :mod:`.pdu`: MMS PDUs and the session/presentation envelope.
- :mod:`.client`: :class:`MmsClient`, requests matched by invokeID.
- :mod:`.report`: IEC 61850 report decoding, OptFlds / TrgOps / ReasonCode.
- :mod:`.rcb`: report control block status, reservation and enabling.
- :mod:`.control`: controls (direct and SBO, normal and enhanced security).
- :mod:`.types`: type descriptions (GetVariableAccessAttributes) and value labelling.
"""

from .client import MmsClient
from .control import ControlError, ControlResult, LastApplError, Origin, operate
from .errors import (
    DataAccessError,
    MmsConnectionError,
    MmsError,
    MmsProtocolError,
    MmsReject,
    MmsTimeout,
    ServiceError,
)
from .pdu import (
    OBJECT_CLASS_DOMAIN,
    OBJECT_CLASS_NAMED_VARIABLE,
    OBJECT_CLASS_NAMED_VARIABLE_LIST,
    InformationReport,
    ObjectName,
)
from .types import MmsType
from .report import OptFlds, ReasonCode, Report, ReportEntry, TrgOps, decode_report, is_report

__all__ = [
    "MmsClient", "ObjectName", "InformationReport", "MmsType",
    "OBJECT_CLASS_DOMAIN", "OBJECT_CLASS_NAMED_VARIABLE", "OBJECT_CLASS_NAMED_VARIABLE_LIST",
    "Report", "ReportEntry", "OptFlds", "TrgOps", "ReasonCode", "decode_report", "is_report",
    "MmsError", "MmsConnectionError", "MmsTimeout", "MmsProtocolError", "MmsReject",
    "DataAccessError", "ServiceError",
    "operate", "Origin", "ControlResult", "ControlError", "LastApplError",
]
