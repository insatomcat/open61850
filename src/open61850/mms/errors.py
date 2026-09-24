# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""MMS client exceptions (ISO 9506-2 error codes)."""

from __future__ import annotations

DATA_ACCESS_ERRORS = {
    0: "object-invalidated",
    1: "hardware-fault",
    2: "temporarily-unavailable",
    3: "object-access-denied",
    4: "object-undefined",
    5: "invalid-address",
    6: "type-unsupported",
    7: "type-inconsistent",
    8: "object-attribute-inconsistent",
    9: "object-access-unsupported",
    10: "object-non-existent",
    11: "object-value-invalid",
}

ERROR_CLASSES = {
    0: "vmd-state", 1: "application-reference", 2: "definition", 3: "resource", 4: "service",
    5: "service-preempt", 6: "time-resolution", 7: "access", 8: "initiate", 9: "conclude",
    10: "cancel", 11: "file", 12: "others",
}


class MmsError(Exception):
    """Base class of MMS client errors."""


class MmsConnectionError(MmsError, ConnectionError):
    """The association could not be established or was lost."""


class MmsTimeout(MmsError, TimeoutError):
    """No response arrived in time."""


class MmsProtocolError(MmsError):
    """The peer sent something the client cannot decode."""


class DataAccessError(MmsError):
    """A variable could not be read or written (AccessResult / Write failure)."""

    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(f"data access error {code} ({DATA_ACCESS_ERRORS.get(code, 'unknown')})")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, DataAccessError) and other.code == self.code

    def __hash__(self) -> int:
        return hash(("DataAccessError", self.code))


class ServiceError(MmsError):
    """The server answered a request with a confirmed-ErrorPDU."""

    def __init__(self, error_class: int, code: int) -> None:
        self.error_class = error_class
        self.code = code
        super().__init__(
            f"service error class {error_class} ({ERROR_CLASSES.get(error_class, 'unknown')}), code {code}"
        )


class MmsReject(MmsError):
    """The server rejected a PDU (RejectPDU)."""

    def __init__(self, reason_tag: int, code: int) -> None:
        self.reason_tag = reason_tag
        self.code = code
        super().__init__(f"request rejected (reason [{reason_tag}] code {code})")
