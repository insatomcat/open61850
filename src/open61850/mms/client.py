# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""MMS client for IEC 61850 servers.

One background thread receives every PDU: responses are matched to their
request by invokeID, so several requests may be outstanding (from several
threads), up to the number the server accepted at association time (see
:attr:`MmsClient.association`); informationReports go to the ``on_information_report`` callback
and to the listeners added with :meth:`MmsClient.add_report_listener`.
Callbacks run on the receive thread: keep them short or hand the work to a
queue.

Example::

    with MmsClient.connect("10.0.0.2") as client:
        for domain in client.get_name_list(OBJECT_CLASS_DOMAIN):
            print(domain)
        print(client.read(ObjectName("LLN0$ST$Mod$stVal", "IED1LD0")))
"""

from __future__ import annotations

import itertools
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Optional

from ..data import IECData
from . import pdu
from .association import Association, AssociationParameters, association_request, decode_association_response
from .errors import (
    DataAccessError,
    MmsConnectionError,
    MmsProtocolError,
    MmsReject,
    MmsTimeout,
    ServiceError,
)
from .pdu import InformationReport, ObjectName
from .reference import Name, data_set_object_name, to_object_name
from .transport import IsoConnection
from .types import MmsType, get_variable_access_attributes_response

__all__ = [
    "InformationReportCallback",
    "MmsClient",
]


InformationReportCallback = Callable[[InformationReport], None]


@dataclass
class _Pending:
    done: threading.Event = field(default_factory=threading.Event)
    response: Optional[pdu.IncomingPdu] = None
    error: Optional[BaseException] = None


class MmsClient:
    def __init__(
        self,
        connection: IsoConnection,
        *,
        on_information_report: Optional[InformationReportCallback] = None,
        request_timeout: float = 10.0,
        association: Optional[Association] = None,
    ) -> None:
        self._conn = connection
        self.association = association
        outstanding = association.max_outstanding_calling if association is not None else 0
        self._slots = threading.BoundedSemaphore(outstanding) if outstanding > 0 else None
        self._on_report = on_information_report
        self._listeners: list[InformationReportCallback] = []
        self.request_timeout = request_timeout
        self._invoke_ids = itertools.count(1)
        self._pending: dict[int, _Pending] = {}
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._close_reason: Optional[BaseException] = None
        self._receiver: Optional[threading.Thread] = None

    # --- lifecycle -----------------------------------------------------------

    @classmethod
    def connect(
        cls,
        host: str,
        port: int = 102,
        *,
        timeout: float = 10.0,
        on_information_report: Optional[InformationReportCallback] = None,
        association: AssociationParameters = AssociationParameters(),
    ) -> MmsClient:
        """Open TCP, COTP and the MMS association, then start receiving."""
        try:
            conn = IsoConnection.connect(host, port, timeout=timeout)
        except OSError as exc:
            raise MmsConnectionError(f"cannot connect to {host}:{port}: {exc}") from exc
        try:
            conn.send(association_request(association))
            response = _recv_with_timeout(conn, timeout)
            if response is None:
                raise MmsConnectionError("connection closed during association")
            accepted = decode_association_response(response)
        except BaseException:
            conn.close()
            raise
        client = cls(conn, on_information_report=on_information_report, request_timeout=timeout, association=accepted)
        client._start()
        return client

    def _start(self) -> None:
        self._receiver = threading.Thread(target=self._receive_loop, name="mms-client-rx", daemon=True)
        self._receiver.start()

    def close(self) -> None:
        """Close the connection; outstanding requests fail with MmsConnectionError."""
        if not self._closed.is_set():
            self._fail_all(MmsConnectionError("connection closed by the client"))
            self._conn.close()
        if self._receiver is not None and self._receiver is not threading.current_thread():
            self._receiver.join(timeout=5)

    @property
    def local_address(self) -> Optional[str]:
        """This client's IP address, as the server sees it in RCB Owner attributes."""
        return self._conn.local_address

    @property
    def is_connected(self) -> bool:
        return not self._closed.is_set()

    def wait_closed(self, timeout: Optional[float] = None) -> Optional[BaseException]:
        """Block until the connection ends; return why it ended."""
        self._closed.wait(timeout)
        return self._close_reason

    def __enter__(self) -> MmsClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --- receive side --------------------------------------------------------

    def _receive_loop(self) -> None:
        reason: BaseException = MmsConnectionError("connection closed by the server")
        try:
            while True:
                user_data = self._conn.recv()
                if user_data is None:
                    break
                self._dispatch(pdu.decode_pdu(pdu.unwrap(user_data)))
        except (OSError, MmsProtocolError) as exc:
            if not self._closed.is_set():
                reason = MmsConnectionError(f"connection lost: {exc}")
        self._fail_all(reason)
        self._conn.close()

    def _dispatch(self, incoming: pdu.IncomingPdu) -> None:
        if isinstance(incoming, InformationReport):
            with self._lock:
                listeners = list(self._listeners)
            if self._on_report is not None:
                self._on_report(incoming)
            for listener in listeners:
                listener(incoming)
            return
        invoke_id = getattr(incoming, "invoke_id", None)
        if invoke_id is None:
            return  # unsolicited reject or conclude
        with self._lock:
            pending = self._pending.pop(invoke_id, None)
        if pending is not None:
            pending.response = incoming
            pending.done.set()

    def _fail_all(self, reason: BaseException) -> None:
        with self._lock:
            if self._closed.is_set():
                return
            self._close_reason = reason
            self._closed.set()
            pending, self._pending = self._pending, {}
        for p in pending.values():
            p.error = reason
            p.done.set()

    def add_report_listener(self, listener: InformationReportCallback) -> None:
        """Also pass every informationReport to ``listener`` (on the receive thread)."""
        with self._lock:
            self._listeners.append(listener)

    def remove_report_listener(self, listener: InformationReportCallback) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    # --- requests ------------------------------------------------------------

    def request(self, service: bytes, *, timeout: Optional[float] = None) -> pdu.ConfirmedResponse:
        """Send a ConfirmedServiceRequest and wait for its response."""
        limit = self.request_timeout if timeout is None else timeout
        if self._slots is None:
            return self._request(service, limit)
        if not self._slots.acquire(timeout=limit):
            raise MmsTimeout(f"{self.association.max_outstanding_calling} requests already outstanding")  # type: ignore[union-attr]
        try:
            return self._request(service, limit)
        finally:
            self._slots.release()

    def _request(self, service: bytes, timeout: float) -> pdu.ConfirmedResponse:
        pending = _Pending()
        with self._lock:
            if self._closed.is_set():
                raise MmsConnectionError("not connected") from self._close_reason
            invoke_id = next(self._invoke_ids) & 0xFFFFFFFF
            self._pending[invoke_id] = pending
        try:
            self._conn.send(pdu.wrap(pdu.confirmed_request(invoke_id, service)))
        except OSError as exc:
            with self._lock:
                self._pending.pop(invoke_id, None)
            raise MmsConnectionError(f"send failed: {exc}") from exc
        if not pending.done.wait(timeout):
            with self._lock:
                self._pending.pop(invoke_id, None)
            raise MmsTimeout(f"no response to invokeID {invoke_id}")
        if pending.error is not None:
            raise pending.error
        response = pending.response
        if isinstance(response, pdu.ConfirmedError):
            raise ServiceError(response.error_class, response.code)
        if isinstance(response, pdu.Reject):
            raise MmsReject(response.reason_tag, response.code)
        assert isinstance(response, pdu.ConfirmedResponse)
        return response

    def _service(self, service: bytes, expected: int) -> bytes:
        response = self.request(service)
        if response.service != expected:
            raise MmsProtocolError(f"expected service [{expected}] response, got [{response.service}]")
        return response.content

    def get_name_list(
        self, object_class: int, domain: Optional[str] = None, *, max_pages: int = 10_000
    ) -> list[str]:
        """All names of a class (vmd scope, or domain scope with ``domain``), following pages."""
        names: list[str] = []
        continue_after: Optional[str] = None
        for _ in range(max_pages):
            content = self._service(
                pdu.get_name_list_request(object_class, domain, continue_after), pdu.SERVICE_GET_NAME_LIST
            )
            page, more_follows = pdu.get_name_list_response(content)
            names.extend(page)
            if not more_follows or not page:
                break
            continue_after = page[-1]
        return names

    def read_many(self, names: Sequence[Name]) -> list[pdu.AccessResult]:
        """Read several variables in one request; failures come back as DataAccessError values.

        Every method taking a name accepts an :class:`ObjectName`, a
        :class:`~open61850.mms.reference.Reference`, or text:
        ``IED01_LD0/LLN0.Mod.stVal[ST]`` or ``IED01_LD0/LLN0$ST$Mod$stVal``.
        """
        objects = [to_object_name(n) for n in names]
        results = pdu.read_response(self._service(pdu.read_request(objects), pdu.SERVICE_READ))
        if len(results) != len(names):
            raise MmsProtocolError(f"read {len(names)} variables, got {len(results)} results")
        return results

    def read(self, name: Name) -> IECData:
        """Read one variable; raise DataAccessError on failure."""
        (result,) = self.read_many([name])
        if isinstance(result, DataAccessError):
            raise result
        return result

    def write_many(self, names: Sequence[Name], values: list[IECData]) -> list[Optional[DataAccessError]]:
        objects = [to_object_name(n) for n in names]
        results = pdu.write_response(self._service(pdu.write_request(objects, values), pdu.SERVICE_WRITE))
        if len(results) != len(names):
            raise MmsProtocolError(f"wrote {len(names)} variables, got {len(results)} results")
        return results

    def write(self, name: Name, value: IECData) -> None:
        """Write one variable; raise DataAccessError on failure."""
        (error,) = self.write_many([name], [value])
        if error is not None:
            raise error

    def get_type(self, name: Name) -> MmsType:
        """Type of a variable (GetVariableAccessAttributes)."""
        content = self._service(
            pdu.get_variable_access_attributes_request(to_object_name(name)), pdu.SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES
        )
        return get_variable_access_attributes_response(content)

    def get_data_set_members(self, name: Name) -> list[ObjectName]:
        """Members of a data set: ``LD/LLN0.DSName``, ``LD/LLN0$DSName`` or its ObjectName."""
        content = self._service(
            pdu.get_named_variable_list_attributes_request(data_set_object_name(name)),
            pdu.SERVICE_GET_NAMED_VARIABLE_LIST_ATTRIBUTES,
        )
        return pdu.get_named_variable_list_attributes_response(content)


def _recv_with_timeout(conn: IsoConnection, timeout: float) -> Optional[bytes]:
    sock = conn._sock
    sock.settimeout(timeout)
    try:
        return conn.recv()
    except TimeoutError as exc:
        raise MmsTimeout("no association response") from exc
    finally:
        sock.settimeout(None)
