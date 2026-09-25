# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""An IEC 61850 MMS server over TCP.

::

    model = IedModel.from_scl("IED01.cid")
    with MmsServer(model, port=102) as server:
        server.start()
        model.set("IED01LD0/MMXU1.TotW.mag.f[MX]", 1500.0)   # clients read it; reports follow

One thread accepts connections, one thread serves each: COTP, the
association (limits: the smaller of the client's and the server's), then
confirmed requests in order: GetNameList (with continueAfter), Identify,
Read (variables or a data set), Write, GetVariableAccessAttributes,
GetNamedVariableListAttributes, Conclude. Anything else gets a Reject.
"""

from __future__ import annotations

import bisect
import socket
import threading
from collections.abc import Callable
from typing import Optional, Union

from .. import __version__, ber
from ..data import IECData
from ..mms import pdu
from ..mms.errors import MmsProtocolError
from ..mms.pdu import ObjectName
from ..mms.transport import IsoConnection, TransportError
from . import protocol
from .control import ControlEngine
from .model import IedModel
from .reporting import ReportEngine

__all__ = ["MmsServer", "ServerConnection", "ERROR_DEFINITION", "ERROR_ACCESS"]

# MMS error classes and codes used in confirmed-ErrorPDUs
ERROR_DEFINITION = 2  # object-undefined = 1
ERROR_ACCESS = 7  # object-non-existent = 2
_OBJECT_UNDEFINED = 1

WriteHook = Callable[["ServerConnection", ObjectName, IECData], Optional[Union[int, bool]]]


class ServerConnection:
    """One associated client."""

    def __init__(self, server: MmsServer, iso: IsoConnection, peer: tuple) -> None:
        self.server = server
        self.iso = iso
        self.peer = peer
        self.mms_context = pdu.MMS_PRESENTATION_CONTEXT
        self.pdu_size = server.max_pdu_size
        self.closed = threading.Event()
        # Run once the response to the current request has gone (a CommandTermination follows its write).
        self.after_response: list[Callable[[], None]] = []

    @property
    def address(self) -> str:
        return str(self.peer[0]) if self.peer else ""

    def send(self, mms_pdu: bytes) -> None:
        self.iso.send(pdu.wrap(mms_pdu, self.mms_context))

    def close(self) -> None:
        self.closed.set()
        self.iso.close()

    # --- serving ---------------------------------------------------------------

    def serve(self) -> None:
        try:
            request = protocol.decode_association_request(self._recv_or_raise())
            accept, self.pdu_size = protocol.association_accept(
                request, max_pdu_size=self.server.max_pdu_size, max_outstanding=self.server.max_outstanding,
                nesting_level=self.server.nesting_level,
            )
            self.mms_context = request.mms_context
            self.iso.send(accept)
            while not self.closed.is_set():
                user_data = self.iso.recv()
                if user_data is None:
                    break
                if not self._handle(pdu.unwrap(user_data)):
                    break
        except (TransportError, MmsProtocolError, OSError):
            pass
        finally:
            self.closed.set()
            self.iso.close()
            self.server._forget(self)

    def _recv_or_raise(self) -> bytes:
        data = self.iso.recv()
        if data is None:
            raise TransportError("closed before the association")
        return data

    def _handle(self, mms_pdu: bytes) -> bool:
        """Answer one PDU; False when the association ends."""
        try:
            request = protocol.decode_request(mms_pdu)
        except MmsProtocolError:
            self.send(protocol.reject(None, reason=0, code=1))  # confirmed-requestPDU unrecognized
            return True
        if request == "conclude":
            self.send(protocol.conclude_response())
            return False
        assert isinstance(request, protocol.ConfirmedRequest)
        try:
            response = self._service(request)
        except (MmsProtocolError, ber.BerError, KeyError, ValueError, IndexError):
            response = protocol.reject(request.invoke_id, reason=1, code=5)  # invalid-argument
            self.after_response.clear()
        self.send(response)
        actions, self.after_response = self.after_response, []
        for action in actions:
            action()
        return True

    def _service(self, request: protocol.ConfirmedRequest) -> bytes:
        server, model = self.server, self.server.model
        invoke, service, content = request.invoke_id, request.service, request.content
        if service == pdu.SERVICE_GET_NAME_LIST:
            object_class, domain, after = protocol.get_name_list_request(content)
            if domain is not None and domain not in model.logical_devices:
                return protocol.confirmed_error(invoke, ERROR_DEFINITION, _OBJECT_UNDEFINED)
            names = self.server.names(object_class, domain)
            start = bisect.bisect_right(names, after) if after is not None else 0
            page, room = [], self.pdu_size - 64
            for name in names[start:]:
                room -= len(name) + 2
                if room < 0:
                    break
                page.append(name)
            more = start + len(page) < len(names)
            return protocol.confirmed_response(invoke, service, protocol.get_name_list_response(page, more))
        if service == 2:  # identify
            return protocol.confirmed_response(invoke, service, protocol.identify_response(
                server.vendor, server.model_name, server.revision))
        if service == pdu.SERVICE_READ:
            variables, with_result = protocol.read_request(content)
            if isinstance(variables, ObjectName):  # a data set
                members = model.data_sets.get(variables)
                if members is None:
                    return protocol.confirmed_error(invoke, ERROR_DEFINITION, _OBJECT_UNDEFINED)
                results = [model.read(m) for m in members]
                spec = ber.encode_tlv(0xA1, pdu.encode_object_name(variables)) if with_result else None
                return protocol.confirmed_response(invoke, service, protocol.read_response(results, spec))
            return protocol.confirmed_response(invoke, service, protocol.read_response([self._read(v) for v in variables]))
        if service == pdu.SERVICE_WRITE:
            variables, values = protocol.write_request(content)
            if isinstance(variables, ObjectName):
                members = model.data_sets.get(variables, [])
                variables = members
            errors = [self._write(name, value) for name, value in zip(variables, values)]
            return protocol.confirmed_response(invoke, service, protocol.write_response(errors))
        if service == pdu.SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES:
            node = model.node(protocol.object_name_request(content))
            if node is None:
                return protocol.confirmed_error(invoke, ERROR_DEFINITION, _OBJECT_UNDEFINED)
            return protocol.confirmed_response(invoke, service, protocol.get_variable_access_attributes_response(node.mms_type))
        if service == pdu.SERVICE_GET_NAMED_VARIABLE_LIST_ATTRIBUTES:
            members = model.data_sets.get(protocol.object_name_request(content))
            if members is None:
                return protocol.confirmed_error(invoke, ERROR_DEFINITION, _OBJECT_UNDEFINED)
            return protocol.confirmed_response(invoke, service, protocol.get_named_variable_list_attributes_response(members))
        return protocol.reject(invoke, reason=1, code=1)  # unrecognized-service

    def _read(self, name: ObjectName) -> Union[IECData, int]:
        for hook in self.server.read_hooks:
            result = hook(self, name)
            if result is not None:
                return result
        return self.server.model.read(name)

    def _write(self, name: ObjectName, value: IECData) -> Optional[int]:
        for hook in self.server.write_hooks:
            result = hook(self, name, value)
            if result is True:
                return None  # handled
            if isinstance(result, int) and not isinstance(result, bool):
                return result  # handled, refused
        return self.server.model.write(name, value)


class MmsServer:
    """Serves ``model`` on ``host``:``port`` (port 0 picks a free one; see :attr:`port`)."""

    def __init__(self, model: IedModel, host: str = "0.0.0.0", port: int = 102, *, vendor: str = "open61850",
                 model_name: str = "open61850", revision: str = __version__, max_pdu_size: int = 65000,
                 max_outstanding: int = 5, nesting_level: int = 10, reports: bool = True, controls: bool = True) -> None:
        self.model = model
        self.host = host
        self.port = port
        self.vendor, self.model_name, self.revision = vendor, model_name, revision
        self.max_pdu_size, self.max_outstanding, self.nesting_level = max_pdu_size, max_outstanding, nesting_level
        # Hooks see every write first: True = done, an int = refused with that DataAccessError,
        # None = not theirs (reports and controls plug in here).
        self.write_hooks: list[WriteHook] = []
        self.close_hooks: list[Callable[[ServerConnection], None]] = []
        # Read hooks answer some reads themselves (a value or an error code), None = not theirs.
        self.read_hooks: list[Callable[[ServerConnection, ObjectName], Optional[Union[IECData, int]]]] = []
        self.controls_enabled = controls
        self.controls: Optional[ControlEngine] = None
        self.reports_enabled = reports
        self.reports: Optional[ReportEngine] = None
        self.connections: list[ServerConnection] = []
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def names(self, object_class: int, domain: Optional[str]) -> list[str]:
        """What GetNameList lists, sorted."""
        model = self.model
        if object_class == pdu.OBJECT_CLASS_DOMAIN:
            return sorted(model.logical_devices) if domain is None else []
        if domain is None:
            return []
        if object_class == pdu.OBJECT_CLASS_NAMED_VARIABLE:
            return model.names(domain)
        if object_class == pdu.OBJECT_CLASS_NAMED_VARIABLE_LIST:
            return sorted(n.item for n in model.data_sets if n.domain == domain)
        return []

    def start(self) -> None:
        if self.reports_enabled and self.reports is None:
            self.reports = ReportEngine(self)
        if self.controls_enabled and self.controls is None:
            self.controls = ControlEngine(self)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(16)
        self.port = sock.getsockname()[1]
        self._sock = sock
        self._thread = threading.Thread(target=self._accept_loop, name="mms-server", daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while True:
            try:
                client, peer = self._sock.accept()
            except OSError:
                return  # closed by stop()
            threading.Thread(target=self._serve, args=(client, peer), name=f"mms-{peer[0]}", daemon=True).start()

    def _serve(self, client: socket.socket, peer: tuple) -> None:
        try:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            iso = protocol.accept_cotp(client)
        except (TransportError, OSError):
            client.close()
            return
        connection = ServerConnection(self, iso, peer)
        with self._lock:
            self.connections.append(connection)
        connection.serve()

    def _forget(self, connection: ServerConnection) -> None:
        with self._lock:
            if connection in self.connections:
                self.connections.remove(connection)
        for hook in list(self.close_hooks):
            hook(connection)

    def broadcast(self, mms_pdu: bytes, to: Optional[ServerConnection] = None) -> None:
        """Send an unconfirmed PDU to one connection, or to every one."""
        targets = [to] if to is not None else list(self.connections)
        for connection in targets:
            try:
                connection.send(mms_pdu)
            except OSError:
                connection.close()

    def stop(self) -> None:
        if self._sock is not None:
            try:
                # On Linux close() alone leaves the thread in accept() and the port bound.
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
            self._sock = None
        for connection in list(self.connections):
            connection.close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self.reports is not None:
            self.reports.stop()

    def __enter__(self) -> MmsServer:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
