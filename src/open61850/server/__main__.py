# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""``open61850-server`` (``python -m open61850.server``): serve an IED of an SCL file over MMS.

    open61850-server IED01.cid [--ied IED01] [--host 0.0.0.0] [--port 102]

Each line read on standard input sets a value, which clients read and
reports carry::

    IED01LD0/MMXU1.TotW.mag.f[MX] 1500.5
    IED01LD0/XCBR1.Pos.stVal[ST] on        # Dbpos: intermediate-state, off, on, bad-state
    IED01LD0/GGIO1.Ind1.stVal[ST] true

Values are booleans, integers, floats or text, converted to the attribute's
type. The server runs until Ctrl-C (or SIGTERM), or for ``--duration``
seconds; standard input closing does not stop it.
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from collections.abc import Sequence
from typing import Any, Optional

from ..mms.types import PrimitiveType
from .model import IedModel
from .server import MmsServer

_DBPOS = {"intermediate-state": 0, "off": 1, "on": 2, "bad-state": 3}


def parse_value(text: str, mms_type: Any) -> Any:
    """Text of a value for an attribute of ``mms_type``."""
    text = text.strip()
    kind = mms_type.kind if isinstance(mms_type, PrimitiveType) else ""
    if kind == "boolean":
        if text.lower() not in ("true", "false", "1", "0"):
            raise ValueError(f"{text!r} is not a boolean")
        return text.lower() in ("true", "1")
    if kind == "bit-string" and text in _DBPOS:
        return _DBPOS[text]
    if kind in ("integer", "unsigned", "bit-string"):
        return int(text, 0)
    if kind == "float":
        return float(text)
    return text


def apply_line(model: IedModel, line: str) -> str:
    """Set the value a ``REFERENCE VALUE`` line gives; what was done, for the operator."""
    reference, _, text = line.strip().partition(" ")
    node = model.node(reference)
    if node is None:
        raise KeyError(f"no {reference} in the model")
    model.set(reference, parse_value(text, node.mms_type))
    return f"{reference} = {model.get(reference)!r}"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="open61850-server", description=__doc__.splitlines()[0])
    parser.add_argument("scl", help="CID, ICD or SCD file")
    parser.add_argument("--ied", help="IED name, when the file has several")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=102, help="TCP port (default 102; 0 picks a free one)")
    parser.add_argument("--duration", type=float, help="stop after this many seconds")
    args = parser.parse_args(argv)

    model = IedModel.from_scl(args.scl, args.ied)
    server = MmsServer(model, args.host, args.port)
    server.start()
    devices = ", ".join(model.logical_devices)
    print(f"open61850-server: {model.ied_name} ({devices}) on {args.host}:{server.port}", file=sys.stderr, flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    threading.Thread(target=_read_input, args=(model,), name="stdin", daemon=True).start()
    try:
        stop.wait(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


def _read_input(model: IedModel) -> None:
    for line in sys.stdin:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            print(apply_line(model, line), flush=True)
        except (KeyError, ValueError, TypeError) as exc:
            print(f"open61850-server: {exc}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
