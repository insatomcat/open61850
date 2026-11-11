# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Shared test setup: the package is imported from src/ without installing it; a veth pair for the captures."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).resolve().parent / "data"

if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture
def veth_down() -> Iterator[tuple[str, str, Callable[[], None]]]:
    """A veth pair, both ends down (Linux, root, iproute2), and what sets both up: a pod's process bus being made."""
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or shutil.which("ip") is None:
        pytest.skip("needs Linux, root and ip")
    a, b = "o61850t0", "o61850t1"
    subprocess.run(["ip", "link", "del", a], capture_output=True)
    subprocess.run(["ip", "link", "add", a, "type", "veth", "peer", "name", b], check=True)

    def up() -> None:
        for iface in (a, b):
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)

    try:
        yield a, b, up
    finally:
        subprocess.run(["ip", "link", "del", a], capture_output=True)

