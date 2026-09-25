# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The examples start, and the one that needs no network runs on a file.

tests/test_interop_libiec61850.py runs the others against libiec61850.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from conftest import DATA_DIR, ROOT

EXAMPLES = sorted((ROOT / "examples").glob("*.py"))
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}


def test_there_are_examples() -> None:
    assert len(EXAMPLES) >= 7


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.name)
def test_example_help(example) -> None:
    run = subprocess.run([sys.executable, str(example), "--help"], capture_output=True, text=True, env=ENV)
    assert run.returncode == 0, run.stderr
    assert run.stdout.startswith("usage:")


def test_supervise_bus_on_a_file(tmp_path) -> None:
    capture = tmp_path / "bus.pcapng"
    capture.write_bytes(bytes.fromhex(json.loads((DATA_DIR / "editcap_pcapng.json").read_text())["ns"]))
    run = subprocess.run([sys.executable, str(ROOT / "examples" / "supervise_bus.py"), str(capture)],
                         capture_output=True, text=True, env=ENV, check=True)
    assert run.stdout.splitlines()[-1] == "frames: 1 goose, 5 sv"
