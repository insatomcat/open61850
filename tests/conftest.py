# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Shared test setup: the package is imported from src/ without installing it."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).resolve().parent / "data"

if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
