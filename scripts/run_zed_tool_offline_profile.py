#!/usr/bin/env python3
"""Run the offline profile canary with checkout-lock bytes normalized away.

`.zed/operation.lock` is an intentionally durable zed-lock rendezvous point.
Creation or diagnostic-content refresh is not project/profile state mutation, so
black-box before/after comparisons exclude that one exact path while retaining
all other `.zed` state.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).with_name("zed_tool_offline_profile.py")
SPEC = importlib.util.spec_from_file_location("zed_tool_offline_profile", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
CANARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CANARY
SPEC.loader.exec_module(CANARY)

_original_snapshot = CANARY.snapshot


def semantic_snapshot(root: Path):
    rows = _original_snapshot(root)
    rows.pop(".zed/operation.lock", None)
    return rows


CANARY.snapshot = semantic_snapshot

if __name__ == "__main__":
    raise SystemExit(CANARY.main())
