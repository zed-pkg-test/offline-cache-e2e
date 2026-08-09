#!/usr/bin/env python3
"""Run the offline profile canary with durable-lock and Windows normalization.

`.zed/operation.lock` is an intentionally durable zed-lock rendezvous point.
Creation or diagnostic-content refresh is not project/profile state mutation, so
black-box before/after comparisons exclude that one exact path while retaining
all other `.zed` state.

On Windows, Python's argument quoting already protects a batch-file path passed
to `cmd.exe /C`. Adding quote characters to the argument itself makes those
characters part of the command and causes `cmd.exe` to look for a filename that
begins with `"`. The wrapper therefore supplies the path as an ordinary argument
and retains the canonical harness's output assertion.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("zed_tool_offline_profile.py")
SPEC = importlib.util.spec_from_file_location("zed_tool_offline_profile", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
CANARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CANARY
SPEC.loader.exec_module(CANARY)

_original_snapshot = CANARY.snapshot
_original_execute_installed = CANARY.execute_installed


def semantic_snapshot(root: Path):
    rows = _original_snapshot(root)
    rows.pop(".zed/operation.lock", None)
    return rows


def execute_installed(path: Path, os_name: str, transcript: Path) -> None:
    if os_name != "windows":
        _original_execute_installed(path, os_name, transcript)
        return

    environment = os.environ.copy()
    shell = environment.get("COMSPEC", "cmd.exe")
    output = CANARY.run(
        [shell, "/D", "/C", path],
        cwd=path.parent,
        env=environment,
        transcript=transcript,
    )
    if output.stdout.strip() != "hello":
        raise AssertionError(f"unexpected installed command output: {output.stdout!r}")


CANARY.snapshot = semantic_snapshot
CANARY.execute_installed = execute_installed

if __name__ == "__main__":
    raise SystemExit(CANARY.main())
