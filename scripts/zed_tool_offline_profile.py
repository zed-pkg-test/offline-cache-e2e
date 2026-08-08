#!/usr/bin/env python3
"""Independent black-box certification for the staged `zed-tool` CLI.

The harness constructs authenticated archive bytes and a manager-neutral
EnvironmentLock without importing zed-cli or zed-interfaces implementation
code. It then drives only the compiled `zed-tool` process and the installed
fixture command.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any, Mapping, Sequence

PLAN_DIGEST = "a" * 64
FAKE_TOKEN = "gh" + "p_offline_profile_canary_must_not_escape"
SOURCE_LOCATOR = "https://example.invalid/hello-1.0.0.tar.gz"
LOCK_PATH = Path(".zed/environment.lock.json")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(root: Path) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    if not root.exists():
        return rows
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows[relative] = ["symlink", os.readlink(path)]
        elif path.is_file():
            rows[relative] = ["file", sha256(path.read_bytes())]
        elif path.is_dir():
            rows[relative] = ["dir"]
    return rows


def clean_environment(home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        upper = key.upper()
        if (
            upper in {"GH_TOKEN", "GITHUB_TOKEN"}
            or upper.startswith("CLOUDFLARE_")
            or upper.startswith("AWS_")
            or upper.startswith("R2_")
            or upper.startswith("LINEAR_")
        ):
            environment.pop(key, None)
    environment.update(
        {
            "CI": "true",
            "ZED_PKG_HOME": str(home),
            "ZED_PKG_TOKEN": FAKE_TOKEN,
            "ZED_PKG_REGISTRY": "http://127.0.0.1:9",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
    )
    return environment


def run(
    argv: Sequence[str | Path],
    *,
    cwd: Path,
    env: Mapping[str, str],
    transcript: Path,
    expect_success: bool = True,
) -> subprocess.CompletedProcess[str]:
    command = [str(value) for value in argv]
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=dict(env),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    record = (
        f"$ (cd {cwd} && {' '.join(command)})\n"
        f"exit={completed.returncode}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}\n"
    )
    print(record, flush=True)
    transcript.parent.mkdir(parents=True, exist_ok=True)
    with transcript.open("a", encoding="utf-8") as handle:
        handle.write(record)
    if expect_success and completed.returncode != 0:
        raise AssertionError(f"command failed: {' '.join(command)}")
    if not expect_success and completed.returncode == 0:
        raise AssertionError(f"command unexpectedly succeeded: {' '.join(command)}")
    return completed


def command_body(os_name: str) -> tuple[str, bytes, str]:
    if os_name == "windows":
        return "bin/hello.cmd", b"@echo off\r\necho hello\r\n", "hello.cmd"
    return "bin/hello", b"#!/bin/sh\nprintf 'hello\\n'\n", "hello"


def write_archive(path: Path, source: str, body: bytes) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                info = tarfile.TarInfo(f"pkg/{source}")
                info.size = len(body)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o755
                import io

                archive.addfile(info, io.BytesIO(body))
    return path.read_bytes()


def locked_tool(
    *,
    name: str,
    target: str,
    os_name: str,
    arch: str,
    artifact_sha256: str,
    artifact_size: int,
    executable_source: str,
    executable_name: str = "hello",
) -> dict[str, Any]:
    return {
        "requirement": "1",
        "resolved": "1.0.0",
        "backend": "http",
        "backend_version": "1.0.0",
        "source": {
            "kind": "http",
            "locator": SOURCE_LOCATOR.replace("hello", name),
            "immutable": False,
            "portable": False,
        },
        "artifact": {
            "sha256": artifact_sha256,
            "size": artifact_size,
            "format": "tar_gz",
        },
        "platform": {
            "target": target,
            "os": os_name,
            "arch": arch,
        },
        "install": {
            "root": ".",
            "bin_dirs": ["bin"],
            "executables": [
                {
                    "name": executable_name,
                    "path": executable_source,
                    "aliases": [f"{executable_name}-alias"],
                }
            ],
        },
    }


def write_lock(
    project: Path,
    *,
    target: str,
    os_name: str,
    arch: str,
    artifact_sha256: str,
    artifact_size: int,
    executable_source: str,
    collision: bool = False,
    size_delta: int = 0,
) -> Path:
    tools: dict[str, list[dict[str, Any]]] = {
        "hello": [
            locked_tool(
                name="hello",
                target=target,
                os_name=os_name,
                arch=arch,
                artifact_sha256=artifact_sha256,
                artifact_size=artifact_size + size_delta,
                executable_source=executable_source,
            )
        ]
    }
    if collision:
        tools["second"] = [
            locked_tool(
                name="second",
                target=target,
                os_name=os_name,
                arch=arch,
                artifact_sha256=artifact_sha256,
                artifact_size=artifact_size,
                executable_source=executable_source,
            )
        ]
    payload = {
        "schema_version": 1,
        "plan_digest_sha256": PLAN_DIGEST,
        "tools": tools,
    }
    lock = project / LOCK_PATH
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return lock


def make_fixture(
    root: Path,
    *,
    target: str,
    os_name: str,
    arch: str,
    collision: bool = False,
    cache_mode: str = "valid",
    size_delta: int = 0,
) -> tuple[Path, Path, str, int, str, str]:
    project = root / "project"
    home = root / "home"
    project.mkdir(parents=True)
    (home / "cache").mkdir(parents=True)
    (home / "credentials.toml").write_text(
        "malformed = [credential that must never be parsed",
        encoding="utf-8",
    )

    executable_source, body, command_file = command_body(os_name)
    draft = root / "artifact.tar.gz"
    artifact = write_archive(draft, executable_source, body)
    artifact_sha256 = sha256(artifact)
    artifact_size = len(artifact)
    cached = home / "cache" / f"{artifact_sha256}.tar.gz"
    if cache_mode != "missing":
        cached.write_bytes(artifact)
    if cache_mode == "tampered":
        changed = bytearray(cached.read_bytes())
        changed[-1] ^= 1
        cached.write_bytes(changed)

    write_lock(
        project,
        target=target,
        os_name=os_name,
        arch=arch,
        artifact_sha256=artifact_sha256,
        artifact_size=artifact_size,
        executable_source=executable_source,
        collision=collision,
        size_delta=size_delta,
    )
    return project, home, artifact_sha256, artifact_size, executable_source, command_file


def tool_command(binary: Path, arguments: Sequence[str | Path]) -> list[str | Path]:
    return [binary, "--lock", LOCK_PATH, *arguments]


def parse_json(output: subprocess.CompletedProcess[str]) -> Any:
    if output.stderr:
        raise AssertionError(f"successful JSON command wrote stderr: {output.stderr!r}")
    try:
        return json.loads(output.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(f"invalid JSON output: {output.stdout!r}") from error


def assert_failure_without_profile(
    binary: Path,
    project: Path,
    home: Path,
    target: str,
    transcript: Path,
    expected: str,
    arguments: Sequence[str | Path] | None = None,
) -> None:
    before = snapshot(project)
    result = run(
        tool_command(
            binary,
            arguments
            or [
                "install",
                "--target",
                target,
                "--offline",
                "--home",
                home,
            ],
        ),
        cwd=project,
        env=clean_environment(home),
        transcript=transcript,
        expect_success=False,
    )
    combined = result.stdout + result.stderr
    if expected not in combined:
        raise AssertionError(f"expected {expected!r} in failure output: {combined!r}")
    if (project / ".zed/tools/v1" / target).exists():
        raise AssertionError("failed install left a tool profile")
    if snapshot(project) != before:
        raise AssertionError("failed install mutated the project")


def execute_installed(path: Path, os_name: str, transcript: Path) -> None:
    environment = os.environ.copy()
    if os_name == "windows":
        shell = environment.get("COMSPEC", "cmd.exe")
        output = run(
            [shell, "/D", "/S", "/C", f'"{path}"'],
            cwd=path.parent,
            env=environment,
            transcript=transcript,
        )
    else:
        mode = path.stat().st_mode
        if not mode & stat.S_IXUSR:
            raise AssertionError(f"installed command is not executable: {path}")
        output = run(
            [path],
            cwd=path.parent,
            env=environment,
            transcript=transcript,
        )
    if output.stdout.strip() != "hello":
        raise AssertionError(f"unexpected installed command output: {output.stdout!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zed-tool", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--os", required=True, choices=("linux", "macos", "windows"))
    parser.add_argument("--arch", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()

    binary = args.zed_tool.resolve()
    root = args.work_root.resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)
    if root.exists():
        raise AssertionError(f"work root must be fresh: {root}")
    root.mkdir(parents=True)
    evidence = root / "evidence"
    transcript = evidence / "transcript.log"

    primary, home, artifact_sha256, artifact_size, _, command_file = make_fixture(
        root / "primary",
        target=args.target,
        os_name=args.os,
        arch=args.arch,
    )
    environment = clean_environment(home)
    project_before = snapshot(primary)

    verify = parse_json(
        run(
            tool_command(
                binary,
                [
                    "--json",
                    "verify",
                    "--portable",
                    "--plan-digest",
                    PLAN_DIGEST,
                ],
            ),
            cwd=primary,
            env=environment,
            transcript=transcript,
        )
    )
    if verify.get("tools") != 1 or verify.get("validation") != "portable":
        raise AssertionError(verify)
    if snapshot(primary) != project_before:
        raise AssertionError("verify mutated the project")

    listed = parse_json(
        run(
            tool_command(binary, ["--json", "list", "--target", args.target]),
            cwd=primary,
            env=environment,
            transcript=transcript,
        )
    )
    if len(listed) != 1 or listed[0].get("name") != "hello":
        raise AssertionError(listed)
    if listed[0].get("artifact_sha256") != artifact_sha256:
        raise AssertionError(listed)
    if snapshot(primary) != project_before:
        raise AssertionError("list mutated the project")

    first = parse_json(
        run(
            tool_command(
                binary,
                [
                    "--json",
                    "install",
                    "--target",
                    args.target,
                    "--offline",
                    "--home",
                    home,
                ],
            ),
            cwd=primary,
            env=environment,
            transcript=transcript,
        )
    )
    if first.get("action") != "installed":
        raise AssertionError(first)
    profile = primary / ".zed/tools/v1" / args.target / "profile.json"
    if not profile.is_file():
        raise AssertionError(f"missing profile state: {profile}")
    profile_bytes = profile.read_bytes()
    profile_json = json.loads(profile_bytes)
    profile_text = profile_bytes.decode("utf-8")
    for required in (args.target, "hello", "1.0.0", artifact_sha256):
        if required not in profile_text:
            raise AssertionError(f"profile omitted {required!r}: {profile_json!r}")
    for forbidden in (
        str(primary),
        str(home),
        SOURCE_LOCATOR,
        FAKE_TOKEN,
        "credentials.toml",
        "127.0.0.1:9",
    ):
        if forbidden in profile_text + first.__repr__():
            raise AssertionError(f"profile or receipt leaked {forbidden!r}")

    profile_snapshot = snapshot(primary / ".zed/tools/v1" / args.target)
    second = parse_json(
        run(
            tool_command(
                binary,
                [
                    "--json",
                    "install",
                    "--target",
                    args.target,
                    "--offline",
                    "--home",
                    home,
                ],
            ),
            cwd=primary,
            env=environment,
            transcript=transcript,
        )
    )
    if second.get("action") != "unchanged":
        raise AssertionError(second)
    if profile.read_bytes() != profile_bytes:
        raise AssertionError("idempotent replay rewrote profile.json")
    if snapshot(primary / ".zed/tools/v1" / args.target) != profile_snapshot:
        raise AssertionError("idempotent replay changed profile inventory")

    bin_dir = primary / Path(second["bin"])
    installed = bin_dir / command_file
    alias_file = (
        bin_dir / "hello-alias.cmd"
        if args.os == "windows"
        else bin_dir / "hello-alias"
    )
    if not installed.exists() or not alias_file.exists():
        raise AssertionError(f"missing installed commands below {bin_dir}")
    execute_installed(installed, args.os, transcript)
    execute_installed(alias_file, args.os, transcript)

    shared_project = root / "shared-project"
    shutil.copytree(primary / ".zed", shared_project / ".zed")
    shutil.rmtree(shared_project / ".zed/tools", ignore_errors=True)
    shared = parse_json(
        run(
            tool_command(
                binary,
                [
                    "--json",
                    "install",
                    "--target",
                    args.target,
                    "--offline",
                    "--home",
                    home,
                ],
            ),
            cwd=shared_project,
            env=environment,
            transcript=transcript,
        )
    )
    if shared.get("action") != "installed":
        raise AssertionError(shared)
    execute_installed(shared_project / Path(shared["bin"]) / command_file, args.os, transcript)

    missing_project, missing_home, *_ = make_fixture(
        root / "missing",
        target=args.target,
        os_name=args.os,
        arch=args.arch,
        cache_mode="missing",
    )
    assert_failure_without_profile(
        binary,
        missing_project,
        missing_home,
        args.target,
        transcript,
        "prefetch",
    )

    tampered_project, tampered_home, *_ = make_fixture(
        root / "tampered",
        target=args.target,
        os_name=args.os,
        arch=args.arch,
        cache_mode="tampered",
    )
    assert_failure_without_profile(
        binary,
        tampered_project,
        tampered_home,
        args.target,
        transcript,
        "hash mismatch",
    )

    wrong_size_project, wrong_size_home, *_ = make_fixture(
        root / "wrong-size",
        target=args.target,
        os_name=args.os,
        arch=args.arch,
        size_delta=1,
    )
    assert_failure_without_profile(
        binary,
        wrong_size_project,
        wrong_size_home,
        args.target,
        transcript,
        "size mismatch",
    )

    collision_project, collision_home, *_ = make_fixture(
        root / "collision",
        target=args.target,
        os_name=args.os,
        arch=args.arch,
        collision=True,
    )
    assert_failure_without_profile(
        binary,
        collision_project,
        collision_home,
        args.target,
        transcript,
        "claimed by both",
    )

    online_project, online_home, *_ = make_fixture(
        root / "online",
        target=args.target,
        os_name=args.os,
        arch=args.arch,
    )
    assert_failure_without_profile(
        binary,
        online_project,
        online_home,
        args.target,
        transcript,
        "requires `--offline`",
        ["install", "--target", args.target, "--home", online_home],
    )

    digest_project, digest_home, *_ = make_fixture(
        root / "wrong-digest",
        target=args.target,
        os_name=args.os,
        arch=args.arch,
    )
    digest = run(
        tool_command(
            binary,
            ["verify", "--portable", "--plan-digest", "b" * 64],
        ),
        cwd=digest_project,
        env=clean_environment(digest_home),
        transcript=transcript,
        expect_success=False,
    )
    if "plan digest" not in digest.stdout + digest.stderr:
        raise AssertionError(digest.stderr)
    if (digest_project / ".zed/tools").exists():
        raise AssertionError("failed digest verification created a profile")

    unsafe_project, unsafe_home, *_ = make_fixture(
        root / "unsafe-target",
        target=args.target,
        os_name=args.os,
        arch=args.arch,
    )
    assert_failure_without_profile(
        binary,
        unsafe_project,
        unsafe_home,
        args.target,
        transcript,
        "unsupported characters",
        [
            "install",
            "--target",
            "../host",
            "--offline",
            "--home",
            unsafe_home,
        ],
    )

    evidence.mkdir(parents=True, exist_ok=True)
    result = {
        "schema": "zed-pkg-test/zed-tool-offline-profile/v1",
        "candidate": args.candidate,
        "target": args.target,
        "os": args.os,
        "arch": args.arch,
        "artifact_sha256": artifact_sha256,
        "artifact_size": artifact_size,
        "profile_sha256": sha256(profile_bytes),
        "checks": [
            "portable verify",
            "target list",
            "offline install",
            "installed command execution",
            "idempotent replay",
            "shared cache reuse",
            "missing cache rejection",
            "tampered cache rejection",
            "wrong size rejection",
            "command collision rejection",
            "online mode rejection",
            "plan digest rejection",
            "unsafe target rejection",
            "secret-free relative profile state",
        ],
        "result": "pass",
    }
    (evidence / "result.json").write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
