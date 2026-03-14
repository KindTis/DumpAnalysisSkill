from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "dump-analysis-skill"
    / "scripts"
    / "dump_skill.py"
)


SAMPLE_DEBUGGER_OUTPUT = """
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 42
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULTING_IP:
myApp!InventoryComponent::UseItem+0x12 [D:\\Dev\\MyApp\\Source\\Inventory\\InventoryComponent.cpp @ 248]
STACK_TEXT:
00000000`0014f2b0 myApp!InventoryComponent::UseItem+0x12 [D:\\Dev\\MyApp\\Source\\Inventory\\InventoryComponent.cpp @ 248]
00000000`0014f300 myApp!PlayerController::Tick+0x1d [D:\\Dev\\MyApp\\Source\\Player\\PlayerController.cpp @ 102]
LOADED_MODULES:
myApp.exe | good
Engine.dll | partial
SYMBOL_STATUS: good
"""


def _run_cli(args: list[str], env: dict[str, str]) -> dict:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _prepare_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    dump_file = tmp_path / "sample.dmp"
    dump_file.write_bytes(b"MZ")
    symbol_root = tmp_path / "symbols"
    source_root = tmp_path / "source"
    symbol_root.mkdir()
    source_root.mkdir()
    return dump_file, symbol_root, source_root


def test_register_saves_session_and_returns_dump_id(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    dump_file, symbol_root, source_root = _prepare_inputs(tmp_path)
    env = os.environ.copy()

    result = _run_cli(
        [
            "--session-file",
            str(session_file),
            "register",
            "--dump-path",
            str(dump_file.resolve()),
            "--symbol-root",
            str(symbol_root.resolve()),
            "--source-root",
            str(source_root.resolve()),
            "--project-type",
            "native_cpp",
        ],
        env=env,
    )

    assert result["ok"] is True
    assert result["status"] == "registered"
    assert result["dump_id"].startswith("crash-")
    assert session_file.exists()

    db = json.loads(session_file.read_text(encoding="utf-8"))
    assert len(db["sessions"]) == 1
    assert db["sessions"][0]["dump_id"] == result["dump_id"]


def test_analyze_returns_structured_result_from_fake_output(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    dump_file, symbol_root, source_root = _prepare_inputs(tmp_path)
    env = os.environ.copy()
    env["DUMP_SKILL_FAKE_OUTPUT"] = SAMPLE_DEBUGGER_OUTPUT

    reg = _run_cli(
        [
            "--session-file",
            str(session_file),
            "register",
            "--dump-path",
            str(dump_file.resolve()),
            "--symbol-root",
            str(symbol_root.resolve()),
            "--source-root",
            str(source_root.resolve()),
            "--project-type",
            "native_cpp",
        ],
        env=env,
    )
    dump_id = reg["dump_id"]

    analyzed = _run_cli(
        [
            "--session-file",
            str(session_file),
            "analyze",
            "--dump-id",
            dump_id,
        ],
        env=env,
    )

    assert analyzed["ok"] is True
    assert analyzed["dump_id"] == dump_id
    assert analyzed["exception_code"] == "0xC0000005"
    assert analyzed["exception_name"] == "EXCEPTION_ACCESS_VIOLATION"
    assert analyzed["fault_module"] == "myApp"
    assert analyzed["fault_function"] == "InventoryComponent::UseItem"
    assert analyzed["source_location"]["file"].endswith("InventoryComponent.cpp")
    assert analyzed["source_location"]["line"] == 248
    assert analyzed["crashing_thread"] == 42
    assert len(analyzed["stack_frames"]) == 2
    assert analyzed["symbol_quality"] == "good"


def test_exception_stack_modules_commands_return_expected_payloads(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    dump_file, symbol_root, source_root = _prepare_inputs(tmp_path)
    env = os.environ.copy()
    env["DUMP_SKILL_FAKE_OUTPUT"] = SAMPLE_DEBUGGER_OUTPUT

    reg = _run_cli(
        [
            "--session-file",
            str(session_file),
            "register",
            "--dump-path",
            str(dump_file.resolve()),
            "--symbol-root",
            str(symbol_root.resolve()),
            "--source-root",
            str(source_root.resolve()),
            "--project-type",
            "native_cpp",
        ],
        env=env,
    )
    dump_id = reg["dump_id"]

    exc = _run_cli(
        ["--session-file", str(session_file), "exception", "--dump-id", dump_id],
        env=env,
    )
    assert exc["ok"] is True
    assert exc["exception_code"] == "0xC0000005"

    stack = _run_cli(
        [
            "--session-file",
            str(session_file),
            "stack",
            "--dump-id",
            dump_id,
            "--max-frames",
            "1",
        ],
        env=env,
    )
    assert stack["ok"] is True
    assert len(stack["stack_frames"]) == 1
    assert stack["thread_id"] == 42

    modules = _run_cli(
        ["--session-file", str(session_file), "modules", "--dump-id", dump_id],
        env=env,
    )
    assert modules["ok"] is True
    assert modules["symbol_quality"] == "good"
    assert len(modules["loaded_modules"]) == 2


def test_analyze_returns_error_for_unknown_dump_id(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    env = os.environ.copy()
    result = _run_cli(
        ["--session-file", str(session_file), "analyze", "--dump-id", "crash-missing"],
        env=env,
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_request"


def test_register_rejects_missing_dump_file(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    symbol_root = tmp_path / "symbols"
    source_root = tmp_path / "source"
    symbol_root.mkdir()
    source_root.mkdir()
    missing_dump = tmp_path / "missing.dmp"

    env = os.environ.copy()
    result = _run_cli(
        [
            "--session-file",
            str(session_file),
            "register",
            "--dump-path",
            str(missing_dump.resolve()),
            "--symbol-root",
            str(symbol_root.resolve()),
            "--source-root",
            str(source_root.resolve()),
            "--project-type",
            "native_cpp",
        ],
        env=env,
    )

    assert result["ok"] is False
    assert result["error"]["code"] == "dump_file_not_found"

