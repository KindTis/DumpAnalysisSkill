from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "dump-analysis-cdb"
    / "scripts"
    / "dump_skill.py"
)


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


def _prepare_registered_dump(
    *,
    tmp_path: Path,
    fake_output: str,
    source_root: Path,
) -> tuple[Path, dict[str, str], str]:
    session_file = tmp_path / "sessions.json"
    dump_file = tmp_path / "sample.dmp"
    dump_file.write_bytes(b"MZ")
    symbol_root = tmp_path / "symbols"
    symbol_root.mkdir()

    env = os.environ.copy()
    env["DUMP_SKILL_FAKE_OUTPUT"] = fake_output

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
    assert reg["ok"] is True
    return session_file, env, reg["dump_id"]


def test_source_context_returns_requested_window(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    file_a = source_root / "InventoryComponent.cpp"
    file_b = source_root / "PlayerController.cpp"
    file_a.write_text("\n".join([f"line {idx}" for idx in range(1, 11)]), encoding="utf-8")
    file_b.write_text("a\nb\nc\nd\n", encoding="utf-8")

    fake_output = f"""
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 42
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULTING_IP:
myApp!InventoryComponent::UseItem+0x12 [{file_a} @ 5]
STACK_TEXT:
00000000`0014f2b0 myApp!InventoryComponent::UseItem+0x12 [{file_a} @ 5]
00000000`0014f300 myApp!PlayerController::Tick+0x1d [{file_b} @ 3]
LOADED_MODULES:
myApp.exe | good
SYMBOL_STATUS: good
"""

    session_file, env, dump_id = _prepare_registered_dump(
        tmp_path=tmp_path,
        fake_output=fake_output,
        source_root=source_root,
    )

    result = _run_cli(
        [
            "--session-file",
            str(session_file),
            "source-context",
            "--dump-id",
            dump_id,
            "--frame-index",
            "0",
            "--context-before",
            "2",
            "--context-after",
            "1",
        ],
        env=env,
    )
    assert result["ok"] is True
    assert result["focus_line"] == 5
    assert result["start_line"] == 3
    assert result["end_line"] == 6
    assert len(result["lines"]) == 4
    assert result["lines"][0]["text"] == "line 3"


def test_source_context_rejects_outside_source_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    inside_file = source_root / "InventoryComponent.cpp"
    inside_file.write_text("inside\n", encoding="utf-8")
    outside_file = tmp_path / "outside.cpp"
    outside_file.write_text("outside\n", encoding="utf-8")

    fake_output = f"""
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 42
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULTING_IP:
myApp!InventoryComponent::UseItem+0x12 [{inside_file} @ 1]
STACK_TEXT:
00000000`0014f2b0 myApp!InventoryComponent::UseItem+0x12 [{outside_file} @ 1]
LOADED_MODULES:
myApp.exe | good
SYMBOL_STATUS: good
"""

    session_file, env, dump_id = _prepare_registered_dump(
        tmp_path=tmp_path,
        fake_output=fake_output,
        source_root=source_root,
    )

    result = _run_cli(
        [
            "--session-file",
            str(session_file),
            "source-context",
            "--dump-id",
            dump_id,
            "--frame-index",
            "0",
        ],
        env=env,
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_path"


def test_search_uses_dump_source_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "A.cpp").write_text("void UseItem();\nvoid x(){UseItem();}\n", encoding="utf-8")
    (source_root / "B.h").write_text("int UseItemCount = 0;\n", encoding="utf-8")
    (source_root / "Ignore.bin").write_bytes(b"\x00\x01\x02")

    fake_output = """
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 1
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULTING_IP:
myApp!InventoryComponent::UseItem+0x12
STACK_TEXT:
00000000`0014f2b0 myApp!InventoryComponent::UseItem+0x12
LOADED_MODULES:
myApp.exe | good
SYMBOL_STATUS: good
"""

    session_file, env, dump_id = _prepare_registered_dump(
        tmp_path=tmp_path,
        fake_output=fake_output,
        source_root=source_root,
    )

    result = _run_cli(
        [
            "--session-file",
            str(session_file),
            "search",
            "--dump-id",
            dump_id,
            "--query",
            "UseItem",
            "--max-results",
            "10",
        ],
        env=env,
    )

    assert result["ok"] is True
    assert result["count"] >= 2
    assert any(item["file"].endswith("A.cpp") for item in result["results"])
    assert any(item["file"].endswith("B.h") for item in result["results"])


def test_search_requires_source_root_or_dump_id(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    env = os.environ.copy()

    result = _run_cli(
        [
            "--session-file",
            str(session_file),
            "search",
            "--query",
            "UseItem",
        ],
        env=env,
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_request"
