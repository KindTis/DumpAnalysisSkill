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


def test_e2e_flow_register_to_patch_build_test(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    dump_file = tmp_path / "sample.dmp"
    dump_file.write_bytes(b"MZ")
    symbol_root = tmp_path / "symbols"
    source_root = tmp_path / "source"
    symbol_root.mkdir()
    source_root.mkdir()

    src_a = source_root / "InventoryComponent.cpp"
    src_b = source_root / "PlayerController.cpp"
    src_a.write_text("\n".join([f"line {idx}" for idx in range(1, 11)]) + "\n", encoding="utf-8")
    src_b.write_text("void x(){UseItem();}\n", encoding="utf-8")

    fake_output = f"""
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 42
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULTING_IP:
myApp!InventoryComponent::UseItem+0x12 [{src_a} @ 5]
STACK_TEXT:
00000000`0014f2b0 myApp!InventoryComponent::UseItem+0x12 [{src_a} @ 5]
00000000`0014f300 myApp!PlayerController::Tick+0x1d [{src_b} @ 1]
LOADED_MODULES:
myApp.exe | good
SYMBOL_STATUS: good
"""

    env = os.environ.copy()
    env["DUMP_SKILL_FAKE_OUTPUT"] = fake_output
    env["DUMP_SKILL_FAKE_COMMAND_RESULT"] = json.dumps(
        {"return_code": 0, "stdout": "ok", "stderr": ""}
    )

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
    dump_id = reg["dump_id"]

    analyzed = _run_cli(
        ["--session-file", str(session_file), "analyze", "--dump-id", dump_id],
        env=env,
    )
    assert analyzed["ok"] is True
    assert analyzed["exception_code"] == "0xC0000005"

    context = _run_cli(
        [
            "--session-file",
            str(session_file),
            "source-context",
            "--dump-id",
            dump_id,
            "--frame-index",
            "0",
            "--context-before",
            "1",
            "--context-after",
            "1",
        ],
        env=env,
    )
    assert context["ok"] is True
    assert context["focus_line"] == 5

    search = _run_cli(
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
    assert search["ok"] is True
    assert search["count"] >= 1

    preview = _run_cli(
        [
            "--session-file",
            str(session_file),
            "patch",
            "--source-root",
            str(source_root.resolve()),
            "--mode",
            "preview",
            "--changes-json",
            json.dumps([{"path": "InventoryComponent.cpp", "content": "patched\n"}], ensure_ascii=False),
        ],
        env=env,
    )
    assert preview["ok"] is True
    assert preview["applied"] is False

    apply = _run_cli(
        [
            "--session-file",
            str(session_file),
            "patch",
            "--source-root",
            str(source_root.resolve()),
            "--mode",
            "apply",
            "--user-confirmed",
            "--changes-json",
            json.dumps([{"path": "InventoryComponent.cpp", "content": "patched\n"}], ensure_ascii=False),
        ],
        env=env,
    )
    assert apply["ok"] is True
    assert apply["applied"] is True
    assert src_a.read_text(encoding="utf-8") == "patched\n"

    build = _run_cli(
        [
            "--session-file",
            str(session_file),
            "build",
            "--command",
            "dotnet build Airi.sln -c Debug",
            "--working-directory",
            str(tmp_path.resolve()),
            "--user-confirmed",
        ],
        env=env,
    )
    assert build["ok"] is True
    assert build["tool"] == "build_project"

    test = _run_cli(
        [
            "--session-file",
            str(session_file),
            "test",
            "--command",
            "dotnet test tests/Airi.Tests/Airi.Tests.csproj -c Debug",
            "--working-directory",
            str(tmp_path.resolve()),
            "--user-confirmed",
        ],
        env=env,
    )
    assert test["ok"] is True
    assert test["tool"] == "run_tests"
