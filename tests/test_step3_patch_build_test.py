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


def test_patch_defaults_to_preview_and_does_not_write_file(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    target = source_root / "A.cpp"
    target.write_text("int a = 1;\n", encoding="utf-8")

    changes_json = json.dumps([{"path": "A.cpp", "content": "int a = 2;\n"}], ensure_ascii=False)
    result = _run_cli(
        [
            "patch",
            "--source-root",
            str(source_root.resolve()),
            "--changes-json",
            changes_json,
        ],
        env=os.environ.copy(),
    )

    assert result["ok"] is True
    assert result["mode"] == "preview"
    assert result["applied"] is False
    assert target.read_text(encoding="utf-8") == "int a = 1;\n"
    assert "int a = 1;" in result["diff"]
    assert "int a = 2;" in result["diff"]


def test_patch_requires_confirmation_for_apply_mode(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "A.cpp").write_text("int a = 1;\n", encoding="utf-8")

    changes_json = json.dumps([{"path": "A.cpp", "content": "int a = 2;\n"}], ensure_ascii=False)
    result = _run_cli(
        [
            "patch",
            "--source-root",
            str(source_root.resolve()),
            "--mode",
            "apply",
            "--changes-json",
            changes_json,
        ],
        env=os.environ.copy(),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "policy_violation"


def test_patch_writes_when_apply_mode_and_confirmed(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    target = source_root / "A.cpp"
    target.write_text("int a = 1;\n", encoding="utf-8")

    changes_json = json.dumps([{"path": "A.cpp", "content": "int a = 3;\n"}], ensure_ascii=False)
    result = _run_cli(
        [
            "patch",
            "--source-root",
            str(source_root.resolve()),
            "--mode",
            "apply",
            "--user-confirmed",
            "--changes-json",
            changes_json,
        ],
        env=os.environ.copy(),
    )

    assert result["ok"] is True
    assert result["mode"] == "apply"
    assert result["applied"] is True
    assert target.read_text(encoding="utf-8") == "int a = 3;\n"


def test_patch_rejects_path_escape_outside_source_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()

    changes_json = json.dumps([{"path": "..\\escape.cpp", "content": "bad\n"}], ensure_ascii=False)
    result = _run_cli(
        [
            "patch",
            "--source-root",
            str(source_root.resolve()),
            "--changes-json",
            changes_json,
        ],
        env=os.environ.copy(),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_path"


def test_build_requires_user_confirmation(tmp_path: Path) -> None:
    result = _run_cli(
        [
            "build",
            "--command",
            "dotnet build Airi.sln -c Debug",
            "--working-directory",
            str(tmp_path.resolve()),
        ],
        env=os.environ.copy(),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "policy_violation"


def test_build_rejects_shell_chaining(tmp_path: Path) -> None:
    result = _run_cli(
        [
            "build",
            "--command",
            "dotnet build Airi.sln -c Debug && echo done",
            "--working-directory",
            str(tmp_path.resolve()),
            "--user-confirmed",
        ],
        env=os.environ.copy(),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "policy_violation"


def test_build_runs_allowlisted_command_with_fake_runner(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["DUMP_SKILL_FAKE_COMMAND_RESULT"] = json.dumps(
        {"return_code": 0, "stdout": "build ok", "stderr": ""}
    )

    result = _run_cli(
        [
            "build",
            "--command",
            "dotnet build Airi.sln -c Debug",
            "--working-directory",
            str(tmp_path.resolve()),
            "--user-confirmed",
        ],
        env=env,
    )

    assert result["ok"] is True
    assert result["tool"] == "build_project"
    assert result["status"] == "passed"
    assert result["exit_code"] == 0


def test_test_command_returns_failure_on_nonzero_exit(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["DUMP_SKILL_FAKE_COMMAND_RESULT"] = json.dumps(
        {"return_code": 1, "stdout": "x", "stderr": "failed"}
    )

    result = _run_cli(
        [
            "test",
            "--command",
            "dotnet test tests/Airi.Tests/Airi.Tests.csproj -c Debug",
            "--working-directory",
            str(tmp_path.resolve()),
            "--user-confirmed",
        ],
        env=env,
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "test_failed"


def test_test_command_returns_timeout_error(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["DUMP_SKILL_FAKE_COMMAND_TIMEOUT"] = "1"

    result = _run_cli(
        [
            "test",
            "--command",
            "dotnet test tests/Airi.Tests/Airi.Tests.csproj -c Debug",
            "--working-directory",
            str(tmp_path.resolve()),
            "--timeout-seconds",
            "1",
            "--user-confirmed",
        ],
        env=env,
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "test_failed"

