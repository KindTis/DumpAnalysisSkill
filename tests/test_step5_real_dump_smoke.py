from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


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


def _resolve_sample_root() -> Path:
    env_value = os.getenv("DUMP_SKILL_REAL_SAMPLE_ROOT")
    if env_value:
        return Path(env_value).resolve()
    repo_root = Path(__file__).resolve().parents[1]
    return (repo_root.parent / "DumpAnalysisMCP" / "examples" / "cpp-crash-sample").resolve()


def test_real_dump_smoke_register_and_analyze(tmp_path: Path) -> None:
    cdb_path = os.getenv("DUMP_SKILL_CDB_PATH") or os.getenv("DUMP_MCP_CDB_PATH")
    if not cdb_path:
        pytest.skip("cdb path is not configured.")
    if not Path(cdb_path).exists():
        pytest.skip("Configured cdb path does not exist.")

    sample_root = _resolve_sample_root()
    dump_path = sample_root / "cpp_crash_sample.dmp"
    if not dump_path.exists():
        pytest.skip(f"Sample dump not found: {dump_path}")

    session_file = tmp_path / "real-smoke-session.json"
    env = os.environ.copy()
    env.pop("DUMP_SKILL_FAKE_OUTPUT", None)
    env.pop("DUMP_SKILL_FAKE_OUTPUT_FILE", None)
    env.pop("DUMP_SKILL_FAKE_COMMAND_RESULT", None)
    env.pop("DUMP_SKILL_FAKE_COMMAND_TIMEOUT", None)

    reg = _run_cli(
        [
            "--session-file",
            str(session_file),
            "register",
            "--dump-path",
            str(dump_path.resolve()),
            "--symbol-root",
            str(sample_root),
            "--source-root",
            str(sample_root),
            "--project-type",
            "native_cpp",
        ],
        env=env,
    )
    assert reg["ok"] is True
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
    assert analyzed["fault_module"] != "unknown"
    assert analyzed["fault_function"] != "unknown"
    assert int(analyzed["source_location"]["line"]) > 0

