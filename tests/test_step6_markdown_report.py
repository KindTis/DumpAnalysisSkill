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


def test_report_renders_requested_markdown_sections(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    dump_file = tmp_path / "sample.dmp"
    dump_file.write_bytes(b"MZ")
    symbol_root = tmp_path / "symbols"
    source_root = tmp_path / "source"
    symbol_root.mkdir()
    source_root.mkdir()

    source_file = source_root / "main.cpp"
    source_file.write_text(
        "\n".join(
            [
                "void TriggerAccessViolation()",
                "{",
                "    volatile int* ptr = nullptr;",
                "    *ptr = 42;",
                "}",
                "",
                "int main()",
                "{",
                "    TriggerAccessViolation();",
                "    return 0;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    fake_output = f"""
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 0
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULT_ADDRESS: 0x00007FF7C2241712
FAULTING_IP:
cpp_crash_sample!anonymous namespace'::TriggerAccessViolation+0x12 [{source_file} @ 4]
STACK_TEXT:
00000000`0014f2b0 cpp_crash_sample!anonymous namespace'::TriggerAccessViolation+0x12 [{source_file} @ 4]
00000000`0014f300 cpp_crash_sample!main+0x1d [{source_file} @ 9]
00000000`0014f340 kernel32!BaseThreadInitThunk+0x14
00000000`0014f380 ntdll!RtlUserThreadStart+0x21
LOADED_MODULES:
cpp_crash_sample.exe | good
SYMBOL_STATUS: good
"""

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
    dump_id = reg["dump_id"]

    report = _run_cli(
        [
            "--session-file",
            str(session_file),
            "report",
            "--dump-id",
            dump_id,
            "--max-frames",
            "10",
        ],
        env=env,
    )

    assert report["ok"] is True
    assert report["format"] == "markdown"
    markdown = report["report_markdown"]

    assert "## 크래시 덤프 분석 결과" in markdown
    assert "### 예외 정보" in markdown
    assert "| 예외 코드 | `0xC0000005` - `EXCEPTION_ACCESS_VIOLATION` |" in markdown
    assert "| 폴트 주소 | `0x00007FF7C2241712` |" in markdown
    assert "### 콜 스택 (Thread 0)" in markdown
    assert "### 크래시 원인" in markdown
    assert "- 문제 위치:" in markdown
    assert "main.cpp:4" in markdown
    assert "- 문제 코드:" in markdown
    assert "- 주변 코드:" in markdown
    assert "NULL 포인터 역참조(Null Pointer Dereference)" in markdown
    assert "*ptr = 42;" in markdown
    assert "### 호출 흐름 요약" in markdown
    assert "### 수정 방법" in markdown


def test_report_rejects_non_positive_max_frames(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    env = os.environ.copy()
    result = _run_cli(
        ["--session-file", str(session_file), "report", "--dump-id", "crash-missing", "--max-frames", "0"],
        env=env,
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "validation_error"


def test_report_handles_utf8_bom_in_source_file(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    dump_file = tmp_path / "sample.dmp"
    dump_file.write_bytes(b"MZ")
    symbol_root = tmp_path / "symbols"
    source_root = tmp_path / "source"
    symbol_root.mkdir()
    source_root.mkdir()

    source_file = source_root / "main.cpp"
    source_file.write_bytes(
        (
            b"\xef\xbb\xbf"
            + "\n".join(
                [
                    "void TriggerAccessViolation()",
                    "{",
                    "    volatile int* ptr = nullptr;",
                    "    *ptr = 42;",
                    "}",
                ]
            ).encode("utf-8")
            + b"\n"
        )
    )

    fake_output = f"""
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 0
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULTING_IP:
cpp_crash_sample!anonymous namespace'::TriggerAccessViolation+0x12 [{source_file} @ 4]
STACK_TEXT:
00000000`0014f2b0 cpp_crash_sample!anonymous namespace'::TriggerAccessViolation+0x12 [{source_file} @ 4]
LOADED_MODULES:
cpp_crash_sample.exe | good
SYMBOL_STATUS: good
"""

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
    dump_id = reg["dump_id"]

    report = _run_cli(
        [
            "--session-file",
            str(session_file),
            "report",
            "--dump-id",
            dump_id,
        ],
        env=env,
    )

    assert report["ok"] is True
    markdown = report["report_markdown"]
    assert "\ufeff" not in markdown


def test_report_uses_external_markdown_template_file(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    dump_file = tmp_path / "sample.dmp"
    dump_file.write_bytes(b"MZ")
    symbol_root = tmp_path / "symbols"
    source_root = tmp_path / "source"
    symbol_root.mkdir()
    source_root.mkdir()
    source_file = source_root / "main.cpp"
    source_file.write_text("int main(){return 0;}\n", encoding="utf-8")

    template_file = tmp_path / "custom-template.md"
    template_file.write_text(
        "\n".join(
            [
                "# CUSTOM REPORT",
                "코드={{EXCEPTION_CODE}}",
                "스레드={{THREAD_ID}}",
                "{{STACK_ROWS}}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    fake_output = f"""
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 7
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULTING_IP:
cpp_crash_sample!main+0x10 [{source_file} @ 1]
STACK_TEXT:
00000000`0014f2b0 cpp_crash_sample!main+0x10 [{source_file} @ 1]
LOADED_MODULES:
cpp_crash_sample.exe | good
SYMBOL_STATUS: good
"""
    env = os.environ.copy()
    env["DUMP_SKILL_FAKE_OUTPUT"] = fake_output
    env["DUMP_SKILL_REPORT_TEMPLATE_FILE"] = str(template_file)

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

    report = _run_cli(
        [
            "--session-file",
            str(session_file),
            "report",
            "--dump-id",
            dump_id,
        ],
        env=env,
    )

    assert report["ok"] is True
    markdown = report["report_markdown"]
    assert "# CUSTOM REPORT" in markdown
    assert "코드=0xC0000005" in markdown
    assert "스레드=7" in markdown


def test_report_falls_back_to_filename_when_dump_path_is_relative_hint(tmp_path: Path) -> None:
    session_file = tmp_path / "sessions.json"
    dump_file = tmp_path / "sample.dmp"
    dump_file.write_bytes(b"MZ")
    symbol_root = tmp_path / "symbols"
    source_root = tmp_path / "source"
    symbol_root.mkdir()
    source_root.mkdir()

    # Real file is at source root, but dump points to src/main.cpp.
    source_file = source_root / "main.cpp"
    source_file.write_text(
        "\n".join(
            [
                "void CrashNow()",
                "{",
                "    volatile int* ptr = nullptr;",
                "    *ptr = 42;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    fake_output = """
DUMP_TYPE: minidump
PROJECT_TYPE: native_cpp
FAULTING_THREAD: 0
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - EXCEPTION_ACCESS_VIOLATION
FAULTING_IP:
cpp_crash_sample!CrashNow+0x12 [src/main.cpp @ 4]
STACK_TEXT:
00000000`0014f2b0 cpp_crash_sample!CrashNow+0x12 [src/main.cpp @ 4]
LOADED_MODULES:
cpp_crash_sample.exe | good
SYMBOL_STATUS: good
"""
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
    dump_id = reg["dump_id"]

    report = _run_cli(
        [
            "--session-file",
            str(session_file),
            "report",
            "--dump-id",
            dump_id,
        ],
        env=env,
    )

    assert report["ok"] is True
    markdown = report["report_markdown"]
    assert "- 문제 코드: 확인 불가" not in markdown
    assert "main.cpp:4" in markdown
    assert "*ptr = 42;" in markdown
