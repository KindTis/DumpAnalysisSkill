#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from difflib import unified_diff
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


_EXCEPTION_PATTERN = re.compile(
    r"EXCEPTION_CODE:\s*(?:\(NTSTATUS\)\s*)?((?:0x)?[0-9a-fA-F]+)(?:\s*-\s*([A-Z0-9_]+))?"
)
_EXCEPTION_RECORD_PATTERN = re.compile(
    r"ExceptionCode:\s*((?:0x)?[0-9a-fA-F]+)\s*\(([^)]+)\)",
    re.IGNORECASE,
)
_EARLY_EXCEPTION_PATTERN = re.compile(
    r"\(([0-9a-fA-F]+)\.([0-9a-fA-F]+)\):\s*([^-]+)-\s*code\s*((?:0x)?[0-9a-fA-F]+)",
    re.IGNORECASE,
)
_THREAD_PATTERN = re.compile(r"FAULTING_THREAD:\s*(\d+)")
_THREAD_HEX_PATTERN = re.compile(r"FAULTING_THREAD:\s*([0-9a-fA-F]+)", re.IGNORECASE)
_FAULT_LINE_PATTERN = re.compile(
    r"(?P<symbol>[^\s\[]+)(?:\s+\[(?P<file>.+?)\s*@\s*(?P<line>\d+)\])?"
)
_STACK_LINE_PATTERN = re.compile(
    r"^\s*[0-9a-fA-F`]+\s+(?P<symbol>[^\s\[]+![^\s\[]+)(?:\s+\[(?P<file>.+?)\s*@\s*(?P<line>\d+)\])?"
)
_STACK_INDEX_LINE_PATTERN = re.compile(r"^\s*(?P<index>\d+)\s+[0-9a-fA-F`]+\s+[0-9a-fA-F`]+")
_STACK_COMPACT_PREFIX_PATTERN = re.compile(r"^\s*[0-9a-fA-F`]+\s+[0-9a-fA-F`]+\s+")
_SOURCE_LINE_PATTERN = re.compile(
    r"^(?P<file>[A-Za-z]:\\.+?)\((?P<line>\d+)\)\+0x[0-9a-fA-F]+$",
    re.IGNORECASE,
)
_MODULE_STATUS_PATTERN = re.compile(r"^(?P<module>.+?)\s*\|\s*(?P<status>\w+)\s*$")
_MODULE_LM_PATTERN = re.compile(
    r"^[0-9a-fA-F`]+\s+[0-9a-fA-F`]+\s+(?P<module>\S+)\s+\S+\s+\((?P<status>[^)]+)\)",
    re.IGNORECASE,
)
_SYMBOL_STATUS_PATTERN = re.compile(r"SYMBOL_STATUS:\s*(good|partial|poor|missing)")
_FAULT_ADDRESS_PATTERN = re.compile(r"FAULT_ADDRESS:\s*(0x[0-9a-fA-F]+)")
_EXCEPTION_ADDRESS_PATTERN = re.compile(r"ExceptionAddress:\s*([0-9a-fA-F`]+)", re.IGNORECASE)
_DUMP_TYPE_PATTERN = re.compile(r"DUMP_TYPE:\s*(\w+)")
_PROJECT_TYPE_PATTERN = re.compile(r"PROJECT_TYPE:\s*(\w+)")
_FAULT_SYMBOL_WITH_LINE_PATTERN = re.compile(
    r"(?P<symbol>[^\[]+![^\[]+?)\+(?:0x)?[0-9a-fA-F]+\s+\[(?P<file>.+?)\s*@\s*(?P<line>\d+)\]",
    re.IGNORECASE,
)
_FAULT_SYMBOL_PATTERN = re.compile(
    r"(?P<symbol>[^:\[]+![^:\[]+?)\+(?:0x)?[0-9a-fA-F]+:?",
    re.IGNORECASE,
)
_DUMP_ID_PATTERN = re.compile(r"^crash-(\d{8}-\d{6})-(\d{3})$")
_CHAIN_PATTERN = re.compile(r"(?:&&)|\||;")
_DEREF_ASSIGN_PATTERN = re.compile(r"^\*(?P<ptr>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+);$")
_TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".inl",
    ".ixx",
    ".cs",
    ".py",
    ".txt",
    ".ini",
    ".json",
    ".uplugin",
    ".uproject",
}
_DEFAULT_BUILD_ALLOWLIST = (
    "msbuild",
    "dotnet",
    "cmake",
    "ninja",
    "UnrealBuildTool",
    "RunUAT",
)
_DEFAULT_TEST_ALLOWLIST = (
    "ctest",
    "dotnet",
    "pytest",
    "UnrealEditor-Cmd",
    "RunUAT",
)


class SkillError(Exception):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


DEFAULT_SESSION_FILE = Path(__file__).resolve().parents[1] / ".dump-sessions.json"
DEFAULT_REPORT_TEMPLATE_FILE = Path(__file__).resolve().parents[1] / "references" / "report-template.md"


def _emit(payload: dict[str, Any]) -> int:
    json.dump(payload, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


def _ok(**kwargs: Any) -> dict[str, Any]:
    return {"ok": True, **kwargs}


def _err(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        },
    }


def _require_absolute(value: str, field: str) -> str:
    p = Path(value)
    if not p.is_absolute():
        raise SkillError("validation_error", f"{field} must be an absolute path.")
    return str(p.resolve())


def _require_existing_file(path: str, code: str, field: str) -> str:
    resolved = _require_absolute(path, field)
    p = Path(resolved)
    if not p.exists() or not p.is_file():
        raise SkillError(code, f"{field} file not found.", {"path": resolved})
    return resolved


def _require_existing_dir(path: str, code: str, field: str) -> str:
    resolved = _require_absolute(path, field)
    p = Path(resolved)
    if not p.exists() or not p.is_dir():
        raise SkillError(code, f"{field} directory not found.", {"path": resolved})
    return resolved


def _read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"sessions": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SkillError(
            "invalid_session_store",
            "Session file is not valid JSON.",
            {"path": str(path), "message": str(exc)},
        ) from exc
    if not isinstance(data, dict) or "sessions" not in data or not isinstance(data["sessions"], list):
        raise SkillError(
            "invalid_session_store",
            "Session file has invalid structure.",
            {"path": str(path)},
        )
    return data


def _write_json_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _get_report_template_path() -> Path:
    env_path = os.getenv("DUMP_SKILL_REPORT_TEMPLATE_FILE")
    if env_path:
        return Path(env_path).resolve()
    return DEFAULT_REPORT_TEMPLATE_FILE


def _load_report_template_text() -> str:
    path = _get_report_template_path()
    if not path.exists() or not path.is_file():
        raise SkillError(
            "invalid_path",
            "Report template file not found.",
            {"template_file": str(path)},
        )
    return path.read_text(encoding="utf-8")


def _apply_report_template(template: str, values: dict[str, str]) -> str:
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", value)

    unresolved = sorted(set(re.findall(r"\{\{[A-Z0-9_]+\}\}", rendered)))
    if unresolved:
        raise SkillError(
            "validation_error",
            "Report template contains unresolved placeholders.",
            {"placeholders": unresolved, "template_file": str(_get_report_template_path())},
        )
    return rendered.strip() + "\n"


def _load_session_file(session_file: str) -> tuple[Path, dict[str, Any]]:
    session_path = Path(_require_absolute(session_file, "session_file"))
    return session_path, _read_json_file(session_path)


def _new_dump_id(existing: list[dict[str, Any]]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    seq = 1
    for item in existing:
        dump_id = str(item.get("dump_id", ""))
        m = _DUMP_ID_PATTERN.match(dump_id)
        if not m:
            continue
        if m.group(1) != timestamp:
            continue
        seq = max(seq, int(m.group(2)) + 1)
    return f"crash-{timestamp}-{seq:03d}"


def _get_session(session_file: str, dump_id: str) -> dict[str, Any]:
    _, data = _load_session_file(session_file)
    for item in data["sessions"]:
        if item.get("dump_id") == dump_id:
            return item
    raise SkillError("invalid_request", f"dump_id '{dump_id}' does not exist.", {"dump_id": dump_id})


def _is_inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _resolve_source_file(source_root: str, source_file: str) -> Path:
    root = Path(source_root).resolve()
    file_candidate = Path(source_file)
    target = file_candidate if file_candidate.is_absolute() else (root / file_candidate)
    target = target.resolve()
    if not _is_inside_root(target, root):
        raise SkillError(
            "invalid_path",
            "Resolved source file is outside source_root.",
            {"source_root": str(root), "source_file": str(target)},
        )
    return target


def _get_source_context_payload(
    *,
    source_root: str,
    source_file: str,
    focus_line: int,
    context_before: int,
    context_after: int,
) -> dict[str, Any]:
    if context_before < 0 or context_after < 0:
        raise SkillError("invalid_request", "context_before/context_after must be >= 0.")
    if focus_line <= 0:
        raise SkillError(
            "source_mapping_failed",
            "Source line is not available for requested frame.",
            {"focus_line": focus_line},
        )

    target = _resolve_source_file(source_root, source_file)
    if not target.exists() or not target.is_file():
        raise SkillError(
            "source_mapping_failed",
            "Resolved source file does not exist.",
            {"source_file": str(target)},
        )

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return {
            "file": str(target),
            "start_line": 1,
            "end_line": 0,
            "focus_line": focus_line,
            "lines": [],
        }

    clamped_focus = min(max(focus_line, 1), len(lines))
    start_line = max(1, clamped_focus - context_before)
    end_line = min(len(lines), clamped_focus + context_after)
    selected = [{"line": idx + 1, "text": lines[idx]} for idx in range(start_line - 1, end_line)]
    return {
        "file": str(target),
        "start_line": start_line,
        "end_line": end_line,
        "focus_line": clamped_focus,
        "lines": selected,
    }


def _search_code_references_payload(
    *,
    source_root: str,
    query: str,
    max_results: int,
    ignore_case: bool,
) -> list[dict[str, Any]]:
    if not query.strip():
        raise SkillError("invalid_request", "query must be non-empty.")
    if max_results <= 0:
        raise SkillError("invalid_request", "max_results must be positive.")

    root = Path(source_root).resolve()
    if not root.exists() or not root.is_dir():
        raise SkillError(
            "source_root_invalid",
            "source_root does not exist.",
            {"source_root": str(root)},
        )

    needle = query.lower() if ignore_case else query
    results: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if len(results) >= max_results:
            break
        if not path.is_file():
            continue
        if path.suffix.lower() not in _TEXT_EXTENSIONS:
            continue
        if not _is_inside_root(path, root):
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        for idx, line in enumerate(content, start=1):
            hay = line.lower() if ignore_case else line
            if needle in hay:
                results.append(
                    {
                        "file": str(path.resolve()),
                        "line": idx,
                        "match": line.strip(),
                    }
                )
                if len(results) >= max_results:
                    break
    return results


def _parse_csv(value: str | None, fallback: tuple[str, ...]) -> tuple[str, ...]:
    if not value:
        return fallback
    items = [item.strip() for item in value.split(",")]
    return tuple(item for item in items if item)


def _get_build_allowlist() -> tuple[str, ...]:
    return _parse_csv(
        os.getenv("DUMP_SKILL_BUILD_ALLOWLIST") or os.getenv("DUMP_MCP_BUILD_ALLOWLIST"),
        _DEFAULT_BUILD_ALLOWLIST,
    )


def _get_test_allowlist() -> tuple[str, ...]:
    return _parse_csv(
        os.getenv("DUMP_SKILL_TEST_ALLOWLIST") or os.getenv("DUMP_MCP_TEST_ALLOWLIST"),
        _DEFAULT_TEST_ALLOWLIST,
    )


def _get_max_output_chars() -> int:
    value = os.getenv("DUMP_SKILL_MAX_OUTPUT_CHARS") or os.getenv("DUMP_MCP_MAX_OUTPUT_CHARS") or "200000"
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SkillError("validation_error", "max_output_chars must be an integer.", {"value": value}) from exc
    if parsed <= 0:
        raise SkillError("validation_error", "max_output_chars must be positive.", {"value": parsed})
    return parsed


def _get_default_timeout(tool: str) -> int:
    if tool == "build":
        raw = os.getenv("DUMP_SKILL_BUILD_TIMEOUT_SECONDS") or os.getenv("DUMP_MCP_BUILD_TIMEOUT_SECONDS") or "1200"
    else:
        raw = os.getenv("DUMP_SKILL_TEST_TIMEOUT_SECONDS") or os.getenv("DUMP_MCP_TEST_TIMEOUT_SECONDS") or "1800"
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise SkillError("validation_error", f"{tool} timeout must be an integer.", {"value": raw}) from exc
    if parsed <= 0:
        raise SkillError("validation_error", f"{tool} timeout must be positive.", {"value": parsed})
    return parsed


def _contains_shell_chaining(command: str) -> bool:
    return bool(_CHAIN_PATTERN.search(command))


def _normalize_command_name(executable: str) -> str:
    raw = executable.strip().strip('"').strip("'")
    base = Path(raw).name if ("\\" in raw or "/" in raw) else raw
    return os.path.splitext(base)[0].lower()


def _validate_command(command: str, allowlist: tuple[str, ...]) -> str:
    if _contains_shell_chaining(command):
        raise SkillError(
            "policy_violation",
            "Shell chaining operators are not allowed.",
            {"command": command},
        )
    if not command.strip():
        raise SkillError("invalid_request", "command must be non-empty.")

    parts = shlex.split(command, posix=False)
    if not parts:
        raise SkillError("invalid_request", "Command is empty after parsing.")

    normalized = _normalize_command_name(parts[0])
    allowed = {item.lower() for item in allowlist}
    if normalized not in allowed:
        raise SkillError(
            "policy_violation",
            "Command is not allowed by policy.",
            {
                "command": command,
                "normalized_executable": normalized,
                "allowlist": sorted(allowed),
            },
        )
    return normalized


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"


def _run_command(args: list[str], cwd: str | None, timeout_seconds: int) -> tuple[int, str, str]:
    if os.getenv("DUMP_SKILL_FAKE_COMMAND_TIMEOUT") == "1":
        raise TimeoutError("timed out")

    fake = os.getenv("DUMP_SKILL_FAKE_COMMAND_RESULT")
    if fake:
        try:
            parsed = json.loads(fake)
        except json.JSONDecodeError as exc:
            raise SkillError(
                "validation_error",
                "DUMP_SKILL_FAKE_COMMAND_RESULT must be valid JSON.",
                {"message": str(exc)},
            ) from exc
        return_code = int(parsed.get("return_code", 0))
        stdout = str(parsed.get("stdout", ""))
        stderr = str(parsed.get("stderr", ""))
        return return_code, stdout, stderr

    completed = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def _resolve_working_directory(
    *,
    session_file: str,
    dump_id: str | None,
    working_directory: str | None,
) -> str | None:
    if working_directory:
        wd = Path(_require_absolute(working_directory, "working_directory"))
        if not wd.exists() or not wd.is_dir():
            raise SkillError(
                "invalid_path",
                "working_directory does not exist.",
                {"working_directory": str(wd)},
            )
        return str(wd)

    if dump_id:
        source_root = str(_get_session(session_file, dump_id)["source_root"])
        wd = Path(source_root)
        if not wd.exists() or not wd.is_dir():
            raise SkillError(
                "invalid_path",
                "source_root from dump_id does not exist.",
                {"dump_id": dump_id, "source_root": source_root},
            )
        return source_root

    return None


def _run_guarded_command(
    *,
    tool_name: str,
    error_code: str,
    command: str,
    user_confirmed: bool,
    allowlist: tuple[str, ...],
    timeout_seconds: int | None,
    default_timeout: int,
    working_directory: str | None,
) -> dict[str, Any]:
    if not user_confirmed:
        raise SkillError(
            "policy_violation",
            f"{tool_name} requires explicit user confirmation.",
            {"required_flag": "user_confirmed"},
        )

    normalized = _validate_command(command, allowlist)
    args = shlex.split(command, posix=False)
    if not args:
        raise SkillError("invalid_request", "Command cannot be empty after parsing.")

    timeout = timeout_seconds if timeout_seconds is not None else default_timeout
    if timeout <= 0:
        raise SkillError("invalid_request", "timeout_seconds must be positive.", {"timeout_seconds": timeout})

    try:
        return_code, stdout, stderr = _run_command(args=args, cwd=working_directory, timeout_seconds=timeout)
    except TimeoutError as exc:
        raise SkillError(
            error_code,
            f"{tool_name} timed out.",
            {"command": command, "timeout_seconds": timeout, "timed_out": True},
        ) from exc
    except SkillError:
        raise
    except Exception as exc:
        raise SkillError(
            error_code,
            f"{tool_name} execution failed.",
            {"command": command, "exception": type(exc).__name__, "message": str(exc)},
        ) from exc

    max_output_chars = _get_max_output_chars()
    trimmed_stdout = _truncate(stdout, max_output_chars)
    trimmed_stderr = _truncate(stderr, max_output_chars)
    if return_code != 0:
        raise SkillError(
            error_code,
            f"{tool_name} command failed.",
            {
                "command": command,
                "exit_code": return_code,
                "stdout": trimmed_stdout,
                "stderr": trimmed_stderr,
                "normalized_executable": normalized,
            },
        )

    return _ok(
        tool=tool_name,
        status="passed",
        command=command,
        normalized_executable=normalized,
        exit_code=return_code,
        stdout=trimmed_stdout,
        stderr=trimmed_stderr,
        timeout_seconds=timeout,
    )


def _resolve_patch_source_root(args: argparse.Namespace) -> str:
    if args.source_root:
        return _require_existing_dir(str(args.source_root), "source_root_invalid", "source_root")
    if args.dump_id:
        source_root = str(_get_session(str(args.session_file), str(args.dump_id))["source_root"])
        return _require_existing_dir(source_root, "source_root_invalid", "source_root")
    raise SkillError("invalid_request", "patch requires either 'source_root' or 'dump_id'.")


def _resolve_patch_target(root: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    target = candidate if candidate.is_absolute() else (root / candidate)
    resolved = target.resolve()
    if not _is_inside_root(resolved, root):
        raise SkillError(
            "invalid_path",
            "Patch target path is outside source_root.",
            {"source_root": str(root), "target": str(resolved)},
        )
    return resolved


def _load_patch_changes(args: argparse.Namespace) -> list[dict[str, str]]:
    has_json = bool(args.changes_json)
    has_file = bool(args.changes_file)
    if has_json == has_file:
        raise SkillError(
            "invalid_request",
            "Provide exactly one of --changes-json or --changes-file.",
        )

    if has_json:
        raw = str(args.changes_json)
    else:
        path = Path(str(args.changes_file))
        if not path.exists() or not path.is_file():
            raise SkillError("invalid_path", "changes_file not found.", {"path": str(path)})
        raw = path.read_text(encoding="utf-8")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SkillError("invalid_request", "changes JSON is invalid.", {"message": str(exc)}) from exc

    if not isinstance(parsed, list) or not parsed:
        raise SkillError("invalid_request", "changes must be a non-empty list.")

    result: list[dict[str, str]] = []
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise SkillError("invalid_request", "Each change must be an object.", {"index": idx})
        path = item.get("path")
        content = item.get("content")
        if not isinstance(path, str) or not path.strip():
            raise SkillError("invalid_request", "Change 'path' must be non-empty string.", {"index": idx})
        if not isinstance(content, str):
            raise SkillError("invalid_request", "Change 'content' must be string.", {"index": idx})
        result.append({"path": path, "content": content})
    return result


def _exception_name_from_text(text: str) -> str:
    normalized = text.strip().lower()
    mapping = {
        "access violation": "EXCEPTION_ACCESS_VIOLATION",
        "stack overflow": "EXCEPTION_STACK_OVERFLOW",
        "illegal instruction": "EXCEPTION_ILLEGAL_INSTRUCTION",
    }
    return mapping.get(normalized, "UNKNOWN_EXCEPTION")


def _normalize_exception_code(value: str) -> str:
    stripped = value.lower().removeprefix("0x")
    return f"0x{stripped.upper().zfill(8)}"


def _fault_type(exception_name: str) -> str:
    mapping = {
        "EXCEPTION_ACCESS_VIOLATION": "access_violation",
        "EXCEPTION_STACK_OVERFLOW": "stack_overflow",
        "EXCEPTION_ILLEGAL_INSTRUCTION": "illegal_instruction",
    }
    return mapping.get(exception_name, "unknown")


def _parse_symbol(raw_symbol: str) -> tuple[str, str]:
    symbol = raw_symbol.strip()
    if "!" not in symbol:
        return "unknown", symbol
    module, fn = symbol.split("!", 1)
    function = fn.split("+", 1)[0]
    return module, function


def _extract_section(lines: list[str], header: str) -> list[str]:
    target = f"{header}:"
    start_index = -1
    for idx, line in enumerate(lines):
        if line.strip() == target:
            start_index = idx + 1
            break
    if start_index < 0:
        return []

    collected: list[str] = []
    for line in lines[start_index:]:
        stripped = line.strip()
        if stripped.endswith(":") and stripped.isupper():
            break
        if not stripped and collected:
            break
        if stripped:
            collected.append(line)
    return collected


def _normalize_module_symbol_status(raw_status: str) -> str:
    status = raw_status.strip().lower()
    if "private pdb" in status or ("symbols" in status and "no symbols" not in status):
        return "good"
    if "export symbols" in status or "partial" in status:
        return "partial"
    if "deferred" in status or "no symbols" in status:
        return "missing"
    return "unknown"


def _parse_stack_frames_from_lines(lines: list[str]) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        source_match = _SOURCE_LINE_PATTERN.match(stripped)
        if source_match and frames and not frames[-1]["file"]:
            frames[-1]["file"] = source_match.group("file")
            frames[-1]["line"] = int(source_match.group("line"))
            continue

        match = _STACK_INDEX_LINE_PATTERN.match(stripped)
        if match and " : " in stripped:
            call_site = stripped.rsplit(" : ", 1)[-1].strip()
            if "!" not in call_site:
                continue
            module, function = _parse_symbol(call_site)
            frames.append(
                {
                    "index": len(frames),
                    "module": module,
                    "function": function,
                    "file": "",
                    "line": 0,
                    "address": "",
                }
            )
            continue

        match = _STACK_LINE_PATTERN.match(stripped)
        if match:
            module, function = _parse_symbol(match.group("symbol"))
            frames.append(
                {
                    "index": len(frames),
                    "module": module,
                    "function": function,
                    "file": match.group("file") or "",
                    "line": int(match.group("line")) if match.group("line") else 0,
                    "address": "",
                }
            )
            continue

        match = _STACK_COMPACT_PREFIX_PATTERN.match(stripped)
        if match:
            symbol_text = stripped[match.end() :].strip()
            if "!" not in symbol_text:
                continue
            module, function = _parse_symbol(symbol_text)
            frames.append(
                {
                    "index": len(frames),
                    "module": module,
                    "function": function,
                    "file": "",
                    "line": 0,
                    "address": "",
                }
            )

    return frames


def _parse_analysis_output(raw_output: str, *, fallback_project_type: str, dump_id: str) -> dict[str, Any]:
    lines = raw_output.splitlines()

    exception_code = "0x00000000"
    exception_name = "UNKNOWN_EXCEPTION"
    exception_match = _EXCEPTION_PATTERN.search(raw_output)
    if exception_match:
        exception_code = _normalize_exception_code(exception_match.group(1))
        if exception_match.group(2):
            exception_name = exception_match.group(2)
    else:
        exception_record_match = _EXCEPTION_RECORD_PATTERN.search(raw_output)
        if exception_record_match:
            exception_code = _normalize_exception_code(exception_record_match.group(1))
            exception_name = _exception_name_from_text(exception_record_match.group(2))
        else:
            early_match = _EARLY_EXCEPTION_PATTERN.search(raw_output)
            if early_match:
                exception_code = _normalize_exception_code(early_match.group(4))
                exception_name = _exception_name_from_text(early_match.group(3))

    thread_id = 0
    thread_match = _THREAD_PATTERN.search(raw_output)
    if thread_match:
        thread_id = int(thread_match.group(1))
    else:
        thread_hex_match = _THREAD_HEX_PATTERN.search(raw_output)
        if thread_hex_match:
            value = thread_hex_match.group(1).lower()
            if value != "ffffffff":
                thread_id = int(value, 16)
        else:
            early_match = _EARLY_EXCEPTION_PATTERN.search(raw_output)
            if early_match:
                thread_id = int(early_match.group(2), 16)

    fault_address = "unknown"
    fault_address_match = _FAULT_ADDRESS_PATTERN.search(raw_output)
    if fault_address_match:
        fault_address = fault_address_match.group(1)
    else:
        exception_address_match = _EXCEPTION_ADDRESS_PATTERN.search(raw_output)
        if exception_address_match:
            raw_value = exception_address_match.group(1).replace("`", "")
            fault_address = f"0x{raw_value.upper()}"

    dump_type = "unknown"
    dump_type_match = _DUMP_TYPE_PATTERN.search(raw_output)
    if dump_type_match:
        dump_type = dump_type_match.group(1).lower()

    project_type = fallback_project_type
    project_type_match = _PROJECT_TYPE_PATTERN.search(raw_output)
    if project_type_match:
        project_type = project_type_match.group(1)

    fault_module = "unknown"
    fault_function = "unknown"
    source_file = "unknown"
    source_line = 0
    for line in lines:
        match = _FAULT_SYMBOL_WITH_LINE_PATTERN.search(line.strip())
        if not match:
            continue
        fault_module, fault_function = _parse_symbol(match.group("symbol"))
        source_file = match.group("file")
        source_line = int(match.group("line"))
        break

    if fault_module == "unknown":
        for line in lines:
            match = _FAULT_SYMBOL_PATTERN.search(line.strip())
            if not match:
                continue
            fault_module, fault_function = _parse_symbol(match.group("symbol"))
            break

    for line in _extract_section(lines, "FAULTING_IP"):
        match = _FAULT_LINE_PATTERN.search(line.strip())
        if not match:
            continue
        fault_module, fault_function = _parse_symbol(match.group("symbol"))
        if match.group("file"):
            source_file = match.group("file")
        if match.group("line"):
            source_line = int(match.group("line"))
        break

    stack_frames = _parse_stack_frames_from_lines(lines)
    if not stack_frames:
        stack_frames = _parse_stack_frames_from_lines(_extract_section(lines, "STACK_TEXT"))

    if source_file == "unknown":
        for frame in stack_frames:
            if frame["file"] and frame["line"] > 0:
                source_file = frame["file"]
                source_line = frame["line"]
                break

    loaded_modules: list[dict[str, str]] = []
    for line in _extract_section(lines, "LOADED_MODULES"):
        m = _MODULE_STATUS_PATTERN.match(line.strip())
        if not m:
            continue
        loaded_modules.append({"module": m.group("module").strip(), "symbol_status": m.group("status").lower()})
    if not loaded_modules:
        for line in lines:
            m = _MODULE_LM_PATTERN.match(line.strip())
            if not m:
                continue
            loaded_modules.append(
                {
                    "module": m.group("module").strip(),
                    "symbol_status": _normalize_module_symbol_status(m.group("status")),
                }
            )

    symbol_quality = "missing"
    symbol_match = _SYMBOL_STATUS_PATTERN.search(raw_output)
    if symbol_match:
        symbol_quality = symbol_match.group(1).lower()
    elif loaded_modules:
        statuses = {item["symbol_status"] for item in loaded_modules}
        if "poor" in statuses or "missing" in statuses:
            symbol_quality = "poor"
        elif "partial" in statuses:
            symbol_quality = "partial"
        else:
            symbol_quality = "good"
    elif "private pdb symbols" in raw_output.lower():
        symbol_quality = "good"
    elif "symbol loading error summary" in raw_output.lower():
        symbol_quality = "missing"

    warnings: list[str] = []
    if "symbol loading error summary" in raw_output.lower():
        warnings.append("symbol_loading_errors_detected")
    if source_file == "unknown":
        warnings.append("source_line_unresolved")

    return {
        "dump_id": dump_id,
        "dump_type": dump_type,
        "project_type": project_type,
        "exception_code": exception_code,
        "exception_name": exception_name,
        "fault_type": _fault_type(exception_name),
        "fault_address": fault_address,
        "fault_module": fault_module,
        "fault_function": fault_function,
        "source_location": {"file": source_file, "line": source_line},
        "crashing_thread": thread_id,
        "stack_frames": stack_frames,
        "registers": {},
        "loaded_modules": loaded_modules,
        "symbol_quality": symbol_quality,
        "warnings": warnings,
        "suspected_patterns": [],
    }


def _run_cdb(*, dump_path: str, symbol_root: str, source_root: str, binary_root: str | None) -> str:
    fake_text = os.getenv("DUMP_SKILL_FAKE_OUTPUT")
    if fake_text:
        return fake_text
    fake_file = os.getenv("DUMP_SKILL_FAKE_OUTPUT_FILE")
    if fake_file:
        path = Path(fake_file)
        if not path.exists() or not path.is_file():
            raise SkillError("debugger_invocation_failed", "Fake output file not found.", {"path": str(path)})
        return path.read_text(encoding="utf-8")

    cdb_path = os.getenv("DUMP_SKILL_CDB_PATH") or os.getenv("DUMP_MCP_CDB_PATH") or "cdb.exe"
    timeout_value = (
        os.getenv("DUMP_SKILL_ANALYZE_TIMEOUT_SECONDS")
        or os.getenv("DUMP_MCP_ANALYZE_TIMEOUT_SECONDS")
        or "180"
    )
    try:
        timeout_seconds = int(timeout_value)
    except ValueError as exc:
        raise SkillError(
            "validation_error",
            "Analyze timeout must be an integer.",
            {"timeout_value": timeout_value},
        ) from exc
    if timeout_seconds <= 0:
        raise SkillError(
            "validation_error",
            "Analyze timeout must be positive.",
            {"timeout_seconds": timeout_seconds},
        )

    script_parts = [
        f'.sympath "{symbol_root}"',
        f'.srcpath "{source_root}"',
    ]
    if binary_root:
        script_parts.append(f'.exepath "{binary_root}"')
    script_parts.extend(
        [
            ".lines",
            "!analyze -v",
            ".ecxr",
            "kL 64",
            "lm",
            "q",
        ]
    )
    script = "; ".join(script_parts)

    try:
        completed = subprocess.run(
            [cdb_path, "-z", dump_path, "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except Exception as exc:
        raise SkillError(
            "debugger_invocation_failed",
            "Failed to invoke debugger.",
            {"exception": type(exc).__name__, "message": str(exc)},
        ) from exc

    output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
    if completed.returncode != 0 and not output.strip():
        raise SkillError(
            "debugger_invocation_failed",
            "Debugger exited with non-zero status.",
            {"return_code": completed.returncode},
        )
    return output


def _analyze_by_dump_id(session_file: str, dump_id: str) -> dict[str, Any]:
    session = _get_session(session_file, dump_id)
    raw_output = _run_cdb(
        dump_path=str(session["dump_path"]),
        symbol_root=str(session["symbol_root"]),
        source_root=str(session["source_root"]),
        binary_root=str(session.get("binary_root") or ""),
    )
    return _parse_analysis_output(
        raw_output,
        fallback_project_type=str(session["project_type"]),
        dump_id=dump_id,
    )


def _handle_register(args: argparse.Namespace) -> dict[str, Any]:
    session_file = str(args.session_file)
    session_path, data = _load_session_file(session_file)

    dump_path = _require_existing_file(args.dump_path, "dump_file_not_found", "dump_path")
    symbol_root = _require_existing_dir(args.symbol_root, "symbol_path_invalid", "symbol_root")
    source_root = _require_existing_dir(args.source_root, "source_root_invalid", "source_root")
    binary_root: str | None = None
    if args.binary_root:
        binary_root = _require_existing_dir(args.binary_root, "invalid_path", "binary_root")
    log_paths: list[str] = []
    for item in args.log_paths:
        log_paths.append(_require_existing_file(item, "invalid_path", "log_path"))

    if args.project_type not in {"native_cpp", "unreal_engine"}:
        raise SkillError(
            "validation_error",
            "project_type must be one of: native_cpp, unreal_engine.",
            {"project_type": args.project_type},
        )

    dump_id = _new_dump_id(data["sessions"])
    session = {
        "dump_id": dump_id,
        "dump_path": dump_path,
        "symbol_root": symbol_root,
        "source_root": source_root,
        "binary_root": binary_root,
        "project_type": args.project_type,
        "dump_type_hint": args.dump_type_hint,
        "log_paths": log_paths,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    data["sessions"].append(session)
    _write_json_file(session_path, data)

    return _ok(
        status="registered",
        dump_id=dump_id,
        session_file=str(session_path),
    )


def _handle_not_implemented(command: str) -> dict[str, Any]:
    return _ok(
        status="not_implemented",
        command=command,
        message="Command contract is defined; implementation follows next steps.",
    )


def _handle_analyze(args: argparse.Namespace) -> dict[str, Any]:
    session_file = str(args.session_file)
    dump_id = str(args.dump_id)
    result = _analyze_by_dump_id(session_file, dump_id)
    session = _get_session(session_file, dump_id)
    markdown = _render_markdown_report(
        analyzed=result,
        source_root=str(session["source_root"]),
        thread_id=int(result["crashing_thread"]),
        max_frames=30,
    )
    return _ok(
        **result,
        format="markdown",
        report_markdown=markdown,
    )


def _handle_exception(args: argparse.Namespace) -> dict[str, Any]:
    analyzed = _analyze_by_dump_id(str(args.session_file), str(args.dump_id))
    return _ok(
        dump_id=analyzed["dump_id"],
        exception_code=analyzed["exception_code"],
        exception_name=analyzed["exception_name"],
        fault_address=analyzed["fault_address"],
        fault_type=analyzed["fault_type"],
    )


def _handle_stack(args: argparse.Namespace) -> dict[str, Any]:
    max_frames = int(args.max_frames)
    if max_frames <= 0:
        raise SkillError("validation_error", "max_frames must be positive.", {"max_frames": max_frames})

    analyzed = _analyze_by_dump_id(str(args.session_file), str(args.dump_id))
    thread_id = int(args.thread_id) if args.thread_id is not None else int(analyzed["crashing_thread"])
    frames = analyzed["stack_frames"][:max_frames]
    return _ok(
        dump_id=analyzed["dump_id"],
        thread_id=thread_id,
        stack_frames=frames,
    )


def _handle_modules(args: argparse.Namespace) -> dict[str, Any]:
    analyzed = _analyze_by_dump_id(str(args.session_file), str(args.dump_id))
    return _ok(
        dump_id=analyzed["dump_id"],
        symbol_quality=analyzed["symbol_quality"],
        loaded_modules=analyzed["loaded_modules"],
    )


def _report_module_name(value: str) -> str:
    if not value or value == "unknown":
        return "-"
    return Path(value).stem


def _report_symbol_quality(analyzed: dict[str, Any]) -> str:
    raw = str(analyzed.get("symbol_quality", "missing")).lower()
    mapping = {
        "good": "Good",
        "partial": "Partial",
        "poor": "Poor",
        "missing": "Missing",
    }
    pretty = mapping.get(raw, raw.title() or "Unknown")
    if raw != "good":
        return pretty

    fault_module = _report_module_name(str(analyzed.get("fault_module", "")))
    if fault_module != "-":
        return f"{pretty} ({fault_module}.pdb 로드 성공)"

    loaded_modules = analyzed.get("loaded_modules") or []
    if isinstance(loaded_modules, list):
        for item in loaded_modules:
            module = _report_module_name(str(item.get("module", "")))
            if module != "-":
                return f"{pretty} ({module}.pdb 로드 성공)"

    return pretty


def _report_stack_rows(analyzed: dict[str, Any], max_frames: int) -> list[str]:
    rows: list[str] = []
    frames = analyzed.get("stack_frames") or []
    if not isinstance(frames, list):
        return rows

    fault_module = str(analyzed.get("fault_module", ""))
    fault_function = str(analyzed.get("fault_function", ""))
    for frame in frames[:max_frames]:
        index = int(frame.get("index", len(rows)))
        module = str(frame.get("module") or "")
        function = str(frame.get("function") or "")

        is_unknown = (not module or module == "unknown") and (not function or function == "unknown")
        if is_unknown and index == 0:
            rows.append("| 0 | - | *(크래시 발생 지점, 심볼 없음)* |")
            continue

        module_text = _report_module_name(module)
        if function and function != "unknown":
            function_text = f"`{function}`"
        else:
            function_text = "*(심볼 없음)*"

        is_fault = (
            module
            and function
            and module != "unknown"
            and function != "unknown"
            and module == fault_module
            and function == fault_function
        )
        if is_fault:
            module_text = f"**{module_text}**"
            function_text = f"**{function_text}**"

        rows.append(f"| {index} | {module_text} | {function_text} |")

    if not rows:
        rows.append("| 0 | - | *(스택 프레임 없음)* |")
    return rows


def _resolve_source_file_for_report(source_root: str, source_file: str) -> Path | None:
    if not source_file or source_file == "unknown":
        return None
    root = Path(source_root).resolve()

    try:
        strict = _resolve_source_file(source_root, source_file)
        if strict.exists() and strict.is_file():
            return strict
    except SkillError:
        pass

    raw = str(source_file).strip()
    if not raw:
        return None
    normalized = raw.replace("\\", "/").strip()
    without_drive = normalized.split(":", 1)[-1] if ":" in normalized[:3] else normalized
    relative_hint = without_drive.lstrip("/\\")

    if relative_hint:
        hinted = (root / Path(relative_hint)).resolve()
        if _is_inside_root(hinted, root) and hinted.exists() and hinted.is_file():
            return hinted

    filename = Path(relative_hint or normalized).name
    if not filename:
        return None

    matches = sorted(
        [p.resolve() for p in root.rglob(filename) if p.is_file()],
        key=lambda p: (len(p.parts), str(p).lower()),
    )
    if not matches:
        return None

    hint_parts = [part.lower() for part in Path(relative_hint).parts if part not in {"", "."}]
    if len(hint_parts) >= 2:
        suffix_matches = []
        for candidate in matches:
            tail = [part.lower() for part in candidate.parts[-len(hint_parts) :]]
            if tail == hint_parts:
                suffix_matches.append(candidate)
        if suffix_matches:
            matches = suffix_matches

    return matches[0]


def _report_source_snippet(source_root: str, source_file: str, focus_line: int) -> tuple[str, str, str]:
    if not source_file or source_file == "unknown" or focus_line <= 0:
        return "", "", ""
    target = _resolve_source_file_for_report(source_root, source_file)
    if target is None:
        return "", "", ""
    if not target.exists() or not target.is_file():
        return "", "", ""

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return "", "", str(target)
    if lines[0].startswith("\ufeff"):
        lines[0] = lines[0].lstrip("\ufeff")

    clamped = min(max(focus_line, 1), len(lines))
    start = max(1, clamped - 3)
    end = min(len(lines), clamped + 3)
    selected = lines[start - 1 : end]
    snippet = "\n".join(selected)
    source_line = lines[clamped - 1].strip()
    return snippet, source_line, str(target)


def _report_problem_location(source_file: str, source_line_no: int) -> str:
    if not source_file or source_file == "unknown" or source_line_no <= 0:
        return "확인 불가 (심볼/소스 매핑 실패)"
    path = Path(source_file)
    return f"`{path.name}:{source_line_no}` (`{source_file}`)"


def _report_extract_pointer_name(source_line: str) -> str:
    if not source_line:
        return "ptr"
    m = re.search(r"\*(\w+)", source_line)
    if m:
        return m.group(1)
    return "ptr"


def _report_root_cause(analyzed: dict[str, Any], source_line: str, source_snippet: str) -> tuple[str, str]:
    source_file = str(analyzed.get("source_location", {}).get("file", "unknown"))
    source_name = Path(source_file).name if source_file and source_file != "unknown" else "알 수 없는 소스"
    function = str(analyzed.get("fault_function", "unknown"))
    function_name = function if function and function != "unknown" else "알 수 없는 함수"
    line_text = source_line.strip()

    if str(analyzed.get("exception_name", "")) == "EXCEPTION_ACCESS_VIOLATION":
        lowered = line_text.lower()
        snippet_lowered = source_snippet.lower()
        if line_text and ("nullptr" in lowered or ("nullptr" in snippet_lowered and "*" in line_text)):
            summary = (
                f"{source_name}의 `{function_name}()` 함수에서 **NULL 포인터 역참조(Null Pointer Dereference)** 가 발생했습니다."
            )
            detail = (
                f"**`{line_text}` 코드에서 `nullptr` 상태 포인터를 역참조**하면서 접근 위반(`0xC0000005`)이 발생했습니다."
            )
            return summary, detail

        summary = f"{source_name}의 `{function_name}()` 함수에서 **잘못된 메모리 접근(Access Violation)** 이 발생했습니다."
        detail = "포인터 또는 주소 유효성 검증 없이 메모리에 접근하여 OS가 실행을 중단했습니다."
        return summary, detail

    summary = f"`{function_name}` 실행 중 **{analyzed.get('exception_name', 'UNKNOWN_EXCEPTION')}** 예외가 발생했습니다."
    detail = "예외 직전 프레임과 소스 라인을 기준으로 입력값/포인터/리소스 유효성을 점검해야 합니다."
    return summary, detail


def _report_fix_method(analyzed: dict[str, Any], source_line: str, source_snippet: str) -> str:
    if str(analyzed.get("exception_name", "")) == "EXCEPTION_ACCESS_VIOLATION":
        lowered = source_line.lower()
        snippet_lowered = source_snippet.lower()
        if source_line and ("nullptr" in lowered or ("nullptr" in snippet_lowered and "*" in source_line)):
            ptr_name = _report_extract_pointer_name(source_line)
            assign_match = _DEREF_ASSIGN_PATTERN.match(source_line.strip())
            if assign_match:
                ptr_name = assign_match.group("ptr")
                rhs = assign_match.group("rhs").strip()
                return (
                    "문제 라인을 기준으로 포인터 유효성 검사를 먼저 수행하도록 수정합니다.\n\n"
                    "```cpp\n"
                    f"if ({ptr_name} != nullptr) {{\n"
                    f"    *{ptr_name} = {rhs};\n"
                    "}\n"
                    "```"
                )

            return (
                "포인터를 역참조하기 전 반드시 유효성을 검사해야 합니다.\n\n"
                "```cpp\n"
                f"// {source_line}\n"
                f"    if ({ptr_name} != nullptr) {{\n"
                f"        *{ptr_name} = 42;\n"
                "    }\n"
                "```"
            )

        return (
            "접근 대상 주소가 유효한지 확인한 뒤에만 메모리에 접근해야 합니다.\n\n"
            "```cpp\n"
            "if (pointer != nullptr) {\n"
            "    *pointer = value;\n"
            "}\n"
            "```"
        )

    return "예외 재현 경로에서 입력값/객체 수명/스레드 경쟁 상태를 순서대로 검증하세요."


def _report_call_flow(analyzed: dict[str, Any], source_line: str) -> str:
    frames = analyzed.get("stack_frames") or []
    if not isinstance(frames, list) or not frames:
        return "호출 흐름 정보를 수집하지 못했습니다."

    selected = list(reversed(frames[: min(len(frames), 8)]))
    lines: list[str] = []
    for idx, frame in enumerate(selected):
        function = str(frame.get("function") or "")
        module = _report_module_name(str(frame.get("module") or ""))
        if function and function != "unknown":
            if module != "-":
                entry = f"{module}!{function}"
            else:
                entry = function
        else:
            entry = "(심볼 없음)"

        file = str(frame.get("file") or "")
        line_no = int(frame.get("line") or 0)
        if file and line_no > 0:
            entry = f"{entry}  [{Path(file).name}:{line_no}]"

        indent = "  " * idx
        prefix = "" if idx == 0 else "└─ "
        lines.append(f"{indent}{prefix}{entry}")

    if source_line:
        lines.append(f"{'  ' * len(selected)}└─ {source_line}  ← 예외 발생 지점")

    return "\n".join(lines)


def _render_markdown_report(
    *,
    analyzed: dict[str, Any],
    source_root: str,
    thread_id: int,
    max_frames: int,
) -> str:
    source_file = str(analyzed.get("source_location", {}).get("file", "unknown"))
    source_line_no = int(analyzed.get("source_location", {}).get("line", 0))
    source_snippet, source_line, resolved_source_file = _report_source_snippet(
        source_root, source_file, source_line_no
    )
    root_summary, root_detail = _report_root_cause(analyzed, source_line, source_snippet)

    stack_rows = _report_stack_rows(analyzed, max_frames=max_frames)
    call_flow = _report_call_flow(analyzed, source_line)
    fix_method = _report_fix_method(analyzed, source_line, source_snippet)
    problem_code_block = "- 문제 코드: 확인 불가"
    if source_line:
        problem_code_block = "\n".join(
            [
                "- 문제 코드:",
                "```cpp",
                source_line,
                "```",
            ]
        )

    context_code_block = ""
    if source_snippet:
        context_code_block = "\n".join(
            [
                "- 주변 코드:",
                "```cpp",
                source_snippet,
                "```",
            ]
        )

    template = _load_report_template_text()
    return _apply_report_template(
        template,
        {
            "THREAD_ID": str(thread_id),
            "EXCEPTION_CODE": str(analyzed.get("exception_code", "unknown")),
            "EXCEPTION_NAME": str(analyzed.get("exception_name", "UNKNOWN_EXCEPTION")),
            "FAULT_ADDRESS": str(analyzed.get("fault_address", "unknown")),
            "SYMBOL_QUALITY": _report_symbol_quality(analyzed),
            "STACK_ROWS": "\n".join(stack_rows),
            "ROOT_SUMMARY": root_summary,
            "PROBLEM_LOCATION": _report_problem_location(
                resolved_source_file if resolved_source_file else source_file,
                source_line_no,
            ),
            "PROBLEM_CODE_BLOCK": problem_code_block,
            "CONTEXT_CODE_BLOCK": context_code_block,
            "ROOT_DETAIL": root_detail,
            "CALL_FLOW": call_flow,
            "FIX_METHOD": fix_method,
        },
    )


def _handle_report(args: argparse.Namespace) -> dict[str, Any]:
    max_frames = int(args.max_frames)
    if max_frames <= 0:
        raise SkillError("validation_error", "max_frames must be positive.", {"max_frames": max_frames})

    analyzed = _analyze_by_dump_id(str(args.session_file), str(args.dump_id))
    session = _get_session(str(args.session_file), str(args.dump_id))
    thread_id = int(args.thread_id) if args.thread_id is not None else int(analyzed["crashing_thread"])

    markdown = _render_markdown_report(
        analyzed=analyzed,
        source_root=str(session["source_root"]),
        thread_id=thread_id,
        max_frames=max_frames,
    )
    return _ok(
        dump_id=analyzed["dump_id"],
        format="markdown",
        report_markdown=markdown,
    )


def _handle_source_context(args: argparse.Namespace) -> dict[str, Any]:
    frame_index = int(args.frame_index)
    context_before = int(args.context_before)
    context_after = int(args.context_after)
    if frame_index < 0:
        raise SkillError("invalid_request", "frame_index must be >= 0.", {"frame_index": frame_index})

    session = _get_session(str(args.session_file), str(args.dump_id))
    analyzed = _analyze_by_dump_id(str(args.session_file), str(args.dump_id))
    frames = analyzed["stack_frames"]
    if frame_index >= len(frames):
        raise SkillError(
            "invalid_request",
            "frame_index is out of range.",
            {"frame_index": frame_index, "stack_size": len(frames)},
        )

    frame = frames[frame_index]
    source_file = str(frame.get("file") or analyzed["source_location"]["file"])
    source_line = int(frame.get("line") or analyzed["source_location"]["line"] or 0)
    if not source_file or source_file == "unknown":
        raise SkillError(
            "source_mapping_failed",
            "No source file is mapped to requested frame.",
            {"dump_id": analyzed["dump_id"], "frame_index": frame_index},
        )

    payload = _get_source_context_payload(
        source_root=str(session["source_root"]),
        source_file=source_file,
        focus_line=source_line,
        context_before=context_before,
        context_after=context_after,
    )
    return _ok(dump_id=analyzed["dump_id"], frame_index=frame_index, **payload)


def _handle_search(args: argparse.Namespace) -> dict[str, Any]:
    query = str(args.query)
    max_results = int(args.max_results)
    ignore_case = bool(args.ignore_case)
    dump_id: str | None = str(args.dump_id) if args.dump_id else None

    if args.source_root:
        source_root = _require_existing_dir(str(args.source_root), "source_root_invalid", "source_root")
    elif dump_id:
        source_root = str(_get_session(str(args.session_file), dump_id)["source_root"])
    else:
        raise SkillError(
            "invalid_request",
            "search requires either 'source_root' or 'dump_id'.",
        )

    results = _search_code_references_payload(
        source_root=source_root,
        query=query,
        max_results=max_results,
        ignore_case=ignore_case,
    )
    return _ok(
        dump_id=dump_id,
        source_root=source_root,
        query=query,
        count=len(results),
        results=results,
    )


def _handle_patch(args: argparse.Namespace) -> dict[str, Any]:
    mode = str(args.mode).lower()
    if mode not in {"preview", "apply"}:
        raise SkillError("invalid_request", "mode must be either 'preview' or 'apply'.", {"mode": mode})
    if mode == "apply" and not bool(args.user_confirmed):
        raise SkillError(
            "policy_violation",
            "apply mode requires explicit user confirmation.",
            {"required_flag": "user_confirmed"},
        )

    source_root = _resolve_patch_source_root(args)
    root = Path(source_root).resolve()
    changes = _load_patch_changes(args)

    prepared: list[tuple[Path, str, str]] = []
    for change in changes:
        target = _resolve_patch_target(root, change["path"])
        old_text = ""
        if target.exists():
            if not target.is_file():
                raise SkillError("invalid_path", "Patch target must be a file path.", {"target": str(target)})
            old_text = target.read_text(encoding="utf-8", errors="replace")
        prepared.append((target, old_text, change["content"]))

    diff_chunks: list[str] = []
    modified_files: list[str] = []
    for target, old_text, new_text in prepared:
        if old_text == new_text:
            continue
        modified_files.append(str(target))
        from_name = f"a/{target.name}" if old_text else "/dev/null"
        to_name = f"b/{target.name}"
        diff_chunks.extend(
            unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=from_name,
                tofile=to_name,
            )
        )

    if mode == "apply":
        for target, _old_text, new_text in prepared:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(new_text, encoding="utf-8")

    return _ok(
        mode=mode,
        applied=(mode == "apply"),
        modified_files=modified_files,
        diff="".join(diff_chunks),
    )


def _handle_build(args: argparse.Namespace) -> dict[str, Any]:
    command = str(args.command)
    timeout_seconds = int(args.timeout_seconds) if args.timeout_seconds is not None else None
    dump_id = str(args.dump_id) if args.dump_id else None
    working_directory = (
        str(args.working_directory) if args.working_directory else None
    )
    resolved_wd = _resolve_working_directory(
        session_file=str(args.session_file),
        dump_id=dump_id,
        working_directory=working_directory,
    )
    return _run_guarded_command(
        tool_name="build_project",
        error_code="build_failed",
        command=command,
        user_confirmed=bool(args.user_confirmed),
        allowlist=_get_build_allowlist(),
        timeout_seconds=timeout_seconds,
        default_timeout=_get_default_timeout("build"),
        working_directory=resolved_wd,
    )


def _handle_test(args: argparse.Namespace) -> dict[str, Any]:
    command = str(args.command)
    timeout_seconds = int(args.timeout_seconds) if args.timeout_seconds is not None else None
    dump_id = str(args.dump_id) if args.dump_id else None
    working_directory = (
        str(args.working_directory) if args.working_directory else None
    )
    resolved_wd = _resolve_working_directory(
        session_file=str(args.session_file),
        dump_id=dump_id,
        working_directory=working_directory,
    )
    return _run_guarded_command(
        tool_name="run_tests",
        error_code="test_failed",
        command=command,
        user_confirmed=bool(args.user_confirmed),
        allowlist=_get_test_allowlist(),
        timeout_seconds=timeout_seconds,
        default_timeout=_get_default_timeout("test"),
        working_directory=resolved_wd,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DumpAnalysisSkill CLI (without MCP). Outputs exactly one JSON object.",
    )
    parser.add_argument(
        "--session-file",
        default=str(DEFAULT_SESSION_FILE),
        help="Absolute path of session store JSON file.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register", help="Register dump analysis session.")
    reg.add_argument("--dump-path", required=True)
    reg.add_argument("--symbol-root", required=True)
    reg.add_argument("--source-root", required=True)
    reg.add_argument("--project-type", required=True)
    reg.add_argument("--binary-root")
    reg.add_argument("--dump-type-hint", default="auto")
    reg.add_argument("--log-paths", nargs="*", default=[])
    reg.set_defaults(handler=_handle_register)

    analyze = sub.add_parser("analyze", help="Run dump analysis and return structured result.")
    analyze.add_argument("--dump-id", required=True)
    analyze.set_defaults(handler=_handle_analyze)

    ex = sub.add_parser("exception", help="Get exception summary for dump_id.")
    ex.add_argument("--dump-id", required=True)
    ex.set_defaults(handler=_handle_exception)

    stack = sub.add_parser("stack", help="Get stack frames for dump_id.")
    stack.add_argument("--dump-id", required=True)
    stack.add_argument("--max-frames", default=30, type=int)
    stack.add_argument("--thread-id", type=int)
    stack.set_defaults(handler=_handle_stack)

    modules = sub.add_parser("modules", help="Get module list and symbol quality for dump_id.")
    modules.add_argument("--dump-id", required=True)
    modules.set_defaults(handler=_handle_modules)

    report = sub.add_parser(
        "report",
        help="Render Korean markdown crash report for dump_id.",
    )
    report.add_argument("--dump-id", required=True)
    report.add_argument("--thread-id", type=int)
    report.add_argument("--max-frames", default=30, type=int)
    report.set_defaults(handler=_handle_report)

    source_context = sub.add_parser(
        "source-context",
        help="Get source context around a stack frame for dump_id.",
    )
    source_context.add_argument("--dump-id", required=True)
    source_context.add_argument("--frame-index", default=0, type=int)
    source_context.add_argument("--context-before", default=20, type=int)
    source_context.add_argument("--context-after", default=20, type=int)
    source_context.set_defaults(handler=_handle_source_context)

    search = sub.add_parser(
        "search",
        help="Search code references from source_root or dump session.",
    )
    search.add_argument("--query", required=True)
    search.add_argument("--dump-id")
    search.add_argument("--source-root")
    search.add_argument("--max-results", default=50, type=int)
    search.add_argument("--ignore-case", action="store_true")
    search.set_defaults(handler=_handle_search)

    patch = sub.add_parser(
        "patch",
        help="Preview or apply file content changes with explicit confirmation for apply mode.",
    )
    patch.add_argument("--dump-id")
    patch.add_argument("--source-root")
    patch.add_argument("--mode", default="preview", choices=["preview", "apply"])
    patch.add_argument("--user-confirmed", action="store_true")
    patch.add_argument("--changes-json")
    patch.add_argument("--changes-file")
    patch.set_defaults(handler=_handle_patch)

    build = sub.add_parser(
        "build",
        help="Run a guarded build command (allowlist/timeout/confirmation).",
    )
    build.add_argument("--command", required=True)
    build.add_argument("--dump-id")
    build.add_argument("--working-directory")
    build.add_argument("--timeout-seconds", type=int)
    build.add_argument("--user-confirmed", action="store_true")
    build.set_defaults(handler=_handle_build)

    test = sub.add_parser(
        "test",
        help="Run a guarded test command (allowlist/timeout/confirmation).",
    )
    test.add_argument("--command", required=True)
    test.add_argument("--dump-id")
    test.add_argument("--working-directory")
    test.add_argument("--timeout-seconds", type=int)
    test.add_argument("--user-confirmed", action="store_true")
    test.set_defaults(handler=_handle_test)

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        payload = args.handler(args)
    except SkillError as exc:
        return _emit(_err(exc.code, exc.message, exc.details))
    except ValueError as exc:
        return _emit(_err("validation_error", str(exc), {}))
    except Exception as exc:  # pragma: no cover
        return _emit(
            _err(
                "internal_error",
                "Unhandled error.",
                {"exception": type(exc).__name__, "message": str(exc)},
            )
        )

    return _emit(payload)


if __name__ == "__main__":
    raise SystemExit(main())
