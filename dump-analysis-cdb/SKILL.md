---
name: dump-analysis-cdb
description: Analyze Windows crash dumps (`.dmp`) directly from Python scripts using WinDbg `cdb.exe` without MCP server dependency. Use when Codex must run local dump triage, extract exception/stack/module/source context, search source references, and optionally run guarded patch/build/test flows with explicit confirmation and command policy controls.
---

# Dump Analysis Cdb

## Overview

Use this skill to analyze Windows dump files without running an MCP server.
Execute the bundled CLI script, parse structured JSON output, and drive fix loops from the analysis result.

## Workflow

1. Validate prerequisites before analysis.
- Confirm Windows environment and `cdb.exe` availability.
- Prefer absolute paths for `dump_path`, `symbol_root`, and `source_root`.

2. Register dump session.
- Run `python scripts/dump_skill.py register ...`.
- Capture `dump_id` from JSON response.

3. Run crash analysis.
- Run `python scripts/dump_skill.py analyze --dump-id <id>`.
- Use `exception`, `stack`, `modules`, `source-context`, `search` for focused queries.

4. Apply optional remediation commands only with explicit confirmation.
- Use `patch --mode apply --user-confirmed`.
- Use `build --user-confirmed` and `test --user-confirmed`.
- Reject commands that violate policy (non-allowlisted executable, shell chaining).

5. Interpret results from one JSON object per execution.
- Success shape: `{ "ok": true, ... }`
- Error shape: `{ "ok": false, "error": { "code", "message", "details" } }`

## Script Usage

Use the bundled script:

```bash
python scripts/dump_skill.py <command> [options]
```

Supported commands:
- `register`
- `analyze`
- `exception`
- `stack`
- `modules`
- `source-context`
- `search`
- `patch`
- `build`
- `test`

## Resources

- Script entrypoint: `scripts/dump_skill.py`
- CLI/output contract: `references/cli-contract.md`
- Policy and safety rules: `references/safety-policy.md`

Load references only when needed.
- Need exact JSON fields or command argument names: read `references/cli-contract.md`.
- Need guard behavior for patch/build/test: read `references/safety-policy.md`.

Do not start MCP server for this workflow.
