---
name: dump-analysis-skill
description: Analyze Windows crash dumps (`.dmp`) directly from Python scripts using WinDbg `cdb.exe` without MCP server dependency. Use when Codex must run local dump triage, extract exception/stack/module/source context, search source references, and optionally run guarded patch/build/test flows with explicit confirmation and command policy controls.
---

# Dump Analysis Skill

## Overview

Use this skill to analyze Windows dump files without running an MCP server.
Execute the bundled CLI script, parse structured JSON output, and drive fix loops from the analysis result.

## Quick Start

Run from the skill folder:

```bash
python scripts/dump_skill.py register --dump-path <abs.dmp> --symbol-root <abs.symbols> --source-root <abs.source> --project-type native_cpp
python scripts/dump_skill.py analyze --dump-id <dump_id>
python scripts/dump_skill.py report --dump-id <dump_id>
python scripts/dump_skill.py source-context --dump-id <dump_id> --frame-index 0
```

Use the JSON result as the only machine-readable interface.

## Workflow

1. Validate prerequisites.
- Confirm Windows and `cdb.exe` availability.
- Use absolute paths for input files/directories.

2. Register dump session.
- Run `register`.
- Capture `dump_id`.

3. Analyze and inspect.
- Run `analyze`.
- For user-facing output, **MUST** use `analyze` response field `report_markdown` as the final answer body.
- **DO NOT** replace `report_markdown` with a free-form summary unless the user explicitly asks for a summary.
- If `report_markdown` is missing for any reason, run `report --dump-id <dump_id>` and use its `report_markdown`.
- Narrow scope with `exception`, `stack`, `modules`.
- Read code around crash frames with `source-context`.
- Search related references with `search`.

4. Apply optional remediation.
- Use `patch --mode preview` first.
- Use `patch --mode apply --user-confirmed` for actual write.
- Use `build`/`test` only with `--user-confirmed`.

5. Iterate.
- Re-run `analyze` after modifications.
- Keep command outputs as evidence for tests and review.

## Commands

Use entrypoint:

```bash
python scripts/dump_skill.py <command> [options]
```

Implemented commands:
- `register`
- `analyze`
- `exception`
- `stack`
- `modules`
- `report`
- `source-context`
- `search`
- `patch`
- `build`
- `test`

## Resources

- Script entrypoint: `scripts/dump_skill.py`
- CLI/output contract: `references/cli-contract.md`
- Report template: `references/report-template.md`
- Policy and safety rules: `references/safety-policy.md`
- Command examples: `references/command-recipes.md`
- Error code index: `references/error-codes.md`
- Troubleshooting guide: `references/troubleshooting.md`

Load references only when needed.
- Need exact JSON fields or command argument names: read `references/cli-contract.md`.
- Need guard behavior for patch/build/test: read `references/safety-policy.md`.
- Need copy-paste command examples: read `references/command-recipes.md`.
- Need error triage mapping: read `references/error-codes.md`.
- Need environment/debug recovery steps: read `references/troubleshooting.md`.

Do not start MCP server for this workflow.

## Response Policy (Strict)

- When user intent is "analyze dump" (e.g., `aa.dmp 크래시 덤프 분석`), final response **MUST** render `report_markdown` directly.
- Final response **MUST NOT** be a prose-only narrative replacing the report sections.
- Additional bullets/recommendations are allowed only after the full report body, and only when user asks for next steps.

