---
name: dump-analysis-cdb
description: Analyze Windows crash dumps (`.dmp`) directly from Python scripts using WinDbg `cdb.exe` without MCP server dependency. Use when Codex must run local dump triage, extract exception/stack/module/source context, search source references, and optionally run guarded patch/build/test flows with explicit confirmation and command policy controls.
---

# Dump Analysis Cdb

## Overview

Use this skill to analyze Windows dump files without running an MCP server.
Execute the bundled CLI script, parse structured JSON output, and drive fix loops from the analysis result.

## Quick Start

Run from the skill folder:

```bash
python scripts/dump_skill.py register --dump-path <abs.dmp> --symbol-root <abs.symbols> --source-root <abs.source> --project-type native_cpp
python scripts/dump_skill.py analyze --dump-id <dump_id>
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
- `source-context`
- `search`
- `patch`
- `build`
- `test`

## Resources

- Script entrypoint: `scripts/dump_skill.py`
- CLI/output contract: `references/cli-contract.md`
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
