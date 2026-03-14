# Troubleshooting

## `debugger_invocation_failed`

Checklist:
1. Verify `cdb.exe` exists and is executable.
2. Set explicit path:
```powershell
$env:DUMP_SKILL_CDB_PATH="C:\Path\To\cdb.exe"
```
3. Re-run `register` + `analyze`.

## `source_mapping_failed` from `source-context`

Checklist:
1. Confirm dump has source mapping and correct PDB.
2. Confirm `source_root` matches actual source tree.
3. Validate frame selection:
```bash
python scripts/dump_skill.py stack --dump-id <id> --max-frames 30
```
4. Retry with another `--frame-index`.

## `policy_violation` on build/test

Checklist:
1. Add `--user-confirmed`.
2. Remove shell chaining operators (`&&`, `|`, `;`).
3. Use allowlisted executable (e.g., `dotnet`, `msbuild`, `pytest`, `ctest`).

## Timeout errors (`build_failed` / `test_failed`)

Checklist:
1. Increase timeout:
```bash
python scripts/dump_skill.py test --command "<cmd>" --user-confirmed --timeout-seconds 1800
```
2. Check command independently in shell.
3. Narrow test scope to reproduce faster.

## Session issues

Symptoms:
- `dump_id ... does not exist`
- `invalid_session_store`

Checklist:
1. Use explicit `--session-file`.
2. Ensure session file is valid JSON and has `{"sessions":[...]}` shape.
3. Re-register dump if session file was deleted or corrupted.
