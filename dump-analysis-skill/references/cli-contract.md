# CLI Contract

## Entry
- Script: `scripts/dump_skill.py`
- Invocation: `python scripts/dump_skill.py <command> [options]`
- Output: exactly one JSON object to stdout.
- Report rendering template: default `references/report-template.md`
- Report template override env: `DUMP_SKILL_REPORT_TEMPLATE_FILE=<abs.md>`

## Common Output Shape
- Success:
```json
{
  "ok": true
}
```
- Error:
```json
{
  "ok": false,
  "error": {
    "code": "validation_error",
    "message": "human readable reason",
    "details": {}
  }
}
```

## Commands
- Implemented in Step 1:
  - `register --dump-path --symbol-root --source-root --project-type [--binary-root] [--dump-type-hint] [--log-paths ...]`
  - `analyze --dump-id` (includes `report_markdown` for default user-facing report)
  - `exception --dump-id`
  - `stack --dump-id [--max-frames] [--thread-id]`
  - `modules --dump-id`
- Implemented in Step 2:
  - `source-context --dump-id [--frame-index] [--context-before] [--context-after]`
  - `search --query [--dump-id|--source-root] [--max-results] [--ignore-case]`
- Implemented in Step 3:
  - `patch --dump-id|--source-root --mode preview|apply [--user-confirmed] --changes-json|--changes-file`
  - `build --command [--dump-id] [--working-directory] [--timeout-seconds] --user-confirmed`
  - `test --command [--dump-id] [--working-directory] [--timeout-seconds] --user-confirmed`
- Implemented in Step 4:
  - `report --dump-id [--thread-id] [--max-frames]`

## Step Status
- Step 0: command names and JSON contract defined.
- Step 1: register/analyze/exception/stack/modules implemented.
- Step 2: source-context/search implemented.
- Step 3: patch/build/test guard logic implemented.
- Step 4: Korean markdown report renderer implemented (`report`).
