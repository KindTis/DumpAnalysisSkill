# CLI Contract

## Entry
- Script: `scripts/dump_skill.py`
- Invocation: `python scripts/dump_skill.py <command> [options]`
- Output: exactly one JSON object to stdout.

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
  - `analyze --dump-id`
  - `exception --dump-id`
  - `stack --dump-id [--max-frames] [--thread-id]`
  - `modules --dump-id`
- Planned for next steps:
  - `source-context`
  - `search`
  - `patch`
  - `build`
  - `test`

## Step Status
- Step 0: command names and JSON contract defined.
- Step 1: register/analyze/exception/stack/modules implemented.
