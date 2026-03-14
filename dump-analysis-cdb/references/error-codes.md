# Error Codes

Common error envelope:

```json
{
  "ok": false,
  "error": {
    "code": "<error_code>",
    "message": "<reason>",
    "details": {}
  }
}
```

## Codes

- `validation_error`
  - Invalid argument value or format.
  - Examples: relative path input, malformed JSON, non-positive timeout.

- `invalid_request`
  - Missing required argument combination.
  - Examples: `search` without `--dump-id` and `--source-root`, invalid `frame-index`.

- `invalid_path`
  - Path is invalid or outside allowed root.
  - Examples: patch path escape (`..\`), missing working directory.

- `dump_file_not_found`
  - `register` input dump file does not exist.

- `symbol_path_invalid`
  - `register` input symbol root does not exist.

- `source_root_invalid`
  - `register` or `search/patch` source root does not exist.

- `source_mapping_failed`
  - Source file/line cannot be resolved for requested frame.

- `invalid_session_store`
  - Session JSON file is malformed or has invalid structure.

- `invalid_request`
  - Requested `dump_id` not found in session file.

- `policy_violation`
  - Guard rule violated.
  - Examples: missing `--user-confirmed`, shell chaining command, non-allowlisted executable.

- `debugger_invocation_failed`
  - `cdb` execution failed before usable output.

- `build_failed`
  - Guarded build command timed out, crashed, or returned non-zero exit code.

- `test_failed`
  - Guarded test command timed out, crashed, or returned non-zero exit code.

- `internal_error`
  - Unexpected unhandled exception.
