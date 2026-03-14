# Safety Policy

## Goals
- Prevent unintended file modification or command execution.
- Keep behavior predictable across local environments.

## Required Guards
- Use absolute paths for dump/symbol/source/binary inputs.
- Require explicit confirmation for mutation actions:
  - `patch --mode apply --user-confirmed`
  - `build --user-confirmed`
  - `test --user-confirmed`
- For build/test commands:
  - Allow only allowlisted executables.
  - Reject shell chaining operators (`&&`, `|`, `;`).
  - Enforce timeout and output length limits.

## Error Reporting
- Return policy violations as:
  - `ok=false`
  - `error.code=policy_violation`
  - details with rejected command and reason
