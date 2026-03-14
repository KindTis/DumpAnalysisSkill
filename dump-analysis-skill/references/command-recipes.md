# Command Recipes

## 1) Register and Analyze

```bash
python scripts/dump_skill.py register \
  --dump-path "C:\work\crash\sample.dmp" \
  --symbol-root "C:\work\symbols" \
  --source-root "C:\work\src" \
  --project-type native_cpp
```

Use returned `dump_id`:

```bash
python scripts/dump_skill.py analyze --dump-id crash-20260315-120000-001
python scripts/dump_skill.py exception --dump-id crash-20260315-120000-001
python scripts/dump_skill.py stack --dump-id crash-20260315-120000-001 --max-frames 20
python scripts/dump_skill.py modules --dump-id crash-20260315-120000-001
```

## 2) Source Context and Search

```bash
python scripts/dump_skill.py source-context \
  --dump-id crash-20260315-120000-001 \
  --frame-index 0 \
  --context-before 20 \
  --context-after 20
```

```bash
python scripts/dump_skill.py search \
  --dump-id crash-20260315-120000-001 \
  --query "InventoryComponent::UseItem" \
  --max-results 50 \
  --ignore-case
```

## 3) Patch (Preview then Apply)

Inline JSON:

```bash
python scripts/dump_skill.py patch \
  --source-root "C:\work\src" \
  --mode preview \
  --changes-json "[{\"path\":\"InventoryComponent.cpp\",\"content\":\"int x=1;\\n\"}]"
```

From file:

```bash
python scripts/dump_skill.py patch \
  --source-root "C:\work\src" \
  --mode apply \
  --user-confirmed \
  --changes-file "C:\work\changes.json"
```

`changes.json` format:

```json
[
  {
    "path": "relative/or/absolute/path.cpp",
    "content": "new full file content\n"
  }
]
```

## 4) Build/Test (Guarded)

```bash
python scripts/dump_skill.py build \
  --command "dotnet build Airi.sln -c Debug" \
  --working-directory "C:\work\repo" \
  --user-confirmed
```

```bash
python scripts/dump_skill.py test \
  --command "dotnet test tests/Airi.Tests/Airi.Tests.csproj -c Debug" \
  --working-directory "C:\work\repo" \
  --timeout-seconds 900 \
  --user-confirmed
```

## 5) Session Store

Default session file:
- `dump-analysis-skill/.dump-sessions.json`

Override:

```bash
python scripts/dump_skill.py --session-file "C:\work\sessions.json" analyze --dump-id <id>
```

