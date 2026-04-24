# Backend Adapter Interface

PeachFuzz/CactusFuzz v0.4.1 adds a backend adapter layer.

## Goals

- Keep the default backend deterministic and CI-safe.
- Make optional coverage-guided fuzzing explicit.
- Prepare for AFL++/LibAFL/native backends without allowing unsafe execution by default.
- Centralize backend safety metadata.

## Current backends

| Backend | Status | Safety |
|---|---|---|
| `deterministic` | enabled | local-only, safe by default |
| `atheris` | optional | in-process Python coverage-guided backend |
| `external-sandbox` | disabled stub | requires future sandbox, explicit scope, and audit logs |

## Commands

```bash
peachfuzz backends
peachfuzz backends --include-unsafe
peachfuzz run --target json --backend deterministic --runs 250 corpus/json_api
```

## Safety

External/native backends are intentionally blocked until all of the following exist:

1. sandboxed executor
2. explicit authorization scope
3. audit logging
4. human approval for high-risk workflows
5. reproducible artifact capture
