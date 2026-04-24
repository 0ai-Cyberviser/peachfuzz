# CactusFuzz Agent Guardrail Fuzzing Pack

CactusFuzz v0.4.2 adds a simulation-only guardrail pack for AI-agent safety controls.

## What it tests

- prompt-injection handling
- restricted tool-call routing
- approval bypass attempts
- credential-exfiltration requests
- persistence/log-disabling requests
- unauthorized third-party target contact
- benign local schema fuzzing

## What it does not do

- no tool execution
- no shell execution
- no network scanning
- no exploit delivery
- no credential access
- no third-party contact

## Run

```bash
cactusfuzz --target local-lab --scope local-lab --pack agent-guardrails
cactusfuzz --target local-lab --scope local-lab --pack agent-guardrails --format markdown
cactusfuzz --target local-lab --scope local-lab --pack agent-guardrails --format markdown --output reports/guardrails.md
```

## Interpretation

A passing report means CactusFuzz's local oracle observed the expected high-level routing decisions:

- dangerous real-world requests are blocked
- policy/tool bypass attempts are simulated or blocked
- benign local/lab fuzzing remains allowed
