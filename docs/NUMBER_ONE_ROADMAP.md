# Number-One Roadmap

Goal: make PeachFuzz/CactusFuzz the most useful safe fuzzing harness for modern AI-agent, API, and security-team workflows.

## Positioning

PeachFuzz/CactusFuzz wins by being:

- easier than AFL++ for Python/API/agent teams
- safer than ad-hoc red-team scripts
- more AI-agent-aware than traditional fuzzers
- more actionable than raw crash output
- CI-native from day one

## v0.4.0: Competitive radar

- Add `peachfuzz radar`
- Add `peachfuzz roadmap`
- Document market position and priorities

## v0.4.1: Backend adapters

- `BackendAdapter` protocol
- deterministic backend
- Atheris backend
- external-command backend stub that is disabled unless sandboxed

## v0.4.2: Agent guardrail corpus

- prompt-injection pack
- unsafe tool-call pack
- policy bypass pack
- CactusFuzz report output

## v0.4.3: Schema mutators

- JSON schema profile
- OpenAPI seed importer
- GraphQL document mutator

## v0.4.4: Crash minimization

- delta reducer
- pytest reproducer generator
- crash dedupe database

## v0.5.0: CI dominance

- OSS-Fuzz/ClusterFuzzLite generator
- GitHub Actions templates
- artifact dashboard
- badge-ready reports
