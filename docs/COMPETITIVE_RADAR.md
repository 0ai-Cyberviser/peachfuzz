# PeachFuzz/CactusFuzz Competitive Radar

This radar summarizes public GitHub discovery performed during the v0.4.0 refinement pass.

Live web and GitLab scraping were not available in the build environment, so this document is a curated GitHub-based radar rather than a claim of complete internet coverage.

## Strategic thesis

PeachFuzz/CactusFuzz should not try to replace AFL++, LibAFL, Atheris, OSS-Fuzz, Hypothesis, boofuzz, or API-specific fuzzers. It should become the safest **AI-agent-aware fuzzing control plane** that can orchestrate or complement those ecosystems.

## Why this can win

1. **Two-edition clarity**
   - PeachFuzz: blue-team, local, defensive.
   - CactusFuzz: authorized red-team, scoped, simulation-first.

2. **AI-agent fuzzing is the wedge**
   - Tool routing.
   - Approval gates.
   - Prompt-injection resistance.
   - Unsafe tool-call regression.
   - Evidence-first reports.

3. **Backend-agnostic design**
   - Atheris now.
   - Deterministic fallback always.
   - AFL++/LibAFL/OSS-Fuzz/ClusterFuzzLite adapters later.

4. **Polished self-refinement**
   - Crashes become advisories.
   - Advisories become reviewable PR plans.
   - CI artifacts make maintainers trust the tool.

## Discovered GitHub families

Run locally:

```bash
peachfuzz radar
peachfuzz roadmap
```

## Immediate v0.4.x priorities

- Backend adapter interface.
- Agent guardrail fuzzing pack.
- Schema-aware JSON/OpenAPI/GraphQL mutators.
- Crash minimizer + pytest reproducer generator.
- OSS-Fuzz/ClusterFuzzLite generator.
- Evidence-first CactusFuzz report mode.
