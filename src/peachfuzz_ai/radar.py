"""Competitive radar for PeachFuzz/CactusFuzz.

This module records a curated, reviewable competitive landscape derived from
public GitHub discovery. It is intentionally static/offline in runtime code so
CI does not scrape third-party systems or depend on live network access.

The goal is not to clone existing fuzzers. The goal is to identify integration
targets and product gaps PeachFuzz/CactusFuzz can own:
- AI-agent-aware guardrail fuzzing
- safe red/blue edition split
- self-refinement proposals
- CI-first crash triage
- corpus intelligence and adapter strategy
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import json
from typing import Iterable


class RadarCategory(str, Enum):
    COVERAGE_GUIDED = "coverage-guided"
    FRAMEWORK = "framework"
    PYTHON = "python"
    PROTOCOL = "protocol"
    AI_AGENT = "ai-agent"
    API_GRAPHQL = "api-graphql"
    PROPERTY_BASED = "property-based"
    CONTINUOUS_FUZZING = "continuous-fuzzing"


@dataclass(frozen=True)
class RadarProject:
    """One competitive/open-source project family."""

    name: str
    url: str
    category: RadarCategory
    signal: str
    peachfuzz_takeaway: str
    recommended_action: str
    priority: int  # 1 highest, 5 lowest

    def to_dict(self) -> dict:
        data = asdict(self)
        data["category"] = self.category.value
        return data


RADAR_PROJECTS: tuple[RadarProject, ...] = (
    RadarProject(
        name="AFL++",
        url="https://github.com/AFLplusplus/AFLplusplus",
        category=RadarCategory.COVERAGE_GUIDED,
        signal="Mature coverage-guided native fuzzing ecosystem.",
        peachfuzz_takeaway="Do not compete head-on; integrate as an optional backend for native targets.",
        recommended_action="Add adapter spec for invoking AFL++ only inside explicit local/sandbox workflows.",
        priority=2,
    ),
    RadarProject(
        name="LibAFL",
        url="https://github.com/AFLplusplus/LibAFL",
        category=RadarCategory.FRAMEWORK,
        signal="Composable fuzzing library for custom engines and advanced schedulers.",
        peachfuzz_takeaway="Borrow the idea of modular stages/schedulers for Python-side corpus intelligence.",
        recommended_action="Design a backend interface: mutator, scheduler, executor, triager, reporter.",
        priority=1,
    ),
    RadarProject(
        name="AFL++ Grammar-Mutator",
        url="https://github.com/AFLplusplus/Grammar-Mutator",
        category=RadarCategory.FRAMEWORK,
        signal="Grammar-aware generation for structured inputs.",
        peachfuzz_takeaway="PeachFuzz should support JSON/OpenAPI/GraphQL grammar-aware mutators.",
        recommended_action="Create grammar mutator interfaces for API schemas and LLM-agent message envelopes.",
        priority=1,
    ),
    RadarProject(
        name="OSS-Fuzz ecosystem",
        url="https://github.com/google/oss-fuzz",
        category=RadarCategory.CONTINUOUS_FUZZING,
        signal="Continuous fuzzing standard for open-source projects.",
        peachfuzz_takeaway="Win by making OSS-Fuzz/ClusterFuzzLite onboarding effortless for Python/agent projects.",
        recommended_action="Ship templates, project.yaml generators, reproducible crash artifact layout.",
        priority=1,
    ),
    RadarProject(
        name="Atheris",
        url="https://github.com/google/atheris",
        category=RadarCategory.PYTHON,
        signal="Coverage-guided Python fuzzing engine.",
        peachfuzz_takeaway="Keep Atheris as first-class Python backend while preserving deterministic fallback.",
        recommended_action="Add backend selection and standardized harness template generation.",
        priority=1,
    ),
    RadarProject(
        name="boofuzz-style protocol fuzzing",
        url="https://github.com/jtpereyda/boofuzz",
        category=RadarCategory.PROTOCOL,
        signal="Protocol/session fuzzing pattern for network services.",
        peachfuzz_takeaway="CactusFuzz can support protocol modeling only for explicit lab scopes and simulations.",
        recommended_action="Add offline protocol model format before any network-capable executor exists.",
        priority=3,
    ),
    RadarProject(
        name="Hypothesis",
        url="https://github.com/HypothesisWorks/hypothesis",
        category=RadarCategory.PROPERTY_BASED,
        signal="Property-based testing and shrinking.",
        peachfuzz_takeaway="Add property-based test generation and minimization concepts for crash reduction.",
        recommended_action="Add optional Hypothesis strategy exporter for schemas and agent states.",
        priority=2,
    ),
    RadarProject(
        name="ToolFuzz",
        url="https://github.com/eth-sri/ToolFuzz",
        category=RadarCategory.AI_AGENT,
        signal="AI-agent/tool-use fuzzing research direction.",
        peachfuzz_takeaway="This is the strategic lane: agent tool-call guardrail fuzzing and policy regression.",
        recommended_action="Prioritize agent message corpus, unsafe-tool routing tests, and approval-gate scoring.",
        priority=1,
    ),
    RadarProject(
        name="AgentProbe",
        url="https://github.com/tomerhakak/agentprobe",
        category=RadarCategory.AI_AGENT,
        signal="Agent probing/failure discovery direction.",
        peachfuzz_takeaway="CactusFuzz should become the practical red-team side for authorized AI-agent probes.",
        recommended_action="Add adversarial scenario packs and evidence-first reporting.",
        priority=1,
    ),
    RadarProject(
        name="EvoMaster",
        url="https://github.com/WebFuzzing/EvoMaster",
        category=RadarCategory.API_GRAPHQL,
        signal="Automated API/system test generation.",
        peachfuzz_takeaway="PeachFuzz should not clone a JVM API fuzzer; instead own lightweight Python CI + agent API schemas.",
        recommended_action="Add OpenAPI/GraphQL seed import and local mutation profiles.",
        priority=2,
    ),
    RadarProject(
        name="GraphQLer / GraphQL fuzzing family",
        url="https://github.com/omar2535/GraphQLer",
        category=RadarCategory.API_GRAPHQL,
        signal="GraphQL-specific attack surface and query generation.",
        peachfuzz_takeaway="GraphQL should be a named PeachFuzz defensive target and CactusFuzz authorized scenario pack.",
        recommended_action="Add GraphQL document corpus and introspection-response parser fuzzing.",
        priority=2,
    ),
)


def projects(category: str | None = None) -> list[RadarProject]:
    """Return radar projects, optionally filtered by category."""
    if category is None:
        return list(RADAR_PROJECTS)
    return [p for p in RADAR_PROJECTS if p.category.value == category]


def top_priorities(limit: int = 5) -> list[RadarProject]:
    """Return highest-priority differentiators."""
    return sorted(RADAR_PROJECTS, key=lambda p: (p.priority, p.name.lower()))[:limit]


def to_json(items: Iterable[RadarProject] | None = None) -> str:
    selected = list(items if items is not None else RADAR_PROJECTS)
    return json.dumps([p.to_dict() for p in selected], indent=2, sort_keys=True)


def to_markdown(items: Iterable[RadarProject] | None = None) -> str:
    selected = list(items if items is not None else RADAR_PROJECTS)
    rows = [
        "| Priority | Project | Category | Signal | PeachFuzz/CactusFuzz move |",
        "|---:|---|---|---|---|",
    ]
    for p in sorted(selected, key=lambda item: (item.priority, item.name.lower())):
        rows.append(
            f"| {p.priority} | [{p.name}]({p.url}) | {p.category.value} | "
            f"{p.signal} | {p.recommended_action} |"
        )
    return "\n".join(rows)


def strategic_thesis() -> str:
    """The product thesis for becoming a top fuzzing tool."""
    return (
        "PeachFuzz/CactusFuzz should win by becoming the safest AI-agent-aware fuzzing "
        "control plane: defensive PeachFuzz for blue teams, authorized CactusFuzz for "
        "red teams, pluggable backend adapters for established fuzzers, and polished "
        "self-refinement reports that convert crashes into reviewable PRs."
    )
