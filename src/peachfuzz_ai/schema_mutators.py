"""Schema-aware mutators for PeachFuzz/CactusFuzz.

These mutators generate local-only structured corpora for parsers, API schemas,
GraphQL documents, and webhook envelopes. They do not contact targets, execute
tools, or perform exploitation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from pathlib import Path
import random
import string
from typing import Any, Iterable


class SchemaKind(str, Enum):
    JSON_API = "json"
    OPENAPI = "openapi"
    GRAPHQL = "graphql"
    WEBHOOK = "webhook"


@dataclass(frozen=True)
class SchemaSeed:
    """A structured corpus seed."""

    name: str
    kind: SchemaKind
    payload: Any
    description: str
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_bytes(self) -> bytes:
        if self.kind == SchemaKind.GRAPHQL and isinstance(self.payload, str):
            return self.payload.encode("utf-8")
        return json.dumps(self.payload, sort_keys=True).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        return data


@dataclass(frozen=True)
class CorpusWriteResult:
    """Result of writing generated corpus files."""

    output_dir: str
    count: int
    files: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


class SchemaAwareMutator:
    """Deterministic structured mutator for API and agent safety surfaces."""

    def __init__(self, seed: int = 1337) -> None:
        self.random = random.Random(seed)

    def default_seeds(self, kind: SchemaKind | str | None = None) -> list[SchemaSeed]:
        """Return default seeds, optionally filtered by kind."""
        selected: list[SchemaSeed] = []
        kinds = [SchemaKind(kind)] if kind else list(SchemaKind)
        for item in kinds:
            if item == SchemaKind.JSON_API:
                selected.extend(self.json_api_seeds())
            elif item == SchemaKind.OPENAPI:
                selected.extend(self.openapi_seeds())
            elif item == SchemaKind.GRAPHQL:
                selected.extend(self.graphql_seeds())
            elif item == SchemaKind.WEBHOOK:
                selected.extend(self.webhook_seeds())
        return selected

    def json_api_seeds(self) -> list[SchemaSeed]:
        return [
            SchemaSeed(
                name="json_api_workflow_minimal",
                kind=SchemaKind.JSON_API,
                payload={"endpoint": "/v1/workflows", "body": {"workflow_type": "schema-fuzz", "target": "local-lab"}},
                description="Minimal local workflow API envelope.",
                tags=("api", "workflow", "valid"),
            ),
            SchemaSeed(
                name="json_api_nested_agent_message",
                kind=SchemaKind.JSON_API,
                payload={
                    "endpoint": "/v1/agent/messages",
                    "body": {
                        "messages": [
                            {"role": "system", "content": "Follow safety policy."},
                            {"role": "user", "content": "Summarize local fuzzing results."},
                        ],
                        "tools": [{"name": "report", "requires_approval": False}],
                    },
                },
                description="LLM-agent message envelope for parser regression.",
                tags=("api", "agent", "tools"),
            ),
        ]

    def openapi_seeds(self) -> list[SchemaSeed]:
        return [
            SchemaSeed(
                name="openapi_minimal_workflows",
                kind=SchemaKind.OPENAPI,
                payload={
                    "openapi": "3.1.0",
                    "info": {"title": "Local Lab API", "version": "0.1.0"},
                    "paths": {
                        "/v1/workflows": {
                            "post": {
                                "operationId": "createWorkflow",
                                "requestBody": {
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "type": "object",
                                                "required": ["workflow_type", "target"],
                                                "properties": {
                                                    "workflow_type": {"type": "string"},
                                                    "target": {"type": "string"},
                                                },
                                            }
                                        }
                                    }
                                },
                                "responses": {"200": {"description": "ok"}},
                            }
                        }
                    },
                },
                description="Minimal OpenAPI 3.1 local workflow schema.",
                tags=("openapi", "valid", "workflow"),
            )
        ]

    def graphql_seeds(self) -> list[SchemaSeed]:
        return [
            SchemaSeed(
                name="graphql_query_findings",
                kind=SchemaKind.GRAPHQL,
                payload="query Findings($limit: Int = 10) { findings(limit: $limit) { id severity title } }",
                description="Benign GraphQL query document.",
                tags=("graphql", "query"),
            ),
            SchemaSeed(
                name="graphql_introspection_shape",
                kind=SchemaKind.GRAPHQL,
                payload="{ __schema { queryType { name } mutationType { name } } }",
                description="Offline introspection-shaped document for parser handling.",
                tags=("graphql", "introspection", "offline"),
            ),
        ]

    def webhook_seeds(self) -> list[SchemaSeed]:
        return [
            SchemaSeed(
                name="webhook_guardrail_pass",
                kind=SchemaKind.WEBHOOK,
                payload={
                    "event": "guardrail.pack.completed",
                    "headers": {"x-peachfuzz-signature": "sha256=local-test", "content-type": "application/json"},
                    "body": {"target": "local-lab", "ok": True, "passed": 6, "failed": 0},
                },
                description="Webhook envelope for local report delivery parser.",
                tags=("webhook", "guardrail", "valid"),
            ),
            SchemaSeed(
                name="webhook_crash_summary",
                kind=SchemaKind.WEBHOOK,
                payload={
                    "event": "fuzz.crash.summary",
                    "headers": {"content-type": "application/json"},
                    "body": {"target": "json", "crashes": [], "iterations": 250},
                },
                description="Webhook envelope for local crash summary parser.",
                tags=("webhook", "report", "valid"),
            ),
        ]

    def mutate(self, seed: SchemaSeed, count: int = 8) -> list[SchemaSeed]:
        """Generate deterministic structured variants from one seed."""
        variants: list[SchemaSeed] = []
        for idx in range(max(0, count)):
            if seed.kind == SchemaKind.JSON_API:
                payload: Any = self._mutate_json_api(dict(seed.payload))
            elif seed.kind == SchemaKind.OPENAPI:
                payload = self._mutate_openapi(json.loads(json.dumps(seed.payload)))
            elif seed.kind == SchemaKind.GRAPHQL:
                payload = self._mutate_graphql(str(seed.payload))
            elif seed.kind == SchemaKind.WEBHOOK:
                payload = self._mutate_webhook(json.loads(json.dumps(seed.payload)))
            else:
                payload = seed.payload
            variants.append(
                SchemaSeed(
                    name=f"{seed.name}_mut_{idx:03d}",
                    kind=seed.kind,
                    payload=payload,
                    description=f"Schema-aware mutation of {seed.name}",
                    tags=seed.tags + ("mutated",),
                )
            )
        return variants

    def generate(self, kinds: Iterable[SchemaKind | str] | None = None, count_per_seed: int = 4) -> list[SchemaSeed]:
        """Generate default seeds plus mutations for selected kinds."""
        selected_kinds = [SchemaKind(k) for k in kinds] if kinds else list(SchemaKind)
        output: list[SchemaSeed] = []
        for kind in selected_kinds:
            for seed in self.default_seeds(kind):
                output.append(seed)
                output.extend(self.mutate(seed, count=count_per_seed))
        return output

    def write_corpus(
        self,
        output_dir: str | Path,
        kinds: Iterable[SchemaKind | str] | None = None,
        count_per_seed: int = 4,
    ) -> CorpusWriteResult:
        """Write generated corpus files grouped by kind."""
        root = Path(output_dir)
        root.mkdir(parents=True, exist_ok=True)
        files: list[str] = []
        for seed in self.generate(kinds=kinds, count_per_seed=count_per_seed):
            suffix = ".graphql" if seed.kind == SchemaKind.GRAPHQL else ".json"
            target_dir = root / seed.kind.value
            target_dir.mkdir(parents=True, exist_ok=True)
            safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in seed.name)
            path = target_dir / f"{safe_name}{suffix}"
            path.write_bytes(seed.to_bytes())
            files.append(str(path))
        return CorpusWriteResult(output_dir=str(root), count=len(files), files=tuple(files))

    def import_openapi_json(self, path: str | Path) -> list[SchemaSeed]:
        """Import a local OpenAPI JSON file as seeds.

        YAML is intentionally not parsed without an optional dependency. Convert
        YAML to JSON before importing, or add a safe YAML parser in a later PR.
        """
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("OpenAPI document must be a JSON object")
        if "openapi" not in data or "paths" not in data:
            raise ValueError("OpenAPI document must include 'openapi' and 'paths'")
        return [
            SchemaSeed(
                name=p.stem,
                kind=SchemaKind.OPENAPI,
                payload=data,
                description=f"Imported OpenAPI JSON document from {p.name}",
                tags=("openapi", "imported"),
            )
        ]

    def _mutate_json_api(self, payload: dict[str, Any]) -> dict[str, Any]:
        endpoint = payload.get("endpoint", "/v1/local")
        choices = [
            endpoint,
            f"{endpoint}/{{id}}",
            "/v1/" + self._word(),
            "/v1/agent/tools",
            "/v1/webhooks/local",
        ]
        payload["endpoint"] = self.random.choice(choices)
        body = payload.setdefault("body", {})
        if isinstance(body, dict):
            body[self._word()] = self.random.choice([True, False, 0, 1, "", "local-lab", ["alpha", "beta"]])
            body.setdefault("metadata", {})["mutation_id"] = self._word(8)
        return payload

    def _mutate_openapi(self, payload: dict[str, Any]) -> dict[str, Any]:
        paths = payload.setdefault("paths", {})
        new_path = "/" + self._word() + "/" + self.random.choice(["items", "findings", "webhooks"])
        paths[new_path] = {
            self.random.choice(["get", "post"]): {
                "operationId": self._word(10),
                "responses": {"200": {"description": "local ok"}},
            }
        }
        payload.setdefault("components", {}).setdefault("schemas", {})[self._word(8).title()] = {
            "type": "object",
            "properties": {self._word(): {"type": self.random.choice(["string", "integer", "boolean"])}},
        }
        return payload

    def _mutate_graphql(self, document: str) -> str:
        field = self.random.choice(["id", "severity", "title", "createdAt", "status"])
        typename = self.random.choice(["Finding", "Workflow", "GuardrailReport"])
        variants = [
            document,
            f"query {typename}List {{ {typename.lower()}s {{ {field} }} }}",
            f"fragment {typename}Fields on {typename} {{ id {field} }}",
            "{ __typename }",
        ]
        return self.random.choice(variants)

    def _mutate_webhook(self, payload: dict[str, Any]) -> dict[str, Any]:
        payload["event"] = self.random.choice([
            "fuzz.run.started",
            "fuzz.run.completed",
            "guardrail.pack.completed",
            "schema.corpus.generated",
        ])
        headers = payload.setdefault("headers", {})
        if isinstance(headers, dict):
            headers[self.random.choice(["x-request-id", "x-peachfuzz-event", "x-local-only"])] = self._word(12)
        body = payload.setdefault("body", {})
        if isinstance(body, dict):
            body["mutation_id"] = self._word(10)
            body["local_only"] = True
        return payload

    def _word(self, length: int = 6) -> str:
        return "".join(self.random.choice(string.ascii_lowercase) for _ in range(length))


def kind_names() -> list[str]:
    return [kind.value for kind in SchemaKind]


def parse_kinds(raw: Iterable[str] | None) -> list[SchemaKind]:
    if not raw or "all" in raw:
        return list(SchemaKind)
    return [SchemaKind(item) for item in raw]
