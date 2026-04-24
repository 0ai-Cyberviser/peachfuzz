"""CLI for CactusFuzz."""
from __future__ import annotations

import argparse
from pathlib import Path

from .agent import CactusFuzzAgent
from .guardrail_pack import GuardrailOracle
from .scope import AuthorizationScope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cactusfuzz", description="Authorized adversarial fuzzing edition")
    parser.add_argument("--target", default="local-lab", help="owned/lab target identifier")
    parser.add_argument("--scope", action="append", default=["local-lab"], help="authorized target/scope; repeatable")
    parser.add_argument("--operator", default="local-operator")
    parser.add_argument("--pack", choices=["default", "agent-guardrails"], default="default")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--output", help="optional output file for report")
    args = parser.parse_args(argv)

    scope = AuthorizationScope(targets=tuple(args.scope), operator=args.operator)
    agent = CactusFuzzAgent(scope)

    if args.pack == "agent-guardrails":
        report = GuardrailOracle(agent).run_pack(target=args.target)
        output = report.to_markdown() if args.format == "markdown" else report.to_json()
        if args.output:
            Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(output)
        return 0 if report.ok else 1

    findings = agent.run_cases(agent.default_cases(), target=args.target)
    output = agent.to_json(findings)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
