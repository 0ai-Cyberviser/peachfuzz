"""CLI for CactusFuzz."""
from __future__ import annotations

import argparse

from .agent import CactusFuzzAgent
from .scope import AuthorizationScope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cactusfuzz", description="Authorized adversarial fuzzing edition")
    parser.add_argument("--target", default="local-lab", help="owned/lab target identifier")
    parser.add_argument("--scope", action="append", default=["local-lab"], help="authorized target/scope; repeatable")
    parser.add_argument("--operator", default="local-operator")
    args = parser.parse_args(argv)

    scope = AuthorizationScope(targets=tuple(args.scope), operator=args.operator)
    agent = CactusFuzzAgent(scope)
    findings = agent.run_cases(agent.default_cases(), target=args.target)
    print(agent.to_json(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
