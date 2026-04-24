"""Command line interface for PeachFuzz AI."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import load_corpus
from .guardrails import validate_target_name
from .targets import get_target, target_names
from .backends import BackendRunRequest, backend_matrix_json, backend_matrix_markdown, backend_names, get_backend
from .radar import to_json as radar_json, to_markdown as radar_markdown, strategic_thesis
from .roadmap import to_json as roadmap_json, to_markdown as roadmap_markdown
from .editions import edition_matrix_markdown
from .self_refine import SelfRefinementEngine


def run_deterministic(args: argparse.Namespace) -> int:
    target_name = validate_target_name(args.target)
    corpus = load_corpus(args.corpus) if args.corpus else [b"{}", b'{"endpoint":"/v1/ask"}']
    backend = get_backend(args.backend)
    request = BackendRunRequest(
        target_name=target_name,
        target=get_target(target_name),
        corpus=corpus,
        runs=args.runs,
        report_dir=args.report_dir,
        seed=args.seed,
    )
    outcome = backend.run(request)
    if outcome.result is not None:
        print(outcome.result.to_json())
    else:
        print(outcome.to_dict())
    return 1 if args.fail_on_crash and not outcome.ok else 0


def run_atheris(args: argparse.Namespace) -> int:
    target_name = validate_target_name(args.target)
    target = get_target(target_name)
    try:
        import atheris  # type: ignore
    except ImportError:
        print("atheris is not installed. Run: python -m pip install 'peachfuzz-ai[fuzz]'", file=sys.stderr)
        return 2

    def test_one_input(data: bytes) -> None:
        target(data)

    atheris.Setup(sys.argv[:1] + args.atheris_args + [str(p) for p in args.corpus], test_one_input)
    atheris.Fuzz()
    return 0


def run_refine(args: argparse.Namespace) -> int:
    engine = SelfRefinementEngine(report_dir=args.report_dir)
    output = engine.write_plan(args.output)
    print(f"Wrote Mythos Glasswing refinement plan: {output}")
    return 0


def run_editions(args: argparse.Namespace) -> int:
    print(edition_matrix_markdown())
    return 0


def run_backends(args: argparse.Namespace) -> int:
    if args.format == "json":
        import json
        print(json.dumps(backend_matrix_json(include_unsafe=args.include_unsafe), indent=2, sort_keys=True))
    else:
        print("# PeachFuzz/CactusFuzz Backend Matrix\n")
        print(backend_matrix_markdown(include_unsafe=args.include_unsafe))
    return 0


def run_radar(args: argparse.Namespace) -> int:
    if args.format == "json":
        print(radar_json())
    else:
        print("# PeachFuzz/CactusFuzz Competitive Radar\n")
        print(strategic_thesis())
        print()
        print(radar_markdown())
    return 0


def run_roadmap(args: argparse.Namespace) -> int:
    if args.format == "json":
        print(roadmap_json())
    else:
        print("# PeachFuzz/CactusFuzz Number-One Roadmap\n")
        print(roadmap_markdown())
    return 0


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="peachfuzz", description="PeachFuzz AI defensive fuzzing harness")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run deterministic fallback fuzzing")
    run.add_argument("--target", choices=target_names(), required=True)
    run.add_argument("--runs", type=int, default=1000)
    run.add_argument("--seed", type=int, default=1337)
    run.add_argument("--report-dir", default="reports")
    run.add_argument("--backend", choices=backend_names(), default="deterministic")
    run.add_argument("--fail-on-crash", action="store_true")
    run.add_argument("corpus", nargs="*", help="corpus files or directories")
    run.set_defaults(func=run_deterministic)

    ath = sub.add_parser("atheris", help="run atheris coverage-guided fuzzing")
    ath.add_argument("--target", choices=target_names(), required=True)
    ath.add_argument("corpus", nargs="*", type=Path)
    ath.add_argument("atheris_args", nargs=argparse.REMAINDER)
    ath.set_defaults(func=run_atheris)

    refine = sub.add_parser("refine", help="generate a Mythos Glasswing self-refinement proposal")
    refine.add_argument("--report-dir", default="reports")
    refine.add_argument("--output", default="MYTHOS_GLASSWING_PLAN.md")
    refine.set_defaults(func=run_refine)

    editions = sub.add_parser("editions", help="show PeachFuzz/CactusFuzz edition split")
    editions.set_defaults(func=run_editions)

    backends = sub.add_parser("backends", help="show fuzz backend safety matrix")
    backends.add_argument("--format", choices=["markdown", "json"], default="markdown")
    backends.add_argument("--include-unsafe", action="store_true", help="include disabled/sandbox-required backend stubs")
    backends.set_defaults(func=run_backends)

    radar = sub.add_parser("radar", help="show competitive radar")
    radar.add_argument("--format", choices=["markdown", "json"], default="markdown")
    radar.set_defaults(func=run_radar)

    roadmap = sub.add_parser("roadmap", help="show scored number-one roadmap")
    roadmap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    roadmap.set_defaults(func=run_roadmap)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
