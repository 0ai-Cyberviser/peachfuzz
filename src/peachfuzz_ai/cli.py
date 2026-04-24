"""Command line interface for PeachFuzz AI."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import PeachFuzzEngine, load_corpus
from .guardrails import validate_target_name
from .targets import get_target, target_names


def run_deterministic(args: argparse.Namespace) -> int:
    target_name = validate_target_name(args.target)
    corpus = load_corpus(args.corpus) if args.corpus else [b"{}", b'{"endpoint":"/v1/ask"}']
    engine = PeachFuzzEngine(get_target(target_name), target_name, report_dir=args.report_dir, seed=args.seed)
    result = engine.run(corpus, runs=args.runs)
    print(result.to_json())
    return 1 if result.crashes and args.fail_on_crash else 0


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


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="peachfuzz", description="PeachFuzz AI defensive fuzzing harness")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run deterministic fallback fuzzing")
    run.add_argument("--target", choices=target_names(), required=True)
    run.add_argument("--runs", type=int, default=1000)
    run.add_argument("--seed", type=int, default=1337)
    run.add_argument("--report-dir", default="reports")
    run.add_argument("--fail-on-crash", action="store_true")
    run.add_argument("corpus", nargs="*", help="corpus files or directories")
    run.set_defaults(func=run_deterministic)

    ath = sub.add_parser("atheris", help="run atheris coverage-guided fuzzing")
    ath.add_argument("--target", choices=target_names(), required=True)
    ath.add_argument("corpus", nargs="*", type=Path)
    ath.add_argument("atheris_args", nargs=argparse.REMAINDER)
    ath.set_defaults(func=run_atheris)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
