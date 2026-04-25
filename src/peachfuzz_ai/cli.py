from __future__ import annotations
from .peachtree_import import PeachTreeSeedImporter
"""Command line interface for PeachFuzz AI."""

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
from .schema_mutators import SchemaAwareMutator, kind_names, parse_kinds
from .minimizer import CrashSignature, DeltaMinimizer, MinimizeRequest, write_minimized_result
from .reproducer import ReproducerRequest, write_pytest_reproducer


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


def run_peachtrace(args: argparse.Namespace) -> int:
    args.backend = "peachtrace"
    return run_deterministic(args)


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


def run_schemas(args: argparse.Namespace) -> int:
    mutator = SchemaAwareMutator(seed=args.seed)
    kinds = parse_kinds(args.kind)
    if args.import_openapi:
        seeds = mutator.import_openapi_json(args.import_openapi)
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        files = []
        for seed in seeds:
            path = output_dir / "openapi" / f"{seed.name}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(seed.to_bytes())
            files.append(str(path))
        import json
        print(json.dumps({"output_dir": str(output_dir), "count": len(files), "files": files}, indent=2, sort_keys=True))
        return 0

    result = mutator.write_corpus(args.output, kinds=kinds, count_per_seed=args.count)
    print(result.to_json())
    return 0


def _signature_from_args(args: argparse.Namespace, payload: bytes, target_name: str) -> CrashSignature:
    if args.expected_exception:
        return CrashSignature(args.expected_exception, args.expected_message or "")
    return DeltaMinimizer(get_target(target_name), target_name).infer_signature(payload)


def run_minimize(args: argparse.Namespace) -> int:
    target_name = validate_target_name(args.target)
    payload = Path(args.payload).read_bytes()
    signature = _signature_from_args(args, payload, target_name)
    minimizer = DeltaMinimizer(get_target(target_name), target_name)
    result, minimized = minimizer.minimize(
        MinimizeRequest(
            target_name=target_name,
            payload=payload,
            signature=signature,
            max_rounds=args.max_rounds,
        )
    )
    payload_path, json_path = write_minimized_result(result, minimized, args.output)
    print(result.to_json())
    print(f"payload={payload_path}")
    print(f"metadata={json_path}")
    return 0 if result.reproduced else 1


def run_reproduce(args: argparse.Namespace) -> int:
    target_name = validate_target_name(args.target)
    payload = Path(args.payload).read_bytes()
    signature = _signature_from_args(args, payload, target_name)
    result = write_pytest_reproducer(
        ReproducerRequest(
            target_name=target_name,
            payload=payload,
            signature=signature,
            test_name=args.test_name,
        ),
        output_dir=args.output,
    )
    print(result.to_json())
    return 0


def run_minimize_reports(args: argparse.Namespace) -> int:
    import json

    report_dir = Path(args.report_dir)
    crash_dir = report_dir / "crashes"
    output_dir = Path(args.output)
    reproducer_dir = Path(args.reproducer_output)
    processed: list[dict[str, object]] = []

    if not crash_dir.exists():
        print(json.dumps({"processed": [], "count": 0, "message": f"no crash dir found: {crash_dir}"}, indent=2))
        return 0

    for payload_path in sorted(crash_dir.glob("*.bin")):
        metadata_path = payload_path.with_suffix(".json")
        if metadata_path.exists():
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            target_name = validate_target_name(str(metadata.get("target_name", args.target or "")))
            signature = CrashSignature(
                str(metadata.get("exception_type", args.expected_exception or "Exception")),
                str(metadata.get("message", args.expected_message or "")),
            )
        else:
            if not args.target:
                continue
            target_name = validate_target_name(args.target)
            signature = CrashSignature(args.expected_exception or "Exception", args.expected_message or "")

        payload = payload_path.read_bytes()
        minimizer = DeltaMinimizer(get_target(target_name), target_name)
        result, minimized = minimizer.minimize(
            MinimizeRequest(
                target_name=target_name,
                payload=payload,
                signature=signature,
                max_rounds=args.max_rounds,
            )
        )
        minimized_path, minimized_json = write_minimized_result(result, minimized, output_dir)
        repro = None
        if args.generate_reproducers and result.reproduced:
            repro = write_pytest_reproducer(
                ReproducerRequest(target_name=target_name, payload=minimized, signature=result.signature),
                output_dir=reproducer_dir,
            )
        processed.append(
            {
                "source": str(payload_path),
                "minimized_payload": str(minimized_path),
                "minimized_metadata": str(minimized_json),
                "reproducer": None if repro is None else repro.output_path,
                "result": result.to_dict(),
            }
        )

    print(json.dumps({"processed": processed, "count": len(processed)}, indent=2, sort_keys=True))
    return 0



def run_import_peachtree(args):
    result = PeachTreeSeedImporter().import_manifest(
        args.seed_manifest,
        args.target,
        args.output,
        source_root=args.source_root,
    )
    print(result.to_json())
    return 0

def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="peachfuzz", description="PeachFuzz AI defensive fuzzing harness")
    sub = parser.add_subparsers(dest="command", required=True)

    import_peachtree = sub.add_parser("import-peachtree", help="import reviewed PeachTree seed manifests into a local corpus")
    import_peachtree.add_argument("--seed-manifest", required=True)
    import_peachtree.add_argument("--target", choices=["json", "graphql", "openapi", "webhook", "yaml", "xml", "http", "log"], required=True)
    import_peachtree.add_argument("--output", required=True)
    import_peachtree.add_argument("--source-root")
    import_peachtree.set_defaults(func=run_import_peachtree)

    run = sub.add_parser("run", help="run deterministic fallback fuzzing")
    run.add_argument("--target", choices=target_names(), required=True)
    run.add_argument("--runs", type=int, default=1000)
    run.add_argument("--seed", type=int, default=1337)
    run.add_argument("--report-dir", default="reports")
    run.add_argument("--backend", choices=backend_names(), default="deterministic")
    run.add_argument("--fail-on-crash", action="store_true")
    run.add_argument("corpus", nargs="*", help="corpus files or directories")
    run.set_defaults(func=run_deterministic)


    trace = sub.add_parser("peachtrace", help="run dependency-free trace-guided fuzzing")
    trace.add_argument("--target", choices=target_names(), required=True)
    trace.add_argument("--runs", type=int, default=1000)
    trace.add_argument("--seed", type=int, default=1337)
    trace.add_argument("--report-dir", default="reports")
    trace.add_argument("--fail-on-crash", action="store_true")
    trace.add_argument("corpus", nargs="*", help="corpus files or directories")
    trace.set_defaults(func=run_peachtrace)

    ath = sub.add_parser("atheris", help="legacy optional Atheris fuzzing; prefer: peachfuzz run --backend peachtrace")
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

    schemas = sub.add_parser("schemas", help="generate schema-aware local fuzz corpora")
    schemas.add_argument("--kind", action="append", choices=["all"] + kind_names(), default=["all"])
    schemas.add_argument("--count", type=int, default=4, help="mutations per built-in seed")
    schemas.add_argument("--seed", type=int, default=1337)
    schemas.add_argument("--output", default="corpus/generated/schema")
    schemas.add_argument("--import-openapi", help="import a local OpenAPI JSON file into the corpus")
    schemas.set_defaults(func=run_schemas)

    minimize = sub.add_parser("minimize", help="minimize one local crash payload")
    minimize.add_argument("--target", choices=target_names(), required=True)
    minimize.add_argument("--expected-exception", help="expected exception type; inferred when omitted")
    minimize.add_argument("--expected-message", default="", help="expected exception message substring")
    minimize.add_argument("--max-rounds", type=int, default=8)
    minimize.add_argument("--output", default="reports/minimized")
    minimize.add_argument("payload", help="crash payload file")
    minimize.set_defaults(func=run_minimize)

    reproduce = sub.add_parser("reproduce", help="generate a pytest reproducer for one crash payload")
    reproduce.add_argument("--target", choices=target_names(), required=True)
    reproduce.add_argument("--expected-exception", help="expected exception type; inferred when omitted")
    reproduce.add_argument("--expected-message", default="", help="expected exception message substring")
    reproduce.add_argument("--output", default="tests/regression")
    reproduce.add_argument("--test-name")
    reproduce.add_argument("payload", help="crash or minimized payload file")
    reproduce.set_defaults(func=run_reproduce)

    minimize_reports = sub.add_parser("minimize-reports", help="bulk minimize reports/crashes and optionally generate pytest reproducers")
    minimize_reports.add_argument("--report-dir", default="reports")
    minimize_reports.add_argument("--output", default="reports/minimized")
    minimize_reports.add_argument("--reproducer-output", default="tests/regression")
    minimize_reports.add_argument("--generate-reproducers", action="store_true")
    minimize_reports.add_argument("--target", choices=target_names())
    minimize_reports.add_argument("--expected-exception")
    minimize_reports.add_argument("--expected-message", default="")
    minimize_reports.add_argument("--max-rounds", type=int, default=8)
    minimize_reports.set_defaults(func=run_minimize_reports)

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
