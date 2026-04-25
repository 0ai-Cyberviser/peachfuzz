import json
from pathlib import Path

import pytest

from peachfuzz_ai.cli import main
from peachfuzz_ai.guardrails import validate_target_name
from peachfuzz_ai.schema_mutators import SchemaAwareMutator, SchemaKind, kind_names, parse_kinds
from peachfuzz_ai.targets import get_target, target_names


def test_kind_names_include_structured_targets():
    assert {"json", "openapi", "graphql", "webhook"}.issubset(set(kind_names()))


def test_parse_kinds_all_and_specific():
    assert SchemaKind.JSON_API in parse_kinds(["all"])
    assert parse_kinds(["graphql"]) == [SchemaKind.GRAPHQL]


def test_default_seed_generation():
    mutator = SchemaAwareMutator(seed=1)
    seeds = mutator.default_seeds()
    kinds = {seed.kind for seed in seeds}
    assert SchemaKind.JSON_API in kinds
    assert SchemaKind.OPENAPI in kinds
    assert SchemaKind.GRAPHQL in kinds
    assert SchemaKind.WEBHOOK in kinds


def test_generate_is_deterministic():
    first = SchemaAwareMutator(seed=7).generate(kinds=["webhook"], count_per_seed=2)
    second = SchemaAwareMutator(seed=7).generate(kinds=["webhook"], count_per_seed=2)
    assert [seed.to_bytes() for seed in first] == [seed.to_bytes() for seed in second]


def test_write_corpus(tmp_path: Path):
    result = SchemaAwareMutator(seed=2).write_corpus(tmp_path, kinds=["graphql", "webhook"], count_per_seed=1)
    assert result.count > 0
    assert (tmp_path / "graphql").exists()
    assert (tmp_path / "webhook").exists()


def test_import_openapi_json(tmp_path: Path):
    source = tmp_path / "openapi.json"
    source.write_text(json.dumps({"openapi": "3.1.0", "paths": {"/x": {"get": {"responses": {"200": {"description": "ok"}}}}}}), encoding="utf-8")
    seeds = SchemaAwareMutator().import_openapi_json(source)
    assert seeds[0].kind == SchemaKind.OPENAPI


def test_import_openapi_json_rejects_invalid(tmp_path: Path):
    source = tmp_path / "bad.json"
    source.write_text(json.dumps({"not": "openapi"}), encoding="utf-8")
    with pytest.raises(ValueError):
        SchemaAwareMutator().import_openapi_json(source)


def test_new_targets_registered():
    assert {"openapi", "graphql", "webhook"}.issubset(set(target_names()))
    for name in ["openapi", "graphql", "webhook"]:
        assert callable(get_target(name))
        assert validate_target_name(name) == name


def test_validate_target_name_matches_registered_targets():
    for name in target_names():
        assert validate_target_name(name) == name


def test_structured_targets_accept_generated_seeds():
    mutator = SchemaAwareMutator(seed=3)
    for kind, target_name in [
        (SchemaKind.OPENAPI, "openapi"),
        (SchemaKind.GRAPHQL, "graphql"),
        (SchemaKind.WEBHOOK, "webhook"),
    ]:
        target = get_target(target_name)
        for seed in mutator.generate(kinds=[kind], count_per_seed=1):
            target(seed.to_bytes())


def test_cli_schemas_generates_corpus(tmp_path: Path, capsys):
    rc = main(["schemas", "--kind", "webhook", "--count", "1", "--output", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"count"' in out
    assert (tmp_path / "webhook").exists()


def test_cli_schemas_import_openapi(tmp_path: Path, capsys):
    source = tmp_path / "openapi.json"
    source.write_text(json.dumps({"openapi": "3.1.0", "paths": {"/x": {"get": {"responses": {"200": {"description": "ok"}}}}}}), encoding="utf-8")
    out_dir = tmp_path / "imported"
    rc = main(["schemas", "--import-openapi", str(source), "--output", str(out_dir)])
    assert rc == 0
    assert (out_dir / "openapi" / "openapi.json").exists()
    assert '"count": 1' in capsys.readouterr().out
