from pathlib import Path
import json

import pytest

from peachfuzz_ai.peachtree_import import PeachTreeSeedImporter, PeachTreeSeedImportError


def _manifest(seed_path: str = "seed.json") -> dict[str, object]:
    return {
        "target": "json",
        "source_dataset": "dataset.jsonl",
        "source_dataset_digest": "abc123",
        "policy": {"local_only": True, "no_network": True, "no_execution": True},
        "seeds": [
            {
                "id": "seed-1",
                "target": "json",
                "path": seed_path,
                "source_record_id": "record-1",
                "source_digest": "source-digest",
                "bytes": 2,
            }
        ],
    }


def test_import_peachtree_seed_manifest(tmp_path: Path) -> None:
    source = tmp_path / "seed.json"
    source.write_text("{}\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_manifest()) + "\n", encoding="utf-8")
    output = tmp_path / "corpus"

    result = PeachTreeSeedImporter().import_manifest(manifest, "json", output)

    assert result.imported == 1
    assert (output / "seed.json").exists()


def test_import_rejects_missing_provenance(tmp_path: Path) -> None:
    bad = _manifest()
    bad["seeds"] = [{"path": "seed.json"}]
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(bad), encoding="utf-8")

    with pytest.raises(PeachTreeSeedImportError):
        PeachTreeSeedImporter().import_manifest(manifest, "json", tmp_path / "out")


def test_import_rejects_parent_path_escape(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(_manifest("../seed.json")), encoding="utf-8")

    with pytest.raises(PeachTreeSeedImportError):
        PeachTreeSeedImporter().import_manifest(manifest, "json", tmp_path / "out")
