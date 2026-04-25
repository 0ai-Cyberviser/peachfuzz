from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import shutil
from typing import Any

ALLOWED_TARGETS = {"json", "graphql", "openapi", "webhook", "yaml", "xml", "http", "log"}


@dataclass(frozen=True)
class PeachTreeImportResult:
    target: str
    seed_manifest: str
    output: str
    imported: int
    skipped: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


class PeachTreeSeedImportError(ValueError):
    pass


class PeachTreeSeedImporter:
    """Import reviewed PeachTree seed manifests into local PeachFuzz corpora.

    This importer is intentionally local-only. It refuses manifests without provenance,
    absolute seed paths, parent-directory traversal, unknown targets, or missing source
    dataset digests.
    """

    def import_manifest(
        self,
        seed_manifest: str | Path,
        target: str,
        output: str | Path,
        *,
        source_root: str | Path | None = None,
    ) -> PeachTreeImportResult:
        manifest_path = Path(seed_manifest).resolve()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self._validate_manifest(manifest, target)

        source_base = Path(source_root).resolve() if source_root else manifest_path.parent.resolve()
        out = Path(output).resolve()
        out.mkdir(parents=True, exist_ok=True)

        imported = 0
        skipped = 0
        for seed in manifest.get("seeds", []):
            rel = self._safe_relative_path(str(seed.get("path", "")))
            source = (source_base / rel).resolve()
            if not source.exists() or not source.is_file():
                skipped += 1
                continue
            if not self._is_under(source, source_base):
                raise PeachTreeSeedImportError(f"seed path escapes source root: {rel}")
            destination = out / source.name
            shutil.copyfile(source, destination)
            imported += 1

        return PeachTreeImportResult(
            target=target,
            seed_manifest=str(manifest_path),
            output=str(out),
            imported=imported,
            skipped=skipped,
        )

    @staticmethod
    def _validate_manifest(manifest: dict[str, Any], target: str) -> None:
        if target not in ALLOWED_TARGETS:
            raise PeachTreeSeedImportError(f"unsupported target: {target}")
        if manifest.get("target") != target:
            raise PeachTreeSeedImportError("manifest target does not match requested target")
        if not manifest.get("source_dataset_digest"):
            raise PeachTreeSeedImportError("manifest is missing source_dataset_digest")
        if not isinstance(manifest.get("seeds"), list):
            raise PeachTreeSeedImportError("manifest seeds must be a list")
        policy = manifest.get("policy", {})
        if policy.get("no_network") is not True or policy.get("no_execution") is not True:
            raise PeachTreeSeedImportError("manifest policy must declare no_network and no_execution")
        for seed in manifest.get("seeds", []):
            if not seed.get("source_record_id") or not seed.get("source_digest"):
                raise PeachTreeSeedImportError("seed is missing provenance fields")

    @staticmethod
    def _safe_relative_path(value: str) -> Path:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise PeachTreeSeedImportError(f"unsafe seed path: {value}")
        if not value.strip():
            raise PeachTreeSeedImportError("empty seed path")
        return path

    @staticmethod
    def _is_under(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False
