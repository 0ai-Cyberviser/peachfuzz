# PeachFuzz PeachTree Seed Import

This change adds a local-only importer for reviewed PeachTree seed manifests.

## Usage

```bash
peachfuzz import-peachtree \
  --seed-manifest ../PeachTree/reports/seeds/graphql-seeds.json \
  --target graphql \
  --output corpus/peachtree/graphql
```

## Safety model

- The importer reads local manifests and local seed files only.
- It rejects manifests without `source_dataset_digest`.
- It rejects seeds without provenance fields.
- It rejects absolute paths and parent-directory traversal.
- It requires manifest policy declarations for `no_network` and `no_execution`.

The command does not scan networks, run exploit payloads, execute shell commands, or contact third-party systems.
