# PeachFuzz AI Architecture

PeachFuzz AI follows a safe agentic loop:

1. Load local corpus.
2. Mutate input deterministically or through Atheris.
3. Execute a local target adapter.
4. Catch target exceptions as fuzz findings.
5. Generate a self-refinement advisory.
6. Write crash artifacts and summaries.

It intentionally avoids autonomous offensive execution.
