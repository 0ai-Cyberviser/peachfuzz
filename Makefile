.DEFAULT_GOAL := help
PYTHON ?= python

.PHONY: help install test fuzz fuzz-json fuzz-findings clean package

help:
	@echo "PeachFuzz AI targets:"
	@echo "  install       Install editable dev dependencies"
	@echo "  test          Run unit tests"
	@echo "  fuzz          Run deterministic fuzz smoke tests"
	@echo "  fuzz-json     Run JSON target"
	@echo "  fuzz-findings Run findings target"
	@echo "  package       Build source/wheel package"
	@echo "  clean         Remove cache/build artifacts"

install:
	$(PYTHON) -m pip install -e ".[dev,fuzz]"

test:
	$(PYTHON) -m pytest -q

fuzz: fuzz-json fuzz-findings

fuzz-json:
	$(PYTHON) -m peachfuzz_ai.cli run --target json --runs 500

fuzz-findings:
	$(PYTHON) -m peachfuzz_ai.cli run --target findings --runs 500

package:
	$(PYTHON) -m pip install build
	$(PYTHON) -m build

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist *.egg-info src/*.egg-info reports
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
