# GrantScope — zero-dependency developer tasks.
# Works on Linux / macOS / WSL / Git Bash. Python is the only requirement.

PYTHON ?= python3
PYZ := dist/grantscope.pyz

.PHONY: help test build verify clean demo fixtures install

help:
	@echo "GrantScope targets:"
	@echo "  make test       run the 64 unit tests (stdlib unittest)"
	@echo "  make build      build the single-file zipapp -> $(PYZ)"
	@echo "  make verify     test + build + run the zipapp end-to-end"
	@echo "  make demo       audit the good/ and bad/ example bundles"
	@echo "  make fixtures   regenerate example bundles deterministically"
	@echo "  make clean      remove build artefacts and caches"

test:
	$(PYTHON) -m unittest discover -s tests -v

build:
	$(PYTHON) build.py

fixtures:
	$(PYTHON) examples/make_fixtures.py

verify: test build
	$(PYTHON) $(PYZ) version
	$(PYTHON) $(PYZ) audit examples/good --no-color --fail-on high
	$(PYTHON) $(PYZ) rules --format text | tail -1
	$(PYTHON) $(PYZ) audit examples/bad --format sarif --output dist/bad.sarif --fail-on never
	@echo "verify OK"

demo:
	$(PYTHON) -m grantscope audit examples/good --no-color --fail-on never
	$(PYTHON) -m grantscope audit examples/bad --no-color --quiet --fail-on never

install:
	$(PYTHON) -m pip install -e .

clean:
	rm -rf dist .build_tmp .pytest_cache .mypy_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
