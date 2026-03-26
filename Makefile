PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff

.PHONY: venv install test lint format run-example package clean

venv:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

install: venv
	$(PIP) install -e .[dev]

test:
	$(PYTEST) -q

lint:
	$(RUFF) check src tests

format:
	$(RUFF) format src tests

run-example:
	$(VENV)/bin/manifest-guard fix examples --report-json dist/report.json

package:
	$(PYTHON) -m build

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache dist build *.egg-info .manifestguard
