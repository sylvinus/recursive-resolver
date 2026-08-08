.DEFAULT_GOAL := help

CSV ?= domains.csv
SOURCES := src/ tests/ scripts/

.PHONY: help install test test-integration test-from-csv coverage coverage-all lint format typecheck \
       check check-all build clean docker-shell release release-check

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies
	uv sync --all-extras

test: ## Run unit tests (no network)
	uv run pytest -m "not integration" -v

test-integration: ## Run integration tests (requires network)
	uv run pytest -m integration -v

test-from-csv: ## Bulk differential test against dig (CSV=path/to/file.csv)
	uv run pytest tests/test_csv.py --csv=$(CSV) -v

coverage: ## Offline coverage report (HTML in htmlcov/); does not meet the gate alone
	uv run pytest -m "not integration" --cov --cov-report=html --cov-fail-under=0

coverage-all: ## Full coverage including live DNS (this is the enforced gate)
	uv run pytest --cov --cov-report=html

lint: ## Lint source, tests and scripts
	uv run ruff check $(SOURCES)

format: ## Auto-format source, tests and scripts
	uv run ruff format $(SOURCES)

typecheck: ## Run type checking
	uv run mypy src/

check: lint typecheck ## Lint, typecheck and run the offline tests
	uv run ruff format --check $(SOURCES)
	uv run pytest -m "not integration" -q --no-cov

check-all: lint typecheck ## Everything, including live DNS and the coverage gate
	uv run ruff format --check $(SOURCES)
	uv run pytest -q --cov

build: ## Build sdist and wheel
	uv build

docker-shell: ## Drop into a Docker shell with uv, make, dig and deps installed
	docker build -t recursive-resolver .
	docker run --rm -it -v $(CURDIR):/app -w /app recursive-resolver

clean: ## Remove build artifacts
	rm -rf dist/ build/ htmlcov/ .coverage .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true

# ── Release ───────────────────────────────────────────────────────────
#
# Releases are driven by scripts/release.sh, which is interactive and builds,
# checks, publishes and tags from inside Docker. See CONTRIBUTING.md.

VERSION := $(shell python3 -c "import re; print(re.search(r'version = \"(.+?)\"', open('pyproject.toml').read()).group(1))")

release: ## Interactive release to PyPI and GitHub (see CONTRIBUTING.md)
	./scripts/release.sh

release-check: check-all ## Everything the release script checks, without publishing
	@echo "Verifying version consistency..."
	@PY_VER=$$(python3 -c "import re; print(re.search(r'__version__ = \"(.+?)\"', open('src/recursive_resolver/__init__.py').read()).group(1))"); \
	if [ "$$PY_VER" != "$(VERSION)" ]; then \
		echo "ERROR: Version mismatch: __init__.py=$$PY_VER vs pyproject.toml=$(VERSION)"; exit 1; \
	fi
	@grep -q "\[$(VERSION)\]" CHANGELOG.md || { echo "ERROR: no CHANGELOG.md entry for $(VERSION)"; exit 1; }
	@echo "All checks passed. Version: $(VERSION)"
