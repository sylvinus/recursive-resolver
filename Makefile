.DEFAULT_GOAL := help

CSV ?= domains.csv

.PHONY: help install test test-integration test-from-csv coverage lint format typecheck build clean docker-shell \
       release-check release-build release-shell release-test-pypi release-pypi release-github release

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies
	uv sync

test: ## Run unit tests (no network)
	uv run pytest -m "not integration" -v

test-integration: ## Run integration tests (requires network)
	uv run pytest -m integration -v

test-from-csv: ## Bulk test from CSV file (CSV=path/to/file.csv)
	uv run pytest tests/test_csv.py --csv=$(CSV) -v

coverage: ## Run tests with coverage report
	uv run pytest --cov=recursive_resolver --cov-report=term-missing --cov-report=html -m "not integration"

lint: ## Lint source and tests
	uv run ruff check src/ tests/

format: ## Auto-format source and tests
	uv run ruff format src/ tests/

typecheck: ## Run type checking
	uv run mypy src/

build: ## Build sdist and wheel
	uv build

docker-shell: ## Drop into a Docker shell with uv, make, dig and deps installed
	docker build -t recursive-resolver .
	docker run --rm -it -v $(CURDIR):/app -w /app recursive-resolver

release-shell: release-build ## Test the built wheel in a clean Docker environment
	docker run --rm -it -v $(CURDIR)/dist:/dist python:3.13-slim bash -c '\
		pip install --quiet /dist/recursive_resolver-$(VERSION)-py3-none-any.whl && \
		echo "Installed recursive-resolver $(VERSION)" && \
		echo "Try: recursive-resolver example.com" && \
		echo "     recursive-resolver --trace example.com" && \
		echo "     python -c \"from recursive_resolver import RecursiveResolver; print(RecursiveResolver().resolve(\\\"example.com\\\"))\"" && \
		exec bash'

clean: ## Remove build artifacts
	rm -rf dist/ build/ htmlcov/ .coverage .pytest_cache .mypy_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true

# ── Release targets ───────────────────────────────────────────────────

VERSION := $(shell python3 -c "import re; print(re.search(r'version = \"(.+?)\"', open('pyproject.toml').read()).group(1))")

release-check: ## Run all checks before a release (lint, typecheck, tests)
	@echo "Running pre-release checks..."
	uv run ruff check src/ tests/
	uv run ruff format --check src/ tests/
	uv run mypy src/
	uv run pytest -m "not integration" -x -q
	@echo "Verifying version consistency..."
	@PY_VER=$$(python3 -c "import re; print(re.search(r'__version__ = \"(.+?)\"', open('src/recursive_resolver/__init__.py').read()).group(1))"); \
	TOML_VER=$$(python3 -c "import re; print(re.search(r'version = \"(.+?)\"', open('pyproject.toml').read()).group(1))"); \
	if [ "$$PY_VER" != "$$TOML_VER" ]; then \
		echo "ERROR: Version mismatch — __init__.py=$$PY_VER vs pyproject.toml=$$TOML_VER"; exit 1; \
	fi
	@echo "All checks passed. Version: $(VERSION)"

release-build: clean ## Build sdist and wheel for release
	uv build
	@echo "Built dist/ artifacts for version $(VERSION):"
	@ls -lh dist/

release-test-pypi: release-build ## Upload to Test PyPI
	uv publish --publish-url https://test.pypi.org/legacy/
	@echo "Published $(VERSION) to Test PyPI"
	@echo "Install with: pip install --index-url https://test.pypi.org/simple/ recursive-resolver==$(VERSION)"

release-pypi: release-build ## Upload to PyPI (production)
	uv publish
	@echo "Published $(VERSION) to PyPI"

release-github: ## Create a GitHub release with tag
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "ERROR: Tag v$(VERSION) already exists"; exit 1; \
	fi
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"
	gh release create "v$(VERSION)" dist/* --title "v$(VERSION)" --generate-notes
	@echo "GitHub release v$(VERSION) created"

release: release-check release-pypi release-github ## Full release: checks + PyPI + GitHub
