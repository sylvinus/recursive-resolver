.DEFAULT_GOAL := help

CSV ?= domains.csv
SOURCES := src/ tests/ scripts/

.PHONY: help install test test-integration test-from-csv coverage coverage-all lint format typecheck \
       check check-all build clean docker-shell release release-check \
       test-corpus test-verdicts test-record test-offline test-protocol

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

# ── Real-world testing protocol (TESTING.md) ──────────────────────────

CORPUS ?= corpus.csv
ADVERSARIAL ?= adversarial.csv
CASSETTES ?= cassettes.jsonl

# The later stages read the files the earlier ones write, so those files are the
# dependencies - not the phony targets. A phony prerequisite would rebuild the
# 30,000-name corpus on every verdict run; a file one reuses what is there and
# collects only when it is missing. Delete the file to force a fresh collection.
#
# A collector killed halfway leaves a partial file, which Make would otherwise
# treat as a finished one and every later stage would read as the corpus.
.DELETE_ON_ERROR:

$(CORPUS):
	uv run python scripts/collect_domains_diverse.py -o $@ --limit 30000

$(ADVERSARIAL): $(CORPUS)
	uv run python scripts/collect_domains_adversarial.py --csv $< -o $@

$(CASSETTES): $(ADVERSARIAL)
	uv run python scripts/cassette.py record --csv $< -o $@ --types A,MX

test-corpus: $(ADVERSARIAL) ## Build the adversarial corpus (network, ~10 min)

test-verdicts: $(ADVERSARIAL) ## Verdict differential and flap detection (network, ~1h)
	uv run python scripts/verdict_harness.py --csv $(ADVERSARIAL) -o verdicts.csv --escalate 8

test-record: $(CASSETTES) ## Record cassettes for offline replay (network)

# The only target here that must never reach the network, so it asks for the
# cassettes rather than depending on them: a missing file is an instruction to
# the operator, not a licence to spend ten minutes recording one.
test-offline: ## Replay cassettes under every order and fault, then mutate (no network)
	@test -f $(CASSETTES) || { echo "$(CASSETTES) not found; run 'make test-record' first (needs network)" >&2; exit 1; }
	uv run python scripts/cassette.py replay --cassettes $(CASSETTES)
	uv run python scripts/cassette.py perturb --cassettes $(CASSETTES)
	uv run python scripts/mutation_check.py --cassettes $(CASSETTES)

test-protocol: test-corpus test-verdicts test-record test-offline ## The whole protocol, before a release

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

# Anchored with re.M, matching the `awk -F'"' '/^version = /'` lookup in
# scripts/release.sh: unanchored, this returns the first `version = "..."`
# anywhere in the file, and the two release paths could disagree.
VERSION := $(shell python3 -c "import re; print(re.search(r'^version = \"(.+?)\"', open('pyproject.toml').read(), re.M).group(1))")

release: ## Interactive release to PyPI and GitHub (see CONTRIBUTING.md)
	./scripts/release.sh

release-check: check-all ## Everything the release script checks, without publishing
	@echo "Verifying version consistency..."
	@PY_VER=$$(python3 -c "import re; print(re.search(r'^__version__ = \"(.+?)\"', open('src/recursive_resolver/__init__.py').read(), re.M).group(1))"); \
	if [ "$$PY_VER" != "$(VERSION)" ]; then \
		echo "ERROR: Version mismatch: __init__.py=$$PY_VER vs pyproject.toml=$(VERSION)"; exit 1; \
	fi
	@awk -v v="## [$(VERSION)]" 'index($$0, v) == 1 { found = 1; exit } END { exit !found }' CHANGELOG.md \
		|| { echo "ERROR: no '## [$(VERSION)]' section heading in CHANGELOG.md"; exit 1; }
	@echo "All checks passed. Version: $(VERSION)"
