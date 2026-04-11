.PHONY: check vet lint format test audit setup init-schema run-etl

# Full quality gate: vet → lint → test
check: vet lint test audit

vet:
	uv run ruff check src/ cmd/ tests/

lint:
	uv run ruff format --check src/ cmd/ tests/

format:
	uv run ruff format src/ cmd/ tests/
	uv run ruff check --fix src/ cmd/ tests/

test:
	uv run python -m pytest tests/ -v

audit:
	PIPAPI_PYTHON_LOCATION=.venv/bin/python3 uv run pip-audit

setup:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit .githooks/pre-push
	@echo "Git hooks installed (pre-commit: vet+lint, pre-push: full check)."

init-schema:
	uv run python cmd/init_schema.py

run-etl:
	uv run python cmd/run_etl.py

load-assets:
	uv run python cmd/load_assets.py

visualize:
	uv run python cmd/visualize_graph.py
