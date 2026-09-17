.PHONY: install demo redteam bench lint findings test serve docker clean

VENV := .venv/bin

install:
	uv venv --python 3.12
	uv pip install -e ".[dev]"

demo:      ; @$(VENV)/python -W ignore -m aegis.cli demo
redteam:   ; @$(VENV)/python -W ignore -m aegis.cli redteam
bench:     ; @$(VENV)/python -W ignore -m aegis.cli bench
lint:      ; @$(VENV)/python -W ignore -m aegis.cli lint policies
findings:  ; @$(VENV)/python -W ignore -m aegis.cli findings
test:      ; @$(VENV)/python -W ignore -m pytest tests -q
serve:     ; @$(VENV)/python -W ignore -m aegis.cli serve

# Side-by-side: what agt's linter says vs ours, on a file with 5 real errors.
lint-compare:
	@echo "=== agt lint-policy ==="        ; -$(VENV)/agt lint-policy tests/fixtures
	@echo ""; echo "=== aegis-policylint ==="; -$(VENV)/python -W ignore -m aegis.policytool tests/fixtures

docker:    ; docker compose up --build

clean:
	rm -rf .venv data/exports __pycache__ .pytest_cache
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
