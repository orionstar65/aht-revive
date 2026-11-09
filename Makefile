.PHONY: install dev test promote
install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt
dev:
	.venv/bin/uvicorn app.main:app --reload --port 8000
test:
	.venv/bin/python -m pytest -q
promote:
	.venv/bin/python -m scripts.promote_admin $(EMAIL)
