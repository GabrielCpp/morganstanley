

.PHONY: start
start:
	python -m uvicorn vulnerabilitieserver.main:app --host 0.0.0.0 --port 8000 --workers 4 --loop uvloop --http httptools

.PHONY: dev
dev:
	python -m uvicorn vulnerabilitieserver.main:app --host 0.0.0.0 --port 8000 --reload

.PHONY: install
install:
	pip install -r requirements-test.txt