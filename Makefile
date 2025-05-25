

.PHONY: start
start:
	python -m uvicorn vulnerabilitieserver.main:app --host 0.0.0.0 --port 8000

.PHONY: dev
dev:
	python -m uvicorn vulnerabilitieserver.main:app --host 0.0.0.0 --port 8000 --reload

.PHONY: install
install:
	pip install -r requirements-test.txt