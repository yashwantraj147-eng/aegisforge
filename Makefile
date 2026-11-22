# AegisForge Automation & Management Makefile

.PHONY: help install dev test demo docker-up docker-down clean

help:
	@echo "AegisForge Purple-Team Cyber Range Commands:"
	@echo "  make install         - Install Python & Node dependencies"
	@echo "  make dev             - Launch backend API and frontend dev servers"
	@echo "  make test            - Run backend pytest suite and frontend typecheck"
	@echo "  make lint            - Run Ruff linter and format checks"
	@echo "  make demo            - Run full purple-team CLI interactive demo"
	@echo "  make docker-up       - Boot full production docker-compose environment"
	@echo "  make docker-down     - Teardown docker containers"
	@echo "  make sandbox-up      - Boot isolated 3-node sandbox micro-network"
	@echo "  make sandbox-down    - Teardown sandbox containers"
	@echo "  make clean           - Remove cached artifacts and build folders"

install:
	pip install -e ./backend
	pip install typer rich pytest pytest-asyncio
	cd frontend && npm install
	python sandbox/sample_artifacts/generate_benign_samples.py

dev-backend:
	uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000

dev-frontend:
	cd frontend && npm run dev

test:
	pytest backend/tests -v
	cd frontend && npm run build

demo:
	python cli/aegisctl.py demo

lint:
	ruff check backend/
	ruff format --check backend/

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v

sandbox-up:
	docker compose -f sandbox/docker-compose.sandbox.yml up --build -d

sandbox-down:
	docker compose -f sandbox/docker-compose.sandbox.yml down -v

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf frontend/dist
