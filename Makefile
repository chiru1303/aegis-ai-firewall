.PHONY: all demo build run-backend run-frontend

all: build

demo:
	python scripts/seed_demo.py

build:
	cd frontend && npm run build

run-backend:
	python -m uvicorn app.main:app --app-dir backend --port 8000 --reload

run-frontend:
	cd frontend && npm run dev
