.PHONY: install lint format type test cov verify run scan docker compose clean

install:
	pip install -e ".[dev]"

lint:
	ruff check .

format:
	ruff format .

type:
	mypy

test:
	pytest

cov:
	pytest --cov=netaudit --cov-report=term-missing --cov-fail-under=85

verify: lint type cov

run:
	uvicorn netaudit.api:app --reload

scan:
	-netaudit scan tests/fixtures/fortigate_bad.conf --fail-under 80
	-netaudit scan tests/fixtures/cisco_good.conf --fail-under 80

docker:
	docker build -t netaudit:dev .

compose:
	docker compose up --build

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache dist build .coverage htmlcov
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
