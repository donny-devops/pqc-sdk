.PHONY: dev test lint format benchmark build publish clean

dev:
	pip install -e ".[dev]"

dev-native:
	pip install -e ".[dev,native]"

test:
	python -m pytest tests/ -v --tb=short -W ignore::RuntimeWarning

test-ci:
	python -m pytest tests/ -v --tb=short -W ignore::RuntimeWarning --cov=pqc_sdk --cov-report=xml

benchmark:
	python -m pytest benchmarks/ --benchmark-only --benchmark-sort=mean -W ignore

lint:
	ruff check src/ tests/ benchmarks/
	black --check src/ tests/ benchmarks/
	mypy src/pqc_sdk/ --ignore-missing-imports

format:
	black src/ tests/ benchmarks/
	ruff check --fix src/ tests/ benchmarks/

build:
	pip install build
	python -m build

publish-test:
	pip install twine
	twine upload --repository testpypi dist/*

publish:
	pip install twine
	twine upload dist/*

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
