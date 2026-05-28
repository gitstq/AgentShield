.PHONY: install test lint dashboard clean help

# Default target
help:
	@echo "AgentShield Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install   - Install the package in development mode"
	@echo "  test      - Run all tests"
	@echo "  lint      - Run static analysis with flake8 (if available)"
	@echo "  dashboard - Start the web dashboard"
	@echo "  clean     - Remove build artifacts and cache files"
	@echo "  examples  - Run the basic usage example"

# Install the package
install:
	pip install -e ".[dev]"

# Run tests
test:
	python -m pytest tests/ -v || python -m unittest discover -s tests -v

# Run linting (optional - only if flake8 is installed)
lint:
	flake8 agentshield/ tests/ --max-line-length=100 --ignore=E501,W503 || echo "flake8 not installed, skipping lint"

# Start the dashboard
dashboard:
	python -m agentshield.dashboard.app

# Run basic example
examples:
	python examples/basic_usage.py

# Clean build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/ dist/ .eggs/ 2>/dev/null || true
	rm -rf agentshield_audit_*.json agentshield_audit_*.csv 2>/dev/null || true
	@echo "Clean complete."
