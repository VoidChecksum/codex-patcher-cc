.PHONY: help verify quick test lint smoke patches install-dev clean

help:
	@echo "ccp dev targets:"
	@echo "  make verify       — full local CI: lint + AST + JSON + smoke + tests"
	@echo "  make quick        — verify minus pytest"
	@echo "  make test         — pytest only"
	@echo "  make lint         — ruff only (F-codes)"
	@echo "  make smoke        — ccp --help + ccp list"
	@echo "  make patches      — list applied/pending patches against system codex"
	@echo "  make install-dev  — pip install -e . + dev deps (ruff, pytest, capstone)"
	@echo "  make clean        — remove caches"

verify:
	@bash scripts/dev-verify.sh

quick:
	@bash scripts/dev-verify.sh --quick

test:
	@python3 -m pytest tests/ -v

lint:
	@python3 -m ruff check ccp/ tests/ --select F \
	  --ignore E501,E701,E702,E731,E741,E221,E222,E225,E226,E227,E228,E231,E241,E251,E261,E265,E266,E271,E272,E275,E301,E302,E303,E305,E306,W291,W292,W293,W391,W605,F401,F541,F841

smoke:
	@python3 -m ccp --help >/dev/null && python3 -m ccp list

patches:
	@python3 -m ccp list

install-dev:
	@python3 -m pip install -e .
	@python3 -m pip install ruff pytest capstone frida-tools

clean:
	@rm -rf .pytest_cache __pycache__ ccp/__pycache__ tests/__pycache__ \
	        build/ dist/ *.egg-info
