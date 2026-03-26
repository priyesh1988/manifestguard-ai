# Contributing

1. Create a virtual environment.
2. Install dev dependencies with `pip install -e .[dev]`.
3. Run `ruff check src tests` and `pytest -q` before opening a PR.
4. Add tests for any analyzer or fixer change.
5. Keep fixes deterministic and safe by default.
