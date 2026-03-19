# Contributing to Aegis

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/thecnical/aegis
cd aegis
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -q
```

## Code Style

We use `ruff` for linting and `mypy` for type checking:

```bash
ruff check .
mypy aegis/ --ignore-missing-imports
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes with tests
4. Run the test suite and linters
5. Open a pull request against `main`

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml).

## Feature Requests

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.yml).

## Security Issues

Do **not** open public issues for security vulnerabilities. Email the maintainers directly.

## License

By contributing, you agree your contributions will be licensed under the MIT License.
