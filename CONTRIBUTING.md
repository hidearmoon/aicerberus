# Contributing to AICerberus

Thank you for your interest in contributing! AICerberus is an open-source project focused on AI supply chain security — your contributions help keep the AI ecosystem safer.

## Getting Started

```bash
git clone https://github.com/hidearmoon/aicerberus
cd aicerberus
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/
```

All tests must pass and ruff lint must be clean before opening a PR.

## Lint

```bash
ruff check aicerberus/
```

## Areas Where Contributions Are Welcome

- **New CVE sources** — add support for GHSA, NVD, or vendor advisories beyond OSV
- **New model file formats** — GGUF, MLflow models, Keras v3 (.keras), etc.
- **New license types** — AI-specific licenses added by new model families
- **HuggingFace model ID patterns** — improve discovery regex for new framework APIs
- **CI integration examples** — GitLab CI, CircleCI, Bitbucket Pipelines
- **Bug fixes and test coverage**

## Pull Request Guidelines

1. Fork the repo and create a feature branch from `main`
2. Write tests for any new functionality
3. Ensure `pytest tests/` passes and `ruff check aicerberus/` is clean
4. Keep PRs focused — one feature or fix per PR
5. Update `README.md` / `README_zh.md` if you add a CLI flag or new feature

## Reporting Security Issues

Please **do not** file public GitHub issues for security vulnerabilities in AICerberus itself. Instead, email `openforge-ai@proton.me` with the details.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
