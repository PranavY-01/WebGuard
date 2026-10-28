# Contributing to WebGuard

This file is for people changing WebGuard's code. If you want to *use* WebGuard, read the
[user guide](docs/USER_GUIDE.md).

## Setup

Contributors use [uv](https://docs.astral.sh/uv/) with the committed, hash-pinned `uv.lock`:

```console
$ uv sync --locked                          # .venv with exactly the locked dependencies (Python 3.12+)
$ uv run webguard version
```

uv-managed interpreters are optional and only useful for testing several Python versions locally
(`uv python install 3.12 3.13 3.14`, then `UV_PYTHON=3.13 uv run --locked pytest`). Any CPython 3.12+ works.

## Checks (all run in CI)

```console
$ uv run ruff check && uv run ruff format --check
$ uv run mypy --strict src/
$ uv run lint-imports                       # architecture contracts (network I/O only in webguard.egress)
$ uv run pytest                             # unit, integration and security tests
```

CI runs these on Linux, macOS and Windows × Python 3.12, 3.13 and 3.14, and audits the locked runtime
dependencies with `pip-audit`.

## Tests never touch the internet

The suite runs against a local TLS server on `127.0.0.1:8443` with a locally generated CA. The test CA, a
loopback-only scope policy and a stub resolver are injected through the Python API and exist only under `tests/`.
An autouse fixture makes any connect or name lookup to a non-loopback host raise before a packet is sent (S-29).

## Generated files

```console
$ uv run python -m tests.unit.render_docs   # docs/RULES.md and tests/fixtures/known_answers.md
$ uv run python -m tests.make_samples       # samples/ (from local fixtures only)
```

Tests fail if `docs/RULES.md` or the known-answer record is out of date.

## Design documents

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, the request pipeline, invariants and design decisions.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): threats, mitigations and residual risk.

Report security issues privately; see [SECURITY.md](SECURITY.md).
