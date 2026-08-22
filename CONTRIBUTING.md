# Contributing

Thanks for taking a look. This is how the project is developed locally and what
CI expects before a change lands.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before you push

These are exactly the steps CI runs, so run them locally first:

```bash
ruff check src tests
mypy src                          # strict mode
pytest -q --cov=securesync --cov-report=term-missing --cov-fail-under=80
```

Coverage currently sits well above that floor; the gate is there so a change
cannot quietly ship untested code.

CI runs the same matrix on Linux, Windows and macOS against Python 3.11 and
3.12 — the tool is cross-platform, so avoid POSIX-only path or permission
assumptions.

## Conventions

- **Crypto is not hand-rolled.** Use the primitives already wired up in
  `src/securesync` (AES-256-GCM-SIV, Argon2id). Do not introduce a new
  algorithm, mode, or KDF without a written reason in the PR.
- **Nothing plaintext hits the repository store.** Any new data written to a
  backup repository goes through the existing encryption path.
- **Typing.** `src/` is fully typed; `mypy --strict` must stay clean.
- **Tests.** Every change ships with a test. Round-trip behaviour
  (backup → restore → byte-identical) is the property that matters most.
- **Commits.** Short imperative subject; the body explains *why*, not *what*.

## Reporting a security problem

Do not open a public issue — see [SECURITY.md](SECURITY.md).
