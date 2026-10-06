# Contributing to Verdamt-Snipe

Thank you for improving Verdamt-Snipe. This project is for authorized security
assessments, defensive research, and in-scope bug-bounty work only.

## Local setup

Use Python 3.10 or newer, then create an isolated environment and install the
runtime dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the test suite before opening a pull request:

```bash
python -m unittest discover -s tests -v
python -m compileall -q verd.py core modules reports runners tests
```

## Changes

- Keep changes focused; do not combine a refactor with an unrelated feature.
- Add or update tests for every behavior change.
- Keep network-facing behavior opt-in and respect the target scope, configured
  rate limits, and authorization boundaries.
- Do not commit credentials, target lists, scan output, or private assessment
  data. The repository's `.gitignore` covers common local artifacts.
- Document new command-line flags, runner modes, or external dependencies in
  `README.md`.

## Pull requests

Describe the problem, the solution, how you tested it, and any operational or
compatibility impact. Maintainers may ask that changes affecting scanning
behavior include a safe local test or mock-based test.
