# Contributing to TrustTrain

Thanks for your interest in improving TrustTrain. Bug reports, detector ideas, documentation fixes and code are all welcome.

## Ground rules

- **Be truthful about capabilities.** Do not add hard-coded results, simulated success responses or benchmark numbers that were not produced by running the code. Findings must keep their evidence, confidence, methodology and limitations.
- **Never execute dataset content** and never deserialize untrusted data with pickle or similar mechanisms.
- **Report vulnerabilities privately.** See [SECURITY.md](SECURITY.md); do not open public issues for them.

## Development setup

```bash
git clone https://github.com/kirtanbhatt10/trusttrain.git && cd trusttrain

# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.15.0
pip install -r requirements-dev.txt && pip install -e ../sdk
uvicorn app.main:app --reload

# Frontend (another terminal)
cd frontend && npm install && npm run dev
```

## Before opening a pull request

Run the same checks as CI (details in [docs/TESTING.md](docs/TESTING.md)):

```bash
ruff check backend sdk scripts examples && ruff format --check backend sdk scripts examples
(cd backend && mypy app && pytest)
(cd sdk && mypy trusttrain && pytest)
(cd frontend && npm run lint && npm test && npm run build)
```

- Add or update tests for every behavior change. Security-relevant changes need a negative test (the attack is rejected) as well as a positive one.
- If you change ORM models, add an Alembic migration (`alembic revision --autogenerate`) and review it.
- If you change a detector, re-run `python scripts/run_benchmark.py --output docs/benchmark-results.json`, update `docs/RESEARCH_AND_BENCHMARKS.md`, and keep `tests/test_attack_lab.py` floors passing. Do not lower a floor without explaining why in the pull request.
- Update `CHANGELOG.md` under "Unreleased".

## Adding a detector

1. Create `backend/app/detectors/<name>.py` with a class that has `name`, `applicable(ctx) -> (bool, reason)` and `run(ctx) -> list[FindingDraft]`.
2. Every `FindingDraft` needs a severity, confidence, explanation, evidence (row indices), investigation steps and limitations.
3. Register it in `detectors/engine.py::all_detectors`.
4. Add any configurable threshold to `_THRESHOLD_KEYS` in `services/inspection.py`.
5. Add positive and negative tests to `tests/test_detectors.py`, and document the method in `docs/DETECTION_METHODOLOGY.md`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`. Keep the subject under 72 characters and describe what changed and why.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
