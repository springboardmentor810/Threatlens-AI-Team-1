# ThreatLens AI

AI-powered malware classification and threat detection platform.

FastAPI backend, React + Vite dashboard, and an Extra Trees / LightGBM ensemble
over EMBER v2 features.

## Quick start

**Python 3.10 is required.** Not a preference: the EMBER feature extractor
depends on LIEF ≤ 0.12.x, whose wheels stop at cp310. See
`backend/requirements.txt` for the full reasoning.

```bash
py -3.10 -m venv .venv
.venv/Scripts/activate            # Windows;  source .venv/bin/activate elsewhere
pip install -r backend/requirements.txt
cp .env.example .env              # then edit; defaults to SQLite, no secrets required
```

EMBER is **not on PyPI** and has to be installed separately. Without it the API
still runs and still performs static analysis — uploads simply come back with
the AI stage marked unavailable.

```bash
pip install git+https://github.com/elastic/ember.git
```

To retrain or re-run the notebooks, add the analysis stack:

```bash
pip install -r ml_model/requirements.txt
```

Run the API from inside `backend/` — the package imports as `app.*`:

```bash
cd backend && uvicorn app.main:app --reload --port 8000
```

Then the dashboard, which proxies `/api` to the backend in development:

```bash
cd frontend && npm ci && npm run dev
```

Run the tests from the repository root (`pytest.ini` supplies the paths):

```bash
pytest -q
```

## How a scan works

```
POST /api/v1/upload
  → static analysis        hashes, MIME, PE headers, imports, URLs/IPs, YARA
  → EMBER v2 features      2,381 values, F1..F2381        (PE files only)
  → AI ensemble            Extra Trees + LightGBM, 50:50  → verdict + risk
  → detection recorded     threat log, timeline, MongoDB audit entry
  → alert raised           only when the verdict is malware
```

Every route lives under `/api/v1`: `auth`, `upload`, `threats`, `alerts`.

## Layout

| Path | Contents |
|---|---|
| `backend/app/` | FastAPI application: `auth/`, `alerts/`, `api/`, `modules/threat_monitoring/`, `services/` |
| `frontend/` | React + Vite + Tailwind dashboard |
| `ml_model/` | Training, tuning, cross-validation, SHAP explainability, inference |
| `database/` | Schema and seed SQL |
| `documentation/` | Project, database and AI/ML documentation |
| `tests/` | Backend test suite |

## Module ownership

| Area | Owner | Location |
|---|---|---|
| User management, auth, database | Member 1 | `backend/app/{auth,controllers,middleware,models,repositories,services}/` |
| File upload & static analysis | Member 2 | `backend/app/api/upload.py`, `backend/app/services/ember_*.py`, `backend/app/yara_rules/` |
| AI/ML models & inference | Member 3 | `ml_model/` |
| Model optimization & cross-validation | Member 4 | `ml_model/optimization/`, `documentation/ai-ml/` |
| Threat monitoring | Member 5 | `backend/app/modules/threat_monitoring/`, `backend/app/api/threat_monitoring.py` |
| Alerts & notifications | Member 6 | `backend/app/alerts/` |
| Frontend dashboard | Member 7 | `frontend/` |

## Status

The team's branches have been consolidated onto a single integration branch.
Progress, decisions, verified findings and the remaining open risks are tracked
in `integration-plan.md` — read that before picking work up.
