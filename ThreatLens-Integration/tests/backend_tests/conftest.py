"""
Shared pytest configuration for the backend test suites.

`app.database.database` reads DATABASE_URL **at import time** and binds one
engine for the life of the process. Any test module that sets the variable in
its own module body therefore only wins if it happens to be imported first,
which makes results depend on collection order (running test_threat_api.py
before test_alerts.py used to produce 13 failures).

pytest imports conftest.py before every test module in its directory, so this
is the one place the environment can be fixed deterministically.
"""

import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_threatlens.db")
os.environ.setdefault("ALERT_INGEST_API_KEY", "test-key")
