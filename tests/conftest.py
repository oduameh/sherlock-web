"""Test-session environment.

`app` runs its DB setup at import time, so the database path must be decided
before any test imports it. Every session gets a fresh temporary SQLite file;
the developer's real history.db is never touched by the suite.
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="sherlock-web-tests-")
os.environ.setdefault("SHERLOCK_DB_PATH", os.path.join(_TMP, "history.db"))
# Deterministic, offline site list (the default; stated here for clarity).
os.environ.setdefault("SHERLOCK_SITES_SOURCE", "bundled")
# One investigation at a time makes the "queued" behaviour testable.
os.environ.setdefault("RECON_MAX_CONCURRENT_INVESTIGATIONS", "1")
