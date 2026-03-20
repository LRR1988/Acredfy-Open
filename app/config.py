"""
Acredfy — configuration module.

Centralises paths, constants and first-run defaults so every other module
can simply ``from app.config import …``.
"""

import os
import sys
import shutil

# ── App metadata ──────────────────────────────────────────────────────────────

APP_NAME = "Acredfy"
APP_VERSION = "4.0.0"

# ── License server ────────────────────────────────────────────────────────────

API_BASE_URL = "https://acredfy.com/api/v1"
LICENSE_CACHE_DAYS = 7  # days the license token is valid offline

# ── Directory layout ──────────────────────────────────────────────────────────

FROZEN = getattr(sys, "frozen", False)

# %APPDATA%\Acredfy\  (e.g. C:\Users\<user>\AppData\Roaming\Acredfy)
APPDATA_DIR = os.path.join(os.path.expandvars("%APPDATA%"), APP_NAME)

# Where the *original* script tree lives (repo root / extracted folder).
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Runtime data (policies, sites, accesos, auth token).
#   - Frozen build  → APPDATA_DIR  (writeable, survives updates)
#   - Dev / source  → SCRIPT_DIR   (repo root, next to Acredfy.pyw)
DATA_DIR = APPDATA_DIR if FROZEN else SCRIPT_DIR

# Bundled read-only assets (images, default JSON files).
#   - Frozen build  → sys._MEIPASS  (PyInstaller temp folder)
#   - Dev / source  → SCRIPT_DIR
BUNDLE_DIR = getattr(sys, "_MEIPASS", SCRIPT_DIR) if FROZEN else SCRIPT_DIR

# ── Data file paths (read/write) ─────────────────────────────────────────────

POLICIES_FILE = os.path.join(DATA_DIR, "policies.json")
SITES_FILE = os.path.join(DATA_DIR, "sites.json")
ACCESSES_FILE = os.path.join(DATA_DIR, "accesos.json")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
UPDATE_STATE_FILE = os.path.join(DATA_DIR, "update_state.json")

# ── Default / seed files shipped inside the bundle ────────────────────────────
# Frozen builds flatten everything under _MEIPASS, so defaults live at
#   <BUNDLE_DIR>/defaults/
# In a source checkout the same files sit under
#   <BUNDLE_DIR>/app/defaults/

_DEFAULTS_DIR = (
    os.path.join(BUNDLE_DIR, "defaults")
    if FROZEN
    else os.path.join(BUNDLE_DIR, "app", "defaults")
)

DEFAULT_SITES_FILE = os.path.join(_DEFAULTS_DIR, "sites.json")
DEFAULT_ACCESSES_FILE = os.path.join(_DEFAULTS_DIR, "accesos.json")


# ── Helpers ───────────────────────────────────────────────────────────────────

def ensure_data_dir() -> None:
    """Create APPDATA_DIR if it doesn't exist and seed it with default files.

    Safe to call multiple times — existing files are never overwritten.
    """
    os.makedirs(APPDATA_DIR, exist_ok=True)

    for src, dst in (
        (DEFAULT_SITES_FILE, SITES_FILE),
        (DEFAULT_ACCESSES_FILE, ACCESSES_FILE),
    ):
        if not os.path.exists(dst) and os.path.exists(src):
            shutil.copy2(src, dst)
