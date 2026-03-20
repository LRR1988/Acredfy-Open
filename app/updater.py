"""
Acredfy — Auto-update module.
Handles version checks, data file merging (sites/accesos), and app updates.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile

from . import config
from .auth import _get_authenticated, LicenseError


def version_gt(a: str, b: str) -> bool:
    """Return True if version a > version b. Simple semver comparison."""
    try:
        va = tuple(int(x) for x in a.split("."))
        vb = tuple(int(x) for x in b.split("."))
        return va > vb
    except (ValueError, AttributeError):
        return False


def check_for_updates() -> dict | None:
    """Check server for updates. Returns response dict or None on error."""
    try:
        return _get_authenticated("updates/check")
    except Exception:
        return None


def _load_update_state() -> dict:
    """Load last-known server hashes."""
    if os.path.isfile(config.UPDATE_STATE_FILE):
        try:
            with open(config.UPDATE_STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"sites_hash": "", "accesos_hash": ""}


def _save_update_state(state: dict) -> None:
    """Save server hashes after successful sync."""
    with open(config.UPDATE_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def merge_sites(server_sites: list, local_sites: list) -> tuple[list, int]:
    """Merge server sites into local sites. Returns (merged_list, new_count).
    Adds server entries not already in local. Never removes local entries."""
    local_lower = {s.strip().lower() for s in local_sites}
    new_entries = []
    for site in server_sites:
        if site.strip().lower() not in local_lower:
            new_entries.append(site)
    return local_sites + new_entries, len(new_entries)


def merge_accesos(server_accesos: list, local_accesos: list) -> tuple[list, int]:
    """Merge server accesos into local accesos. Returns (merged_list, new_count).
    Merge key is URL (case-insensitive). Never removes local entries."""
    local_urls = {a.get("url", "").strip().lower() for a in local_accesos}
    new_entries = []
    for acc in server_accesos:
        if acc.get("url", "").strip().lower() not in local_urls:
            new_entries.append(acc)
    return local_accesos + new_entries, len(new_entries)


def apply_data_updates(check_result: dict) -> dict:
    """Compare server hashes with stored state. Download and merge if changed.
    Returns {sites_updated, accesos_updated, new_sites_count, new_accesos_count}."""
    state = _load_update_state()
    result = {"sites_updated": False, "accesos_updated": False,
              "new_sites_count": 0, "new_accesos_count": 0}

    # Check sites
    server_sites_hash = check_result.get("sites_hash", "")
    if server_sites_hash and server_sites_hash != state.get("sites_hash", ""):
        try:
            server_sites = _get_authenticated("updates/sites")
            if isinstance(server_sites, list):
                # Load local sites
                local_sites = []
                if os.path.isfile(config.SITES_FILE):
                    with open(config.SITES_FILE, "r", encoding="utf-8") as f:
                        local_sites = json.load(f)

                merged, new_count = merge_sites(server_sites, local_sites)
                if new_count > 0:
                    with open(config.SITES_FILE, "w", encoding="utf-8") as f:
                        json.dump(merged, f, ensure_ascii=False, indent=2)
                    result["sites_updated"] = True
                    result["new_sites_count"] = new_count

                state["sites_hash"] = server_sites_hash
        except Exception:
            pass

    # Check accesos
    server_accesos_hash = check_result.get("accesos_hash", "")
    if server_accesos_hash and server_accesos_hash != state.get("accesos_hash", ""):
        try:
            server_accesos = _get_authenticated("updates/accesos")
            if isinstance(server_accesos, list):
                local_accesos = []
                if os.path.isfile(config.ACCESSES_FILE):
                    with open(config.ACCESSES_FILE, "r", encoding="utf-8") as f:
                        local_accesos = json.load(f)

                merged, new_count = merge_accesos(server_accesos, local_accesos)
                if new_count > 0:
                    with open(config.ACCESSES_FILE, "w", encoding="utf-8") as f:
                        json.dump(merged, f, ensure_ascii=False, indent=2)
                    result["accesos_updated"] = True
                    result["new_accesos_count"] = new_count

                state["accesos_hash"] = server_accesos_hash
        except Exception:
            pass

    _save_update_state(state)
    return result


def download_installer(download_url: str, progress_callback=None) -> str:
    """Download installer to temp dir. Returns path to downloaded file."""
    import requests
    dest = os.path.join(tempfile.gettempdir(), "AcredfySetup.exe")
    resp = requests.get(download_url, stream=True, timeout=300)
    resp.raise_for_status()
    total = int(resp.headers.get("content-length", 0))
    downloaded = 0
    with open(dest, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
            downloaded += len(chunk)
            if progress_callback and total:
                progress_callback(downloaded, total)
    return dest


def launch_installer_and_exit(installer_path: str) -> None:
    """Launch installer silently and kill the app.
    /VERYSILENT = no UI. skipifsilent in .iss = won't relaunch app.
    os._exit = no PyInstaller _MEI cleanup (avoids DLL conflict)."""
    import time
    subprocess.Popen(
        [installer_path, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/CLOSEAPPLICATIONS"],
        creationflags=subprocess.DETACHED_PROCESS,
    )
    time.sleep(2)
    os._exit(0)
