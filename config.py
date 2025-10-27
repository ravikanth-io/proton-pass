# smartpass/config.py
"""
Simple settings persistence for SmartPass.
Settings saved as JSON in %APPDATA%/SmartPass/config.json (Windows) or ~/.smartpass/config.json (fallback)
"""

import os
import json
from typing import Dict, Any

DEFAULTS: Dict[str, Any] = {
    "clipboard_clear_seconds": 20,
    "vault_path": None  # if None, vault.default_vault_path() should be used
}

def _appdata_dir() -> str:
    appdata = os.getenv("APPDATA")
    if appdata:
        d = os.path.join(appdata, "SmartPass")
    else:
        d = os.path.join(os.path.expanduser("~"), ".smartpass")
    os.makedirs(d, exist_ok=True)
    return d

def config_path() -> str:
    return os.path.join(_appdata_dir(), "config.json")

def load_config() -> Dict[str, Any]:
    p = config_path()
    if not os.path.exists(p):
        return DEFAULTS.copy()
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            # merge defaults
            out = DEFAULTS.copy()
            out.update(data or {})
            return out
    except Exception:
        return DEFAULTS.copy()

def save_config(cfg: Dict[str, Any]) -> None:
    p = config_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
