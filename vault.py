"""
smartpass.vault
Argon2id KDF + AES-GCM encrypted local vault.
"""

import os
import json
import base64
from typing import Any, Dict, Optional, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level
from .storage import atomic_write_bytes, atomic_read_bytes, default_vault_path, ensure_dir_exists, dump_json_bytes, read_json_bytes

# Default KDF params (tunable). Balance security/performance.
DEFAULT_KDF_PARAMS = {
    "time_cost": 3,        # iterations
    "memory_cost_kb": 65536,  # 64 MB
    "parallelism": 2,
    "hash_len": 32
}

VAULT_VERSION = 1

def _derive_key(password: str, salt: bytes, params: Dict[str, int]) -> bytes:
    """
    Derive a raw key using Argon2id low-level API.
    """
    return low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=int(params.get("time_cost", DEFAULT_KDF_PARAMS["time_cost"])),
        memory_cost=int(params.get("memory_cost_kb", DEFAULT_KDF_PARAMS["memory_cost_kb"])),
        parallelism=int(params.get("parallelism", DEFAULT_KDF_PARAMS["parallelism"])),
        hash_len=int(params.get("hash_len", DEFAULT_KDF_PARAMS["hash_len"])),
        type=low_level.Type.ID
    )

def create_vault(master_password: str, path: Optional[str] = None, kdf_params: Optional[Dict[str,int]] = None) -> str:
    """
    Create a new empty vault and save to path. Returns path used.
    """
    if path is None:
        path = default_vault_path()
    kdf = kdf_params or DEFAULT_KDF_PARAMS.copy()
    salt = os.urandom(16)
    key = _derive_key(master_password, salt, kdf)
    # empty plaintext structure
    plaintext = {"entries": []}
    plaintext_bytes = dump_json_bytes(plaintext)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)  # associated data None
    wrapper = {
        "version": VAULT_VERSION,
        "kdf": {
            "type": "argon2id",
            "time_cost": kdf["time_cost"],
            "memory_cost_kb": kdf["memory_cost_kb"],
            "parallelism": kdf["parallelism"],
            "salt": base64.b64encode(salt).decode("ascii")
        },
        "cipher": {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii")
        }
    }
    atomic_write_bytes(path, dump_json_bytes(wrapper))
    return path

def _load_wrapper(path: str) -> Dict[str, Any]:
    raw = atomic_read_bytes(path)
    return read_json_bytes(raw)

def open_vault(master_password: str, path: Optional[str] = None) -> Dict[str, Any]:
    """
    Decrypt and return the vault plaintext dict (e.g., {"entries":[...]})
    Raises ValueError on incorrect password or corrupted vault.
    """
    if path is None:
        path = default_vault_path()
    wrapper = _load_wrapper(path)
    kdf = wrapper.get("kdf", {})
    salt_b64 = kdf.get("salt")
    if not salt_b64:
        raise ValueError("Invalid vault format: missing salt")
    salt = base64.b64decode(salt_b64)
    params = {
        "time_cost": kdf.get("time_cost", DEFAULT_KDF_PARAMS["time_cost"]),
        "memory_cost_kb": kdf.get("memory_cost_kb", DEFAULT_KDF_PARAMS["memory_cost_kb"]),
        "parallelism": kdf.get("parallelism", DEFAULT_KDF_PARAMS["parallelism"]),
        "hash_len": DEFAULT_KDF_PARAMS["hash_len"]
    }
    key = _derive_key(master_password, salt, params)
    # decrypt
    cipher = wrapper.get("cipher", {})
    nonce = base64.b64decode(cipher.get("nonce", ""))
    ciphertext = base64.b64decode(cipher.get("ciphertext", ""))
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        # Could be wrong password, tampered ciphertext, or bad params
        raise ValueError("Incorrect master password or corrupted vault") from e
    return json.loads(plaintext_bytes.decode("utf-8"))

def save_vault(master_password: str, data: Dict[str, Any], path: Optional[str] = None, kdf_params: Optional[Dict[str,int]] = None) -> str:
    """
    Encrypt the provided plaintext dict and write to path atomically.
    """
    if path is None:
        path = default_vault_path()
    kdf = kdf_params or DEFAULT_KDF_PARAMS.copy()
    salt = os.urandom(16)
    key = _derive_key(master_password, salt, kdf)
    plaintext_bytes = dump_json_bytes(data)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    wrapper = {
        "version": VAULT_VERSION,
        "kdf": {
            "type": "argon2id",
            "time_cost": kdf["time_cost"],
            "memory_cost_kb": kdf["memory_cost_kb"],
            "parallelism": kdf["parallelism"],
            "salt": base64.b64encode(salt).decode("ascii")
        },
        "cipher": {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii")
        }
    }
    atomic_write_bytes(path, dump_json_bytes(wrapper))
    return path

# High-level helpers for entries
def add_entry(master_password: str, entry: Dict[str,str], path: Optional[str] = None) -> None:
    data = open_vault(master_password, path)
    entries: List[Dict[str,str]] = data.get("entries", [])
    entries.append(entry)
    data["entries"] = entries
    save_vault(master_password, data, path)

def list_entries(master_password: str, path: Optional[str] = None) -> List[Dict[str,str]]:
    data = open_vault(master_password, path)
    return data.get("entries", [])

def remove_entry(master_password: str, index: int, path: Optional[str] = None) -> None:
    data = open_vault(master_password, path)
    entries: List[Dict[str,str]] = data.get("entries", [])
    if index < 0 or index >= len(entries):
        raise IndexError("Entry index out of range")
    del entries[index]
    data["entries"] = entries
    save_vault(master_password, data, path)
