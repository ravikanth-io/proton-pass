import os
import shutil
import json
from typing import Optional

def ensure_dir_exists(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def atomic_write_bytes(path: str, data: bytes) -> None:
    """
    Atomically write bytes to 'path' by writing to a temp file and renaming.
    """
    ensure_dir_exists(path)
    tmp = path + ".tmp"
    # write binary
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    # atomic replace
    os.replace(tmp, path)

def atomic_read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()
    

def copy_file_atomic(src: str, dst: str) -> None:
    ensure_dir_exists(dst)
    tmp = dst + ".tmp"
    shutil.copyfile(src, tmp)
    os.replace(tmp, dst)


def default_vault_path() -> str:
    """
    Recommend Windows %APPDATA% location; fallback to user profile .smartpass.
    """
    appdata = os.getenv("APPDATA")
    if appdata:
        d = os.path.join(appdata, "SmartPass")
        return os.path.join(d, "vault.bin")
    # fallback
    home = os.path.expanduser("~")
    return os.path.join(home, ".smartpass", "vault.bin")

def read_json_bytes(b: bytes) -> dict:
    return json.loads(b.decode("utf-8"))

def dump_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=None).encode("utf-8")
