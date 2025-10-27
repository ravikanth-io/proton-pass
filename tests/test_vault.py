import os
import tempfile
import json
import base64
from smartpass.vault import create_vault, open_vault, add_entry, list_entries, remove_entry
from smartpass.storage import atomic_read_bytes, read_json_bytes

def test_vault_create_and_open():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "vault.bin")
        master = "CorrectHorseBatteryStaple!23"
        create_vault(master, path)
        data = open_vault(master, path)
        assert isinstance(data, dict)
        assert "entries" in data
        assert data["entries"] == []

def test_vault_add_list_remove():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "vault.bin")
        master = "S3cureMaster!"
        create_vault(master, path)
        add_entry(master, {"name":"ex","username":"u","password":"p"}, path)
        entries = list_entries(master, path)
        assert len(entries) == 1
        assert entries[0]["name"] == "ex"
        # remove
        remove_entry(master, 0, path)
        entries2 = list_entries(master, path)
        assert len(entries2) == 0

def test_wrong_password_fails():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "vault.bin")
        create_vault("abc123!", path)
        try:
            open_vault("wrongpass", path)
            ok = True
        except Exception:
            ok = False
        assert not ok

def test_tamper_detection():
    # tamper with ciphertext and expect failure
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "vault.bin")
        master = "TamperTest!"
        create_vault(master, path)
        # read raw wrapper bytes and modify ciphertext
        raw = atomic_read_bytes(path)
        j = read_json_bytes(raw)
        # change a byte in ciphertext
        ct_b64 = j["cipher"]["ciphertext"]
        ct = bytearray(base64.b64decode(ct_b64))
        if len(ct) > 0:
            ct[0] ^= 0xFF
        j["cipher"]["ciphertext"] = base64.b64encode(bytes(ct)).decode("ascii")
        # write tampered file
        with open(path, "wb") as f:
            f.write(json.dumps(j).encode("utf-8"))
        # now open should fail
        try:
            open_vault(master, path)
            ok = True
        except Exception:
            ok = False
        assert not ok
