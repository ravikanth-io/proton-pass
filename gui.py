# smartpass/gui.py
# SmartPass GUI with Vault integration, settings, auto-save suggestions

import sys
import typing
import os
from functools import partial

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QClipboard
from PySide6.QtWidgets import (
    QApplication, QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QLineEdit, QPushButton, QSpinBox, QCheckBox, QTextEdit, QGroupBox,
    QGridLayout, QMessageBox, QInputDialog, QListWidget, QDialog, QDialogButtonBox
)

# evaluator/generator
try:
    from smartpass.evaluator import score_password, SYMBOLS
except Exception:
    from smartpass.score import score_password  # type: ignore
    SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"

from smartpass.generator import generate
from smartpass.config import load_config, save_config
from smartpass.vault import (
    create_vault, add_entry, list_entries, remove_entry, default_vault_path
)

# Use config values
CFG = load_config()
DEFAULT_CLEAR_CLIP_SECONDS = int(CFG.get("clipboard_clear_seconds", 20))
DEFAULT_VAULT_PATH = CFG.get("vault_path") or default_vault_path()

# ---------------- UI building helpers ----------------

def make_generator_group():
    box = QGroupBox("Generator")
    layout = QGridLayout()
    box.setLayout(layout)

    lbl_len = QLabel("Length:")
    spin_len = QSpinBox()
    spin_len.setRange(4, 128)
    spin_len.setValue(16)

    chk_upper = QCheckBox("Uppercase")
    chk_upper.setChecked(True)
    chk_lower = QCheckBox("Lowercase")
    chk_lower.setChecked(True)
    chk_digits = QCheckBox("Digits")
    chk_digits.setChecked(True)
    chk_symbols = QCheckBox("Symbols")
    chk_symbols.setChecked(True)

    btn_generate = QPushButton("Generate")
    txt_generated = QLineEdit()
    txt_generated.setReadOnly(True)

    btn_copy = QPushButton("Copy (auto-clear)")
    btn_save_vault = QPushButton("Save to Vault")
    btn_save_quick = QPushButton("Save (suggested name)")
    btn_manage_vault = QPushButton("Manage Vault")
    btn_settings = QPushButton("Settings")

    layout.addWidget(lbl_len, 0, 0)
    layout.addWidget(spin_len, 0, 1)
    layout.addWidget(chk_upper, 1, 0)
    layout.addWidget(chk_lower, 1, 1)
    layout.addWidget(chk_digits, 2, 0)
    layout.addWidget(chk_symbols, 2, 1)
    layout.addWidget(btn_generate, 3, 0)
    layout.addWidget(btn_copy, 3, 1)
    layout.addWidget(btn_save_vault, 4, 0)
    layout.addWidget(btn_save_quick, 4, 1)
    layout.addWidget(btn_manage_vault, 5, 0)
    layout.addWidget(btn_settings, 5, 1)
    layout.addWidget(txt_generated, 6, 0, 1, 2)

    return {
        "widget": box,
        "spin_len": spin_len,
        "chk_upper": chk_upper,
        "chk_lower": chk_lower,
        "chk_digits": chk_digits,
        "chk_symbols": chk_symbols,
        "btn_generate": btn_generate,
        "txt_generated": txt_generated,
        "btn_copy": btn_copy,
        "btn_save_vault": btn_save_vault,
        "btn_save_quick": btn_save_quick,
        "btn_manage_vault": btn_manage_vault,
        "btn_settings": btn_settings,
    }


def make_evaluator_group():
    box = QGroupBox("Evaluator")
    layout = QVBoxLayout()
    box.setLayout(layout)

    lbl_input = QLabel("Type or paste a password (live evaluation):")
    input_pw = QLineEdit()
    input_pw.setEchoMode(QLineEdit.Normal)

    lbl_score = QLabel("Score: N/A")
    lbl_label = QLabel("Strength: N/A")
    txt_explanations = QTextEdit()
    txt_explanations.setReadOnly(True)
    txt_explanations.setMaximumHeight(200)

    layout.addWidget(lbl_input)
    layout.addWidget(input_pw)
    layout.addWidget(lbl_score)
    layout.addWidget(lbl_label)
    layout.addWidget(QLabel("Detections / Suggestions:"))
    layout.addWidget(txt_explanations)

    return {
        "widget": box,
        "input_pw": input_pw,
        "lbl_score": lbl_score,
        "lbl_label": lbl_label,
        "txt_explanations": txt_explanations
    }


class VaultListDialog(QDialog):
    def __init__(self, parent=None, vault_path=None, master_password=None):
        super().__init__(parent)
        self.setWindowTitle("Vault Entries")
        self.setMinimumSize(600, 400)
        self.vault_path = vault_path
        self.master_password = master_password

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.list_widget = QListWidget()
        self.layout.addWidget(self.list_widget)

        btns = QDialogButtonBox()
        self.btn_copy = QPushButton("Copy Password")
        self.btn_remove = QPushButton("Remove Entry")
        self.btn_close = QPushButton("Close")
        btns.addButton(self.btn_copy, QDialogButtonBox.ActionRole)
        btns.addButton(self.btn_remove, QDialogButtonBox.ActionRole)
        btns.addButton(self.btn_close, QDialogButtonBox.RejectRole)
        self.layout.addWidget(btns)

        self.btn_copy.clicked.connect(self.on_copy)
        self.btn_remove.clicked.connect(self.on_remove)
        self.btn_close.clicked.connect(self.close)

        self.populate()

    def populate(self):
        try:
            entries = list_entries(self.master_password, self.vault_path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open vault: {e}")
            self.reject()
            return
        self.entries = entries
        self.list_widget.clear()
        for i, e in enumerate(entries):
            name = e.get("name", "")
            user = e.get("username", "")
            notes = (e.get("notes") or "")[:60]
            display = f"[{i}] {name} — {user} — {notes}"
            self.list_widget.addItem(display)

    def on_copy(self):
        idx = self.list_widget.currentRow()
        if idx < 0:
            QMessageBox.information(self, "Select", "Please select an entry first.")
            return
        entry = self.entries[idx]
        pw = entry.get("password", "")
        if not pw:
            QMessageBox.information(self, "No password", "Selected entry has no password.")
            return
        try:
            cb = QApplication.clipboard()
            cb.setText(pw, mode=QClipboard.Clipboard)
            QMessageBox.information(self, "Copied", "Password copied to clipboard.")
        except Exception:
            QMessageBox.warning(self, "Clipboard", "Could not copy to clipboard.")

    def on_remove(self):
        idx = self.list_widget.currentRow()
        if idx < 0:
            QMessageBox.information(self, "Select", "Please select an entry first.")
            return
        confirm = QMessageBox.question(self, "Remove", f"Remove entry #{idx}? This cannot be undone.")
        if confirm != QMessageBox.Yes:
            return
        try:
            remove_entry(self.master_password, idx, self.vault_path)
            QMessageBox.information(self, "Removed", "Entry removed.")
            self.populate()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove: {e}")


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumSize(400, 180)
        cfg = load_config()
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.spin_clip = QSpinBox()
        self.spin_clip.setRange(2, 600)
        self.spin_clip.setValue(int(cfg.get("clipboard_clear_seconds", DEFAULT_CLEAR_CLIP_SECONDS)))

        self.input_vault = QLineEdit()
        self.input_vault.setText(cfg.get("vault_path") or "")

        self.layout.addWidget(QLabel("Clipboard auto-clear (seconds):"))
        self.layout.addWidget(self.spin_clip)
        self.layout.addWidget(QLabel("Vault file path (leave blank for default):"))
        self.layout.addWidget(self.input_vault)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.layout.addWidget(btns)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

    def values(self):
        return {"clipboard_clear_seconds": int(self.spin_clip.value()), "vault_path": self.input_vault.text() or None}


class SmartPassGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SmartPass — Generator & Evaluator")
        self.setMinimumSize(920, 460)
        self.clip_timer: typing.Optional[QTimer] = None

        # read config
        self.cfg = load_config()
        self.vault_path = self.cfg.get("vault_path") or default_vault_path()
        self.clip_clear_seconds = int(self.cfg.get("clipboard_clear_seconds", DEFAULT_CLEAR_CLIP_SECONDS))

        # build UI
        main = QHBoxLayout()
        self.setLayout(main)

        gen = make_generator_group()
        evalg = make_evaluator_group()

        main.addWidget(gen["widget"], 1)
        main.addWidget(evalg["widget"], 1)

        # Wire up generator controls
        gen["btn_generate"].clicked.connect(partial(self.on_generate_click, gen, evalg))
        gen["btn_copy"].clicked.connect(partial(self.on_copy_generated, gen))
        gen["btn_save_vault"].clicked.connect(partial(self.on_save_to_vault, gen))
        gen["btn_save_quick"].clicked.connect(partial(self.on_save_quick, gen))
        gen["btn_manage_vault"].clicked.connect(self.on_manage_vault)
        gen["btn_settings"].clicked.connect(self.on_settings)

        # Wire up evaluator input
        evalg["input_pw"].textChanged.connect(partial(self.on_password_changed, evalg))

        # store references
        self.gen = gen
        self.evalg = evalg

    # ----------------- Generator actions -----------------
    def on_generate_click(self, gen, evalg):
        length = gen["spin_len"].value()
        use_upper = gen["chk_upper"].isChecked()
        use_lower = gen["chk_lower"].isChecked()
        use_digits = gen["chk_digits"].isChecked()
        use_symbols = gen["chk_symbols"].isChecked()
        try:
            pw = generate(
                length=length,
                use_upper=use_upper,
                use_lower=use_lower,
                use_digits=use_digits,
                use_symbols=use_symbols,
            )
            gen["txt_generated"].setText(pw)
            # place generated into evaluator input for convenience
            evalg["input_pw"].setText(pw)
        except Exception as e:
            gen["txt_generated"].setText(f"Error: {e}")

    def on_copy_generated(self, gen):
        pw = gen["txt_generated"].text()
        if not pw:
            return
        try:
            clipboard: QClipboard = QApplication.clipboard()
            clipboard.setText(pw, mode=QClipboard.Clipboard)
            clipboard.setText(pw, mode=QClipboard.Selection)
        except Exception:
            pass

        btn = gen["btn_copy"]
        old_text = btn.text()
        btn.setText("Copied ✓")
        btn.setEnabled(False)
        QTimer.singleShot(1500, lambda: (btn.setText(old_text), btn.setEnabled(True)))

        # setup timer to clear clipboard using current config
        self.start_clipboard_clear_timer(self.clip_clear_seconds)

    # ----------------- Save flows -----------------
    def on_save_to_vault(self, gen):
        pw = gen["txt_generated"].text()
        if not pw:
            QMessageBox.information(self, "No password", "Generate or paste a password first.")
            return

        master, ok = QInputDialog.getText(self, "Vault master", "Enter vault master password (will create vault if missing):", QLineEdit.Password)
        if not ok or master == "":
            return

        # create vault if can't be opened
        try:
            try:
                _ = list_entries(master, self.vault_path)
            except Exception:
                create_vault(master, self.vault_path)
        except Exception as e:
            QMessageBox.critical(self, "Vault error", f"Could not create/open vault: {e}")
            return

        name, ok = QInputDialog.getText(self, "Entry name", "Entry name (e.g., site):")
        if not ok or name == "":
            return
        username, ok = QInputDialog.getText(self, "Username", "Username for entry (optional):")
        if not ok:
            username = ""
        notes, ok = QInputDialog.getMultiLineText(self, "Notes", "Optional notes:")
        if not ok:
            notes = ""

        entry = {"name": name, "username": username, "password": pw, "notes": notes}
        try:
            add_entry(master, entry, self.vault_path)
            QMessageBox.information(self, "Saved", f"Entry '{name}' added to vault.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add entry: {e}")

    def on_save_quick(self, gen):
        """
        Save generated password with suggested name: uses first 6 chars of pw + timestamp as name,
        or 'generated-<timestamp>' if pw not suitable.
        """
        pw = gen["txt_generated"].text()
        if not pw:
            QMessageBox.information(self, "No password", "Generate or paste a password first.")
            return
        # suggested name
        cleaned = "".join(ch for ch in pw if ch.isalnum())
        suggested = (cleaned[:6] if cleaned else "generated") + "-" + str(abs(hash(pw)))[:6]
        master, ok = QInputDialog.getText(self, "Vault master", "Enter vault master password (will create vault if missing):", QLineEdit.Password)
        if not ok or master == "":
            return
        try:
            try:
                _ = list_entries(master, self.vault_path)
            except Exception:
                create_vault(master, self.vault_path)
        except Exception as e:
            QMessageBox.critical(self, "Vault error", f"Could not create/open vault: {e}")
            return

        # ask only for username (name uses suggested)
        username, ok = QInputDialog.getText(self, "Username", f"Username for entry (optional):")
        if not ok:
            username = ""
        entry = {"name": suggested, "username": username, "password": pw, "notes": "Saved via GUI quick-save"}
        try:
            add_entry(master, entry, self.vault_path)
            QMessageBox.information(self, "Saved", f"Entry '{suggested}' added to vault.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add entry: {e}")

    def on_manage_vault(self):
        master, ok = QInputDialog.getText(self, "Vault master", "Enter vault master password:", QLineEdit.Password)
        if not ok or master == "":
            return
        dlg = VaultListDialog(self, vault_path=self.vault_path, master_password=master)
        dlg.exec()

    # ----------------- Settings -----------------
    def on_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        vals = dlg.values()
        self.cfg.update(vals)
        save_config(self.cfg)
        # apply live
        self.clip_clear_seconds = int(self.cfg.get("clipboard_clear_seconds", DEFAULT_CLEAR_CLIP_SECONDS))
        self.vault_path = self.cfg.get("vault_path") or default_vault_path()
        QMessageBox.information(self, "Saved", "Settings saved.")

    # ----------------- Clipboard -----------------
    def start_clipboard_clear_timer(self, seconds: int):
        if self.clip_timer and self.clip_timer.isActive():
            self.clip_timer.stop()
        self.clip_timer = QTimer(self)
        self.clip_timer.setSingleShot(True)
        self.clip_timer.timeout.connect(self.clear_clipboard)
        self.clip_timer.start(seconds * 1000)

    def clear_clipboard(self):
        try:
            clipboard: QClipboard = QApplication.clipboard()
            clipboard.setText("", mode=QClipboard.Clipboard)
            clipboard.setText("", mode=QClipboard.Selection)
        except Exception:
            pass

    # ----------------- Evaluator -----------------
    def on_password_changed(self, evalg, text: str):
        pw = text
        if pw == "":
            evalg["lbl_score"].setText("Score: N/A")
            evalg["lbl_label"].setText("Strength: N/A")
            evalg["txt_explanations"].setPlainText("")
            return

        try:
            result = score_password(pw)
        except Exception:
            try:
                from smartpass.score import score_password as simple_score
                result = simple_score(pw)
                result = {
                    "entropy": None,
                    "penalty": None,
                    "final_bits": None,
                    "score": result.get("score", 0) * 20,
                    "label": result.get("label", ""),
                    "explanations": []
                }
            except Exception:
                evalg["lbl_score"].setText("Score: error")
                evalg["lbl_label"].setText("Strength: error")
                evalg["txt_explanations"].setPlainText("Evaluator error")
                return

        sc = result.get("score", 0)
        if isinstance(sc, int) and sc <= 5:
            sc_display = int(min(100, round((sc / 5.0) * 100)))
        else:
            try:
                sc_display = int(result.get("score", 0))
            except Exception:
                sc_display = 0

        evalg["lbl_score"].setText(f"Score: {sc_display} / 100")
        evalg["lbl_label"].setText(f"Strength: {result.get('label','')}")
        lines = []
        exps = result.get("explanations") or []
        for e in exps:
            lines.append("• " + e)
        suggs = result.get("suggestions") or []
        for s in suggs:
            lines.append("• " + s)
        evalg["txt_explanations"].setPlainText("\n".join(lines))


def main():
    app = QApplication(sys.argv)
    gui = SmartPassGUI()
    gui.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
