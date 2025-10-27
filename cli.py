"""CLI for SmartPass — generate, score, vault (create/add/list/remove/export/import/changepw)."""

import argparse
from rich import print
from rich.panel import Panel
from rich.table import Table
from getpass import getpass
import shutil
import os

from .generator import generate

from .evaluator import score_password
from .suggestions import suggest_improvements
from .vault import (
    create_vault,
    add_entry,
    list_entries,
    remove_entry,
    default_vault_path,
    open_vault,
    save_vault,
)
from .storage import atomic_read_bytes, default_vault_path as storage_default_vault_path

def cmd_generate(args):
    for i in range(args.copies):
        pw = generate(
            length=args.length,
            use_symbols=not args.no_symbols,
            use_upper=not args.no_upper,
            use_lower=not args.no_lower,
            use_digits=not args.no_digits,
        )
        print(f"[bold green]Password #{i+1}:[/bold green] {pw}")

def cmd_score(args):
    pw = args.password
    result = score_password(pw)
    sugg = suggest_improvements(pw)
    header = f"Score: {result['score']} / 100 — {result['label']}"
    body = (
        f"Estimated entropy: {result['entropy']:.1f} bits\n"
        f"Penalty: {result['penalty']:.1f} bits\n"
        f"Final entropy: {result['final_bits']:.1f} bits\n"
    )
    print(Panel(body, title=header))
    if result["explanations"]:
        print("[bold]Detections:[/bold]")
        for e in result["explanations"]:
            print(f" • {e}")
    if sugg["suggestions"]:
        print("\n[bold]Suggestions:[/bold]")
        # dedupe suggestions while preserving order
        seen = set()
        for s in sugg["suggestions"]:
            if s not in seen:
                print(f" • {s}")
                seen.add(s)
    if sugg["examples"]:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Example stronger password")
        for ex in sugg["examples"]:
            table.add_row(ex)
        print("\n")
        print(table)

# Vault subcommands

def cmd_vault_create(args):
    path = args.file or default_vault_path()
    master = getpass("Enter new master password: ")
    confirm = getpass("Confirm master password: ")
    if master != confirm:
        print("[red]Master password mismatch — aborting.[/red]")
        return
    create_vault(master, path)
    print(f"[green]Created vault at:[/green] {path}")

def cmd_vault_add(args):
    path = args.file or default_vault_path()
    master = getpass("Vault master password: ")
    name = args.name or input("Entry name (e.g., site): ")
    username = args.username or input("Username: ")
    password = args.password or getpass("Password (input hidden): ")
    notes = args.notes or ""
    entry = {"name": name, "username": username, "password": password, "notes": notes}
    try:
        add_entry(master, entry, path)
        print("[green]Entry added to vault.[/green]")
    except Exception as e:
        print(f"[red]Failed to add entry: {e}[/red]")

def cmd_vault_list(args):
    path = args.file or default_vault_path()
    master = getpass("Vault master password: ")
    try:
        entries = list_entries(master, path)
    except Exception as e:
        print(f"[red]Failed to open vault: {e}[/red]")
        return
    if not entries:
        print("[yellow]Vault is empty.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", width=4)
    table.add_column("Name")
    table.add_column("Username")
    table.add_column("Notes")
    for i, e in enumerate(entries):
        table.add_row(str(i), e.get("name", ""), e.get("username", ""), (e.get("notes") or "")[:40])
    print(table)

def cmd_vault_remove(args):
    path = args.file or default_vault_path()
    master = getpass("Vault master password: ")
    idx = args.index
    try:
        remove_entry(master, idx, path)
        print("[green]Removed entry.[/green]")
    except Exception as e:
        print(f"[red]Failed to remove entry: {e}[/red]")

# New: export & import and change-master

def cmd_vault_export(args):
    """Export vault file (encrypted) to a backup path. This copies the encrypted file as-is."""
    path = args.file or default_vault_path()
    out = args.output or os.path.join(os.getcwd(), "vault-backup.bin")
    try:
        if not os.path.exists(path):
            print(f"[red]Vault not found at {path}[/red]")
            return
        # atomic copy
        shutil.copyfile(path, out)
        print(f"[green]Exported vault to:[/green] {out}")
        print("[yellow]Note: exported file remains encrypted; protect the backup file.[/yellow]")
    except Exception as e:
        print(f"[red]Failed to export vault: {e}[/red]")

def cmd_vault_import(args):
    """Import an encrypted vault backup by replacing current vault file after confirmation."""
    path = args.file or default_vault_path()
    src = args.input
    if not src:
        print("[red]Please provide --input path to the backup file.[/red]")
        return
    if not os.path.exists(src):
        print(f"[red]Import file not found: {src}[/red]")
        return
    confirm = input(f"Importing will overwrite the vault at {path}. Continue? (yes/NO): ")
    if confirm.lower() != "yes":
        print("Aborted.")
        return
    try:
        shutil.copyfile(src, path)
        print(f"[green]Imported vault from {src} to {path}[/green]")
    except Exception as e:
        print(f"[red]Failed to import: {e}[/red]")

def cmd_vault_changepw(args):
    """Change the master password: decrypt using old password then re-encrypt with new password."""
    path = args.file or default_vault_path()
    old = getpass("Current master password: ")
    try:
        data = open_vault(old, path)
    except Exception as e:
        print(f"[red]Failed to open vault (wrong password?): {e}[/red]")
        return
    new = getpass("New master password: ")
    confirm = getpass("Confirm new master password: ")
    if new != confirm:
        print("[red]New password mismatch — aborting.[/red]")
        return
    try:
        save_vault(new, data, path)
        print("[green]Master password changed and vault re-encrypted.[/green]")
    except Exception as e:
        print(f"[red]Failed to save vault with new password: {e}[/red]")

def main():
    parser = argparse.ArgumentParser(prog="smartpass")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="Generate one or more passwords")
    gen.add_argument("--length", type=int, default=16, help="Password length")
    gen.add_argument("--no-symbols", action="store_true", help="Disable symbols")
    gen.add_argument("--no-upper", action="store_true", help="Disable uppercase")
    gen.add_argument("--no-lower", action="store_true", help="Disable lowercase")
    gen.add_argument("--no-digits", action="store_true", help="Disable digits")
    gen.add_argument("--copies", type=int, default=1, help="How many passwords to generate")
    gen.set_defaults(func=cmd_generate)

    sc = sub.add_parser("score", help="Score a password and show suggestions")
    sc.add_argument("password", type=str, help="Password to evaluate (wrap in quotes)")
    sc.set_defaults(func=cmd_score)

    v = sub.add_parser("vault", help="Vault operations")
    vsub = v.add_subparsers(dest="vcmd", required=True)

    vc_create = vsub.add_parser("create", help="Create a new vault")
    vc_create.add_argument("--file", "-f", type=str, help="Path to vault file")
    vc_create.set_defaults(func=cmd_vault_create)

    vc_add = vsub.add_parser("add", help="Add an entry to the vault")
    vc_add.add_argument("--file", "-f", type=str, help="Path to vault file")
    vc_add.add_argument("--name", type=str, help="Entry name (site)")
    vc_add.add_argument("--username", type=str, help="Username")
    vc_add.add_argument("--password", type=str, help="Password (avoid passing via CLI in public shells)")
    vc_add.add_argument("--notes", type=str, help="Optional notes")
    vc_add.set_defaults(func=cmd_vault_add)

    vc_list = vsub.add_parser("list", help="List entries in the vault")
    vc_list.add_argument("--file", "-f", type=str, help="Path to vault file")
    vc_list.set_defaults(func=cmd_vault_list)

    vc_rm = vsub.add_parser("remove", help="Remove entry by index")
    vc_rm.add_argument("--file", "-f", type=str, help="Path to vault file")
    vc_rm.add_argument("index", type=int, help="Entry index (number shown in list)")
    vc_rm.set_defaults(func=cmd_vault_remove)

    vc_export = vsub.add_parser("export", help="Export encrypted vault file to a backup path")
    vc_export.add_argument("--file", "-f", type=str, help="Path to vault file")
    vc_export.add_argument("--output", "-o", type=str, help="Backup output path")
    vc_export.set_defaults(func=cmd_vault_export)

    vc_import = vsub.add_parser("import", help="Import an encrypted vault backup (overwrites current)")
    vc_import.add_argument("--file", "-f", type=str, help="Path to vault file")
    vc_import.add_argument("--input", "-i", type=str, help="Backup file to import")
    vc_import.set_defaults(func=cmd_vault_import)

    vc_chpw = vsub.add_parser("changepw", help="Change the vault master password")
    vc_chpw.add_argument("--file", "-f", type=str, help="Path to vault file")
    vc_chpw.set_defaults(func=cmd_vault_changepw)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
