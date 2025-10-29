#!/usr/bin/env python3
"""
PassKey — Password & Key Creator + Manager (Tkinter GUI)

- Encrypted local vault (vault.json) using cryptography.Fernet
- Key derived from master password via PBKDF2HMAC with salt
- Simple CRUD for entries: title, username, password, notes
- Password generator with options
"""

import json
import os
import base64
import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from getpass import getpass
from typing import Dict, Any, Optional, List

import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# ---------- Configuration ----------
VAULT_FILE = "vault.json"
KDF_ITERATIONS = 390_000  # strong but moderate; increase if you want slower key derivation
SALT_LEN = 16  # bytes

# ---------- Crypto helpers ----------
def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derive a 32-byte key suitable for Fernet from the master password and salt.
    """
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key


def encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(plaintext)


def decrypt_data(key: bytes, token: bytes) -> bytes:
    f = Fernet(key)
    return f.decrypt(token)


# ---------- Vault management ----------
def init_vault(master_password: str) -> None:
    """
    Create an empty vault with a new salt and empty entries.
    """
    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(master_password, salt)
    empty = json.dumps({"entries": []}).encode("utf-8")
    token = encrypt_data(key, empty)
    payload = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "vault": base64.b64encode(token).decode("utf-8")
    }
    with open(VAULT_FILE, "w") as f:
        json.dump(payload, f)
    print("Vault initialized.")


def load_vault(master_password: str) -> Dict[str, Any]:
    """
    Load and decrypt the vault. Returns the vault dict (with 'entries' list).
    Raises ValueError if file missing or password invalid.
    """
    if not os.path.exists(VAULT_FILE):
        raise FileNotFoundError("Vault file not found. Initialize the vault first.")
    with open(VAULT_FILE, "r") as f:
        payload = json.load(f)
    salt = base64.b64decode(payload["salt"])
    token = base64.b64decode(payload["vault"])
    key = derive_key(master_password, salt)
    try:
        plaintext = decrypt_data(key, token)
    except Exception as e:
        raise ValueError("Unable to decrypt vault. Wrong master password or corrupted vault.") from e
    vault = json.loads(plaintext.decode("utf-8"))
    return {"vault": vault, "salt": salt, "key": key}


def save_vault(vault_obj: Dict[str, Any], key: bytes, salt: bytes) -> None:
    """
    Encrypt and save vault_obj (a dict). Overwrites vault file.
    """
    plaintext = json.dumps(vault_obj, ensure_ascii=False).encode("utf-8")
    token = encrypt_data(key, plaintext)
    payload = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "vault": base64.b64encode(token).decode("utf-8")
    }
    with open(VAULT_FILE, "w") as f:
        json.dump(payload, f)


# ---------- Password generator ----------
def generate_password(length: int = 16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
    if length < 4:
        raise ValueError("Password length should be at least 4")
    alphabet = ""
    if use_lower:
        alphabet += string.ascii_lowercase
    if use_upper:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>/?\\|"
    if not alphabet:
        raise ValueError("No character sets selected")
    # ensure at least one char from each selected set
    password_chars = []
    if use_lower:
        password_chars.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        password_chars.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        password_chars.append(secrets.choice(string.digits))
    if use_symbols:
        password_chars.append(secrets.choice("!@#$%^&*()-_=+[]{};:,.<>/?\\|"))
    while len(password_chars) < length:
        password_chars.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


# ---------- GUI ----------
class PassKeyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PassKey — Password & Key Manager")
        self.geometry("800x520")
        self.resizable(False, False)

        # runtime state
        self.vault_data: Dict[str, Any] = {"entries": []}
        self.key: Optional[bytes] = None
        self.salt: Optional[bytes] = None

        self.create_widgets()

    def create_widgets(self):
        # Top: Master password frame
        top_frame = ttk.Frame(self, padding=8)
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Master Password:").pack(side=tk.LEFT, padx=(0,6))
        self.master_pwd_var = tk.StringVar()
        self.master_pwd_entry = ttk.Entry(top_frame, textvariable=self.master_pwd_var, show="*")
        self.master_pwd_entry.pack(side=tk.LEFT)
        ttk.Button(top_frame, text="Initialize Vault", command=self.on_init_vault).pack(side=tk.LEFT, padx=6)
        ttk.Button(top_frame, text="Unlock Vault", command=self.on_unlock_vault).pack(side=tk.LEFT)

        # Main frame: left list, right details
        main = ttk.Frame(self, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        # Left: entries list + search
        left = ttk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,8))
        search_frame = ttk.Frame(left)
        search_frame.pack(fill=tk.X)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', self.update_listbox)
        ttk.Entry(search_frame, textvariable=self.search_var).pack(side=tk.LEFT)
        self.listbox = tk.Listbox(left, width=36, height=24)
        self.listbox.pack(side=tk.LEFT, fill=tk.Y, pady=(6,0))
        self.listbox.bind('<<ListboxSelect>>', lambda e: self.on_select_entry())

        # Buttons below list
        list_btn_frame = ttk.Frame(left)
        list_btn_frame.pack(pady=6)
        ttk.Button(list_btn_frame, text="New Entry", command=self.on_new_entry).pack(side=tk.LEFT, padx=4)
        ttk.Button(list_btn_frame, text="Delete", command=self.on_delete_entry).pack(side=tk.LEFT, padx=4)
        ttk.Button(list_btn_frame, text="Copy Password", command=self.on_copy_password).pack(side=tk.LEFT, padx=4)

        # Right: details + generator
        right = ttk.Frame(main)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Details form
        form = ttk.Frame(right, padding=6, relief=tk.RIDGE)
        form.pack(fill=tk.BOTH, expand=True)
        ttk.Label(form, text="Title:").grid(row=0, column=0, sticky=tk.W)
        self.title_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.title_var, width=40).grid(row=0, column=1, sticky=tk.W, pady=4)

        ttk.Label(form, text="Username / Email:").grid(row=1, column=0, sticky=tk.W)
        self.user_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.user_var, width=40).grid(row=1, column=1, sticky=tk.W, pady=4)

        ttk.Label(form, text="Password:").grid(row=2, column=0, sticky=tk.W)
        self.pwd_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.pwd_var, width=40, show="*").grid(row=2, column=1, sticky=tk.W, pady=4)

        ttk.Label(form, text="Notes:").grid(row=3, column=0, sticky=tk.NW)
        self.notes_text = tk.Text(form, width=40, height=6)
        self.notes_text.grid(row=3, column=1, pady=4)

        # Save / View
        action_frame = ttk.Frame(form)
        action_frame.grid(row=4, column=1, pady=8, sticky=tk.E)
        ttk.Button(action_frame, text="Save Entry", command=self.on_save_entry).pack(side=tk.LEFT, padx=4)
        ttk.Button(action_frame, text="View Password", command=self.on_toggle_view).pack(side=tk.LEFT, padx=4)

        # Password generator
        gen_box = ttk.LabelFrame(right, text="Password Generator", padding=8)
        gen_box.pack(fill=tk.X, pady=10)
        ttk.Label(gen_box, text="Length:").grid(row=0, column=0, sticky=tk.W)
        self.gen_len = tk.IntVar(value=16)
        ttk.Spinbox(gen_box, from_=4, to=128, textvariable=self.gen_len, width=6).grid(row=0, column=1, sticky=tk.W, padx=4)

        self.gen_upper = tk.BooleanVar(value=True)
        self.gen_lower = tk.BooleanVar(value=True)
        self.gen_digits = tk.BooleanVar(value=True)
        self.gen_symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(gen_box, text="Upper", variable=self.gen_upper).grid(row=1, column=0)
        ttk.Checkbutton(gen_box, text="Lower", variable=self.gen_lower).grid(row=1, column=1)
        ttk.Checkbutton(gen_box, text="Digits", variable=self.gen_digits).grid(row=1, column=2)
        ttk.Checkbutton(gen_box, text="Symbols", variable=self.gen_symbols).grid(row=1, column=3)

        ttk.Button(gen_box, text="Generate -> Password", command=self.on_generate_password).grid(row=2, column=0, columnspan=2, pady=6)

        # Status bar
        self.status_var = tk.StringVar(value="Vault locked.")
        status = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(side=tk.BOTTOM, fill=tk.X)

    # ---------- GUI actions ----------
    def on_init_vault(self):
        pwd = self.master_pwd_var.get().strip()
        if not pwd:
            messagebox.showwarning("Master password", "Please enter a master password to initialize the vault.")
            return
        if os.path.exists(VAULT_FILE):
            if not messagebox.askyesno("Vault exists", "A vault already exists. Overwrite?"):
                return
        try:
            init_vault(pwd)
            self.status_var.set("Vault initialized. You can now unlock.")
            messagebox.showinfo("Vault created", "Vault initialized successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize vault: {e}")

    def on_unlock_vault(self):
        pwd = self.master_pwd_var.get().strip()
        if not pwd:
            messagebox.showwarning("Master password", "Enter master password to unlock vault.")
            return
        try:
            res = load_vault(pwd)
            self.vault_data = res["vault"]
            self.key = res["key"]
            self.salt = res["salt"]
            self.status_var.set("Vault unlocked.")
            self.update_listbox()
            messagebox.showinfo("Unlocked", "Vault successfully unlocked.")
        except FileNotFoundError:
            messagebox.showerror("No vault", "No vault found. Initialize a vault first.")
        except ValueError:
            messagebox.showerror("Wrong password", "Unable to decrypt vault. Check your master password.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_listbox(self, *_):
        self.listbox.delete(0, tk.END)
        q = self.search_var.get().strip().lower()
        entries: List[Dict[str, Any]] = self.vault_data.get("entries", [])
        for idx, entry in enumerate(entries):
            title = entry.get("title", "")
            username = entry.get("username", "")
            display = f"{title} — {username}" if username else title
            if not q or q in display.lower():
                self.listbox.insert(tk.END, display)

    def on_new_entry(self):
        self.title_var.set("")
        self.user_var.set("")
        self.pwd_var.set("")
        self.notes_text.delete("1.0", tk.END)

    def on_save_entry(self):
        if self.key is None or self.salt is None:
            messagebox.showwarning("Locked", "Unlock the vault with master password first.")
            return
        title = self.title_var.get().strip()
        username = self.user_var.get().strip()
        password = self.pwd_var.get().strip()
        notes = self.notes_text.get("1.0", tk.END).strip()
        if not title:
            messagebox.showwarning("Missing", "Please provide a title for the entry.")
            return
        # add or update existing (update if title matches)
        entries = self.vault_data.setdefault("entries", [])
        for ent in entries:
            if ent.get("title") == title:
                ent["username"] = username
                ent["password"] = password
                ent["notes"] = notes
                break
        else:
            entries.append({"title": title, "username": username, "password": password, "notes": notes})
        # save
        try:
            save_vault(self.vault_data, self.key, self.salt)
            messagebox.showinfo("Saved", "Entry saved into vault.")
            self.update_listbox()
        except Exception as e:
            messagebox.showerror("Save error", f"Could not save vault: {e}")

    def on_select_entry(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        text = self.listbox.get(sel[0])
        # find entry by title prefix
        title = text.split(" — ")[0]
        entries = self.vault_data.get("entries", [])
        for ent in entries:
            if ent.get("title") == title:
                self.title_var.set(ent.get("title", ""))
                self.user_var.set(ent.get("username", ""))
                self.pwd_var.set(ent.get("password", ""))
                self.notes_text.delete("1.0", tk.END)
                self.notes_text.insert("1.0", ent.get("notes", ""))
                break

    def on_delete_entry(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Select an entry to delete.")
            return
        text = self.listbox.get(sel[0])
        title = text.split(" — ")[0]
        if not messagebox.askyesno("Delete", f"Delete entry '{title}'?"):
            return
        entries = self.vault_data.get("entries", [])
        new = [e for e in entries if e.get("title") != title]
        self.vault_data["entries"] = new
        try:
            save_vault(self.vault_data, self.key, self.salt)
            messagebox.showinfo("Deleted", "Entry removed from vault.")
            self.update_listbox()
            self.on_new_entry()
        except Exception as e:
            messagebox.showerror("Error", f"Could not update vault: {e}")

    def on_copy_password(self):
        if self.key is None:
            messagebox.showwarning("Locked", "Unlock the vault first.")
            return
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Select an entry to copy password.")
            return
        text = self.listbox.get(sel[0])
        title = text.split(" — ")[0]
        entries = self.vault_data.get("entries", [])
        for ent in entries:
            if ent.get("title") == title:
                pwd = ent.get("password", "")
                pyperclip.copy(pwd)
                messagebox.showinfo("Copied", "Password copied to clipboard.")
                break

    def on_toggle_view(self):
        # toggle showing password as plain or masked
        current_show = self.pwd_var.get()
        # simple toggle — if Entry was masked, we will open to show in a dialog
        messagebox.showinfo("Password", f"Password: {self.pwd_var.get() or '(empty)'}")

    def on_generate_password(self):
        length = self.gen_len.get()
        try:
            pwd = generate_password(length,
                                    use_upper=self.gen_upper.get(),
                                    use_lower=self.gen_lower.get(),
                                    use_digits=self.gen_digits.get(),
                                    use_symbols=self.gen_symbols.get())
        except Exception as e:
            messagebox.showerror("Generate error", str(e))
            return
        self.pwd_var.set(pwd)
        pyperclip.copy(pwd)
        messagebox.showinfo("Generated", "Password generated and copied to clipboard.")

# ---------- Entry point ----------
def main():
    app = PassKeyApp()
    app.mainloop()


if __name__ == "__main__":
    main()
