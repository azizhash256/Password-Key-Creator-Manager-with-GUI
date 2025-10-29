# PassKey — Password & Key Creator / Manager (GUI)

**PassKey** is a small, secure password and key manager with a graphical interface built with Python and Tkinter.  
It allows you to generate strong passwords, save them in an encrypted local vault, search/view/copy/delete entries, and protect everything with a master password.

> ⚠️ This tool is intended for personal/local use. It stores data locally in an encrypted file (`vault.json`). Do **not** treat it as a replacement for production vaults or enterprise solutions.

## Features
- Generate strong passwords (customizable length and character classes).
- Create and store credentials (name, username/email, password, notes).
- Encrypted local vault using AES via `cryptography.Fernet` with a key derived from a master password (PBKDF2HMAC + salt).
- Search, view, copy to clipboard, and delete entries.
- Simple, dependency-light GUI using Tkinter.

## Files
- `main.py` — main application code (GUI + crypto + vault handling).
- `requirements.txt` — Python dependencies.
- `LICENSE` — MIT license.
- `.gitignore` — ignores `vault.json` and Python artifacts.

## Quick start

### 1. Clone
bash
git clone https://github.com/<azizhash256>/passkey.git
cd passkey
2. Setup (recommended: virtualenv)
bash
Copy code
python -m venv venv
source venv/bin/activate    # macOS / Linux
venv\Scripts\activate       # Windows

pip install -r requirements.txt
3. Run
bash
Copy code
python main.py
4. Usage
On first run: enter a master password and click Initialize Vault to create a new encrypted vault.

On subsequent runs: enter the same master password and click Unlock Vault.

Use Generate to create a password. Fill the fields and click Save Entry.

Select an entry in the list to View, Copy Password, or Delete.

Security Notes
Vault file: vault.json (contains salt + encrypted data). This file is ignored by .gitignore by default and should be backed up only if you also back up the master password securely.

The master password is NOT stored. If you forget the master password, you cannot decrypt the vault.

Key derivation uses PBKDF2HMAC with many iterations to slow brute-force attempts.

Clipboard: copying a password places it in the OS clipboard. Clear it manually as needed.

Contributing
Contributions, issues and feature requests are welcome. Please open an issue or submit a PR.
