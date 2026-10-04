# SecureVault

A local, offline password manager for Windows, written in Python.

SecureVault keeps all your passwords in **one encrypted file on your own computer**. It has no
network code, no cloud sync, no accounts and no telemetry. Nothing ever leaves your machine.

![Python](https://img.shields.io/badge/python-3.11%2B-blue) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey) ![Tests](https://img.shields.io/badge/tests-53%20passing-brightgreen)

---

## Contents
- [Features](#features)
- [Getting started](#getting-started)
- [Using the app](#using-the-app)
- [Security design](#security-design)
- [Vault file format](#vault-file-format)
- [Limitations: what it can't protect against](#limitations-what-it-cant-protect-against)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Development history](#development-history)
- [Roadmap](#roadmap)

---

## Features

**Core**
- Store logins with title, username, password, website, notes and an optional 2FA secret
- Instant search across title, username and website
- Add, edit and delete entries, with every change saved to disk immediately
- Change the master password at any time

**Security**
- Argon2id key derivation and AES-256-GCM authenticated encryption
- **Optional key file** as a second factor: unlocking needs your password *and* a file (e.g. on a USB stick)
- **Recovery kit**: a printable recovery key that gets you back in if you forget your master
  password or lose your key file
- Auto-lock after 5 minutes of inactivity, plus manual lock (Ctrl+L)
- Secure clipboard: copied secrets are kept out of Windows clipboard history (Win+V) and cloud
  clipboard, and are cleared automatically after 20 seconds
- Increasing delay after repeated wrong master-password attempts
- Crash-safe saving with an automatic backup of the previous version

**Convenience**
- Password generator (length 8–64, choice of character types, option to avoid look-alike characters)
- Password strength meter
- **CSV import** from Chrome, Edge, Brave, Firefox, Bitwarden, LastPass, 1Password and KeePass,
  with automatic format detection and duplicate skipping
- **2FA (TOTP) codes**: live 6-digit codes with a countdown, compatible with Google Authenticator,
  Microsoft Authenticator and similar apps
- Keyboard shortcuts for everything common

---

## Getting started

### Option A: download the `.exe` (no Python needed)
Download `SecureVault.exe` from the [Releases](https://github.com/SolemonCharles/SecureVault/releases)
page and double-click it. Each release also lists a SHA-256 checksum. You can check that your download
matches with:
```powershell
Get-FileHash SecureVault.exe -Algorithm SHA256
```
> Windows SmartScreen will warn about an "unknown publisher" because the `.exe` isn't code-signed yet.
> Click **More info → Run anyway**, or build it yourself from source (below).

### Option B: run from source

#### Requirements
- Windows 10 or 11
- Python 3.11 or newer ([python.org](https://www.python.org/downloads/)). Tick **"Add Python to PATH"**
  during installation.

#### Install
```powershell
git clone https://github.com/SolemonCharles/SecureVault.git
cd SecureVault
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

#### Run
```powershell
.venv\Scripts\pythonw app.py
```
or double-click **`SecureVault.bat`**.

#### Build the `.exe` yourself
```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```
This installs the build tools, runs all tests (and stops if any fail), and then produces
`dist\SecureVault.exe` plus a `.sha256` checksum file.

The vault is stored at `%APPDATA%\SecureVault\vault.svault`. To use a different location, such as a
USB drive or a test vault, pass a path:
```powershell
.venv\Scripts\python app.py D:\my-vault.svault
```

> **Note:** run these commands from inside the `SecureVault` folder. If PowerShell says
> *"The module '.venv' could not be loaded"*, you are in the wrong folder. `cd` into the project first.

---

## Using the app

### First launch
You will be asked to create a **master password**. It must be at least 12 characters and rated at
least "Fair". A passphrase of 4–5 random words works well.

Leave **"Create a recovery kit"** ticked (recommended). Your recovery key is then shown once. Print it
or write it down and store it safely, then tick *"I have stored my recovery key somewhere safe"*.

> ⚠️ **The master password is never stored anywhere.** If you forget it and have no recovery kit,
> your data is permanently lost. Nobody, including the developer, can get it back.

### Main screen
| Action | How |
|---|---|
| Add entry | **+ Add** or `Ctrl+N` |
| Edit entry | Double-click it, or **Edit** |
| Delete entry | **Delete** or `Del` |
| Search | Type in the search box (`Ctrl+F`) |
| Copy username | **Copy username** or `Ctrl+B` |
| Copy password | **Copy password**, or `Ctrl+C` while the list is focused |
| Copy 2FA code | **Copy 2FA code** or `Ctrl+T` |
| Generate password | **Generate** in the entry dialog |
| Lock | **🔒 Lock** or `Ctrl+L` |
| Master password, key file, recovery kit | **Security…** |

### Importing from a browser or another password manager
1. Export your passwords to CSV:
   - **Chrome / Edge / Brave:** `chrome://password-manager/settings` → *Export passwords*
   - **Firefox:** `about:logins` → ⋯ → *Export Logins*
   - **Bitwarden / LastPass / 1Password / KeePass:** use their CSV export option
2. In SecureVault click **Import CSV…** and choose the file.
3. Review the summary (format detected, new entries, duplicates skipped), then confirm.
4. When asked, let SecureVault **delete the CSV**. It contains every password in plain text.
   Also empty your Recycle Bin and check your Downloads folder for other copies.

### 2FA codes
When a website shows you a QR code to set up two-factor authentication, it usually also offers a
text key ("Can't scan the code?"). Paste that key, or an `otpauth://` link, into an entry's
**2FA secret** field. Select the entry to see the live code. It turns red in its last 5 seconds.

> Storing 2FA secrets alongside passwords is convenient, but it means anyone who gets into the
> vault has both factors. For your most important accounts (main email, bank), consider keeping
> 2FA on your phone instead.

### Key file (second factor)
A key file means a stolen vault can't be opened with the password alone. The attacker would also
need the file.

1. Open **Security…** and enter your current master password.
2. Click **Create new key file…** and save it, ideally on a USB stick. Or click **Use existing file…**
   (a generated key file is safer than a photo or document).
3. **Back up the key file immediately**, e.g. on a second USB stick.

From then on, the unlock screen asks for the key file as well. SecureVault remembers *where* the key
file is (never its contents), so the path is filled in for you. The file's exact bytes are the key:
renaming or moving it is fine, but editing or re-saving it breaks it.

### Recovery kit
The recovery kit is a 32-character recovery key (e.g. `ABCD-EFGH-…`). It unlocks the vault if you
forget your master password **or** lose your key file.

- **To use it:** on the unlock screen click **Forgot password or lost key file?**, enter the key, then
  choose a new master password. The key-file requirement is removed, and a **new** recovery kit is
  issued because the old key stops working once used.
- **Create a new kit / remove the kit:** **Security…** → *Recovery kit*.
- The recovery key is as powerful as your password (and key file) combined. Keep it **offline**:
  printed, or on a USB stick in a drawer. Never keep it on the same computer.

---

## Security design

| Layer | Implementation | Why |
|---|---|---|
| Key derivation | **Argon2id**: 256 MiB memory, 3 iterations, parallelism 4, 16-byte random salt | Memory-hard: each password guess costs an attacker significant RAM and time, which makes GPU/ASIC cracking impractical |
| Envelope encryption | A random 256-bit **vault key** encrypts the data. It is stored *wrapped* (AES-256-GCM) in key slots: a **password slot** and an optional **recovery slot** | Either credential can unlock the vault. Changing the password only re-wraps 32 bytes |
| Key file | Password slot key = `HKDF-SHA256(Argon2id(password) ‖ SHA-256(key file))` | Both factors are needed. A key file alone, or a password alone, is useless |
| Recovery key | 160 random bits, shown as 8 groups of 4 base32 characters. Slot key = `HKDF-SHA256(recovery key, salt)` | Far too much entropy to guess, so no slow KDF is needed. Typing mistakes like `0`/`O` are tolerated |
| Encryption | **AES-256-GCM** with a 96-bit random nonce | Industry-standard authenticated encryption. Any modification of the file is detected |
| What is encrypted | The **entire** vault: titles, usernames, URLs, notes, passwords and 2FA secrets | An attacker with the file learns nothing except roughly how big it is |
| Header integrity | The whole header (salt, KDF parameters, key-file flag, key slots, nonce) is bound to the ciphertext as *associated data* | The header can't be altered undetected: no weakening the KDF, switching off the key-file flag, or swapping key slots |
| Downgrade protection | Files with KDF parameters below 64 MiB / 2 iterations are refused | Blocks attacks that swap in deliberately weak parameters |
| Nonce handling | A new random nonce on **every** save, and a new salt on every master-password change | Prevents nonce reuse, the classic way AES-GCM fails |
| Master password | Never stored. Only the vault key is kept in memory while unlocked, and it is discarded on lock. Security changes require re-entering the current password | Nothing on disk can reveal the password, and someone at your unlocked PC can't change your credentials |
| Saving | Write to a temp file → `fsync` → atomic rename, keeping the previous version as `.bak` | A crash or power cut mid-save can't corrupt the vault |
| Clipboard | Sets Windows' `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0` and `CanUploadToCloudClipboard=0`, then clears after 20 s (only if the clipboard still holds what we copied) | Keeps secrets out of Win+V history and cloud sync, and doesn't wipe something else you copied |
| Brute-force on unlock | Exponential delay after 3 failed attempts (max 5 min), on top of Argon2's cost | Slows down someone guessing at your keyboard |
| Random numbers | Python `secrets` (the OS CSPRNG) for the generator, `os.urandom` for salts and nonces | Cryptographically secure randomness |
| Libraries | [`cryptography`](https://cryptography.io) (OpenSSL-backed) and [`argon2-cffi`](https://argon2-cffi.readthedocs.io) (reference Argon2) | Well-audited, widely used implementations. No home-made crypto primitives |

### Why a desktop app?
A local app removes the whole server side: there is no server to breach, no database of millions of
users to steal, and no network traffic to intercept. The trade-off is that **you** are responsible
for backups and for the security of your PC.

---

## Vault file format

The vault is a JSON document:

```json
{
  "header": {
    "v": 2,
    "kdf": "argon2id",
    "salt": "<base64, 16 bytes>",
    "t": 3,
    "m": 262144,
    "p": 4,
    "keyfile": false,
    "slots": {
      "password": { "nonce": "<base64>", "key": "<base64 wrapped vault key>" },
      "recovery": { "salt": "<base64>", "nonce": "<base64>", "key": "<base64 wrapped vault key>" }
    },
    "nonce": "<base64, 12 bytes>"
  },
  "ct": "<base64 AES-256-GCM ciphertext + 16-byte tag>"
}
```

- **Password slot key** = `HKDF-SHA256(Argon2id(password, salt, t, m, p) ‖ SHA-256(keyfile)?, info="SecureVault/v2/password-kek")`
- **Recovery slot key** = `HKDF-SHA256(recovery_key, slot salt, info="SecureVault/v2/recovery-kek")`
- **Slots** = `AES-256-GCM(slot key, vault key)`, with the slot name (`"password"` / `"recovery"`) as AAD
- **Body** = `AES-256-GCM(vault key, plaintext)`, with the whole header as canonical JSON (sorted keys, no whitespace) as AAD
- **Plaintext** = `{"entries": [ {title, username, password, url, notes, totp, id, created, modified}, ... ]}`

**Compatibility:** version 1 files (where the password-derived key encrypted the data directly) are
upgraded to version 2 automatically the first time they are unlocked. Unknown entry fields are
ignored, so older vaults open in newer versions of the app.

---

## Limitations: what it can't protect against

Being honest about the threat model matters:

- **A forgotten master password means lost data**, unless you created a recovery kit. Losing both
  the password and the recovery kit is unrecoverable by design. The same applies to losing the key file.
- **Your recovery kit is a master key.** Anyone who finds it can open your vault. Store it offline.
- **Malware on your PC** (keyloggers, screen grabbers, memory readers) can defeat any password
  manager, commercial ones included. Keep Windows updated, use antivirus, and enable BitLocker.
- **Python can't reliably wipe memory.** Decrypted values may stay in RAM until the app exits.
  Locking drops all references to them.
- **Backups are your job.** Copy `vault.svault` to a USB drive or external disk regularly. It is
  safe to copy anywhere because it is encrypted.
- **Weak master password = weak vault.** Argon2 slows guessing down. It can't save a password like
  `Summer2024!`.
- **The `.exe` isn't code-signed yet**, so Windows can't verify who published it. Check the SHA-256
  checksum, or build from source.
- **Not independently audited.** This is a personal project. Review the code (especially
  `vault/crypto.py`) before trusting it with critical secrets.

---

## Testing

### Automated tests
```powershell
.venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -v
```
Expected result: **53 passed**. The tests cover:

| Area | Tests |
|---|---|
| Encryption | Round-trip, no plaintext in the file, wrong password rejected, fresh nonce on every save |
| Tamper detection | Modified ciphertext, modified header, KDF downgrade attempt |
| Vault operations | Change master password, refusing to overwrite an existing vault, lock clears state, opening old vaults |
| Password generator | Length, character classes, uniqueness, strength scoring |
| 2FA | All official **RFC 6238** test vectors (SHA-1/256/512), plain keys with spaces, invalid input rejected, secrets encrypted |
| CSV import | Chrome, Firefox, Bitwarden (including 2FA and multi-line notes), KeePass, duplicates, non-password CSVs, empty files |
| Key file | Required after enabling, wrong or modified file rejected, file alone not enough, removal, survives a password change, flag tampering detected, never overwrites an existing file |
| Recovery kit | Unlock and reset, works when the key file is lost, old kit stops working after use, typo tolerance, wrong key, removal, stays valid after a password change |
| Format upgrade | v1 vaults upgrade to v2 on unlock, a wrong password leaves the v1 file untouched, swapped key slots detected |

### Manual test checklist
Use a throwaway vault so your real one is untouched:
```powershell
.venv\Scripts\python app.py test-vault.svault
```

| # | Do this | Expected |
|---|---|---|
| 1 | Create a weak master password (e.g. `password`) | Refused |
| 2 | **Import CSV…** → `samples\sample_bitwarden_export.csv` | "Bitwarden, 3 new entries" |
| 3 | Answer **No** when asked to delete the CSV | 3 entries. "Demo GitHub" shows ✓ for 2FA |
| 4 | Import the same file again | "3 already in your vault" |
| 5 | Select **Demo GitHub** | Live 6-digit code with countdown |
| 6 | Add key `JBSWY3DPEHPK3PXP` to a phone authenticator app | Same code as in SecureVault |
| 7 | `Ctrl+T`, paste in Notepad, wait 20 s, paste again | Second paste is empty |
| 8 | Copy a password, press `Win+V` | Not in clipboard history |
| 9 | Edit an entry, set its 2FA secret to `hello`, save | "Invalid 2FA secret" |
| 10 | Lock, then enter a wrong password 4 times | Forced wait, growing each time |
| 11 | Open `test-vault.svault` in Notepad | Encrypted text only, no names or passwords |
| 12 | Change one character in `"ct"`, save, try to unlock | "Wrong master password or vault was tampered with" |
| 13 | Rename `test-vault.svault.bak` → `test-vault.svault`, unlock | Vault opens as before the last change |
| 14 | Leave the app idle for 5 minutes | Locks automatically |
| 15 | **Security…** → enter password → **Create new key file…** → save as `test.key` | "Key file is now required" |
| 16 | Lock | The unlock screen now has a *Key file* field, pre-filled |
| 17 | Clear the key file field and try to unlock | "This vault needs its key file" |
| 18 | **Security…** → **Create new recovery kit** | The recovery key is shown. *Done* stays disabled until you tick the box |
| 19 | Lock → **Forgot password or lost key file?** → enter the recovery key | "Choose a new master password" |
| 20 | Set a new password | A new recovery kit is shown, and the old key no longer works |
| 21 | Lock and unlock with the new password | Opens without the key file |
| 22 | **Security…** → enter a wrong current password → any action | "Current master password is incorrect" |

Delete `test-vault.svault*` and `test.key` when you're done.

> The sample CSV contains **fake** accounts only. `JBSWY3DPEHPK3PXP` is a well-known public demo key.
> Never use either for a real account.

---

## Project structure

```
SecureVault/
├── app.py                  # Tkinter GUI: setup, unlock, recovery, main list, dialogs, auto-lock
├── SecureVault.bat         # Double-click launcher (no console window)
├── build.ps1               # Runs the tests, then builds dist\SecureVault.exe + SHA-256 checksum
├── requirements.txt        # cryptography, argon2-cffi
├── requirements-dev.txt    # pytest, pyinstaller
├── vault/
│   ├── crypto.py           # Argon2id, HKDF, AES-256-GCM, key wrapping, key files, recovery keys
│   ├── store.py            # Vault and Entry model, key slots, atomic save, backup, v1 → v2 upgrade
│   ├── clipboard.py        # Windows clipboard that avoids history/cloud and auto-clears
│   ├── generator.py        # Secure password generator and strength estimate
│   ├── totp.py             # RFC 6238 2FA codes, otpauth:// parsing
│   └── importer.py         # CSV import with format detection and de-duplication
├── tests/
│   ├── conftest.py         # Shared helper that writes legacy v1 vaults
│   ├── test_vault.py       # Encryption, tamper detection, vault operations, generator
│   ├── test_features.py    # 2FA and CSV import
│   └── test_credentials.py # Key file, recovery kit, format upgrade
└── samples/
    └── sample_bitwarden_export.csv   # Fake data for manual testing
```

The security-critical code is deliberately small. `vault/crypto.py` is about 230 lines and can be
reviewed in one sitting.

---

## Development history

### Version 1: core password manager
- Chose a **local desktop app** over a web app: no server, no network attack surface
- Chose **Python** for readable, auditable code backed by well-vetted crypto libraries
- Implemented Argon2id + AES-256-GCM encryption with an authenticated header and downgrade protection
- Built the Tkinter GUI: vault creation, unlock, entry list, search, add/edit/delete, password
  generator, strength meter, change master password
- Added auto-lock, unlock back-off, crash-safe saving with backup
- Wrote a Windows clipboard helper that keeps passwords out of clipboard history and cloud sync
- 12 automated tests for encryption, tamper detection and vault behaviour

### Version 2: CSV import and 2FA
- **CSV import** with automatic detection of 8+ export formats, column-name mapping, titles taken
  from the URL when missing, duplicate skipping, a confirmation summary, and an offer to delete the
  plaintext CSV afterwards
- **2FA / TOTP**: new encrypted `totp` field on entries, accepting base32 keys or `otpauth://` links
  (SHA-1/256/512, 6–8 digits, custom periods), a live code panel with countdown, copy with `Ctrl+T`,
  and a ✓ column in the list
- Older vault files stay compatible (unknown or missing fields are handled)
- 19 more tests, including the official RFC 6238 test vectors (31 total)

### Version 3: key file, recovery kit and `.exe`
- Moved to **envelope encryption** (vault format v2): a random vault key encrypts the data and is
  wrapped in separate key slots. v1 vaults are upgraded automatically on first unlock.
- **Key file** second factor: create a random 64-byte key file or use an existing file, with
  validation (size limits, never overwrites an existing file). Its location is remembered, never its contents.
- **Recovery kit**: optional at setup and manageable under Security. It is shown once with a
  "stored safely" confirmation, can be saved as a text file to print, and is rotated automatically after use.
- **Recovery flow**: "Forgot password or lost key file?" → recovery key → choose a new master password
- New **Security** dialog (replacing *Change master password*), where every change requires the current password
- **`build.ps1`**: runs the tests, builds a single `SecureVault.exe` (~14 MB) with PyInstaller, and writes a SHA-256 checksum
- 22 more tests (53 total)

---

## Roadmap
- [x] ~~Key file second factor~~ (v3)
- [x] ~~Single `.exe` build~~ (v3)
- [x] ~~Recovery kit~~ (v3)
- [ ] Code signing for the `.exe` and an installer
- [ ] Encrypted export / backup
- [ ] Windows Hello quick-unlock, keeping the master password as fallback
- [ ] Password health report: reused, weak and old passwords
- [ ] Categories / folders and favourites

---

## License
Choose a license before publishing (for example [MIT](https://choosealicense.com/licenses/mit/)) and add it as a `LICENSE` file.
