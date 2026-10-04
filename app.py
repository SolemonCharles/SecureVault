"""SecureVault - a local, offline password manager (Tkinter GUI)."""
from __future__ import annotations

import json
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from vault import crypto, importer, totp
from vault.clipboard import SecureClipboard
from vault.generator import estimate_strength, generate_password
from vault.store import Entry, Vault, default_vault_path, vault_has_recovery, vault_requires_keyfile

APP_NAME = "SecureVault"
AUTO_LOCK_SECONDS = 5 * 60
CLIPBOARD_CLEAR_SECONDS = 20
MIN_MASTER_LENGTH = 12
STRENGTH_COLORS = ["#c0392b", "#e67e22", "#f1c40f", "#27ae60", "#1e8449"]


def run_in_background(root: tk.Tk, work, on_done, on_error):
    """Run slow work (Argon2) off the UI thread, then call back on it."""
    def worker():
        try:
            result = work()
        except Exception as e:  # noqa: BLE001
            root.after(0, on_error, e)
        else:
            root.after(0, on_done, result)
    threading.Thread(target=worker, daemon=True).start()


class StrengthMeter(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.bar = tk.Canvas(self, height=6, highlightthickness=0, bg="#ddd")
        self.bar.pack(fill="x")
        self.label = ttk.Label(self, text="", foreground="#666")
        self.label.pack(anchor="w")

    def update_for(self, password: str):
        score, label = estimate_strength(password)
        self.bar.delete("all")
        width = self.bar.winfo_width() or 200
        if password:
            self.bar.create_rectangle(0, 0, width * (score + 1) / 5, 6,
                                      fill=STRENGTH_COLORS[score], width=0)
        self.label.config(text=label if password else "")


class PasswordField(ttk.Frame):
    """Masked entry with a show/hide toggle."""
    def __init__(self, master, textvariable, width=32):
        super().__init__(master)
        self.entry = ttk.Entry(self, textvariable=textvariable, show="•", width=width)
        self.entry.pack(side="left", fill="x", expand=True)
        self.btn = ttk.Button(self, text="Show", width=6, command=self.toggle)
        self.btn.pack(side="left", padx=(4, 0))

    def toggle(self):
        hidden = self.entry.cget("show") != ""
        self.entry.config(show="" if hidden else "•")
        self.btn.config(text="Hide" if hidden else "Show")


# --------------------------------------------------------------------------
# Screens
# --------------------------------------------------------------------------
def new_password_problem(pw: str, confirm: str) -> str | None:
    if len(pw) < MIN_MASTER_LENGTH:
        return f"Use at least {MIN_MASTER_LENGTH} characters."
    if estimate_strength(pw)[0] < 2:
        return "Password is too weak - make it longer or more varied."
    if pw != confirm:
        return "Passwords do not match."
    return None


class SetupScreen(ttk.Frame):
    def __init__(self, app: "App"):
        super().__init__(app.root, padding=30)
        self.app = app
        self.pw = tk.StringVar()
        self.confirm = tk.StringVar()
        self.want_recovery = tk.BooleanVar(value=True)

        ttk.Label(self, text="Create your vault", style="Title.TLabel").pack(anchor="w")
        ttk.Label(self, wraplength=460, justify="left", text=(
            "Choose a strong master password. It is never stored anywhere. "
            "A long passphrase (e.g. 4-5 random words) works well.")).pack(anchor="w", pady=(6, 16))

        ttk.Label(self, text="Master password").pack(anchor="w")
        f1 = PasswordField(self, self.pw); f1.pack(fill="x")
        self.meter = StrengthMeter(self); self.meter.pack(fill="x", pady=(4, 10))
        ttk.Label(self, text="Confirm master password").pack(anchor="w")
        f2 = PasswordField(self, self.confirm); f2.pack(fill="x")
        ttk.Checkbutton(self, variable=self.want_recovery, text=(
            "Create a recovery kit (recommended) - a printable key that lets you\n"
            "get back in if you forget your master password")).pack(anchor="w", pady=(12, 0))

        self.status = ttk.Label(self, text="", foreground="#c0392b")
        self.status.pack(anchor="w", pady=8)
        self.btn = ttk.Button(self, text="Create vault", style="Accent.TButton", command=self.submit)
        self.btn.pack(anchor="e")

        self.pw.trace_add("write", lambda *_: self.meter.update_for(self.pw.get()))
        f1.entry.focus_set()
        f2.entry.bind("<Return>", lambda _: self.submit())

    def submit(self):
        pw = self.pw.get()
        problem = new_password_problem(pw, self.confirm.get())
        if problem:
            return self.status.config(text=problem, foreground="#c0392b")
        want_recovery = self.want_recovery.get()
        self.btn.state(["disabled"])
        self.status.config(text="Creating vault (deriving key)...", foreground="#666")

        def work():
            vault = Vault.create(self.app.vault_path, pw)
            return vault, vault.new_recovery_key() if want_recovery else None
        run_in_background(self.app.root, work, self.done, self.on_error)

    def done(self, result):
        vault, recovery_key = result
        self.app.on_unlocked(vault)
        if recovery_key:
            RecoveryKitDialog(self.app, recovery_key)

    def on_error(self, e):
        self.btn.state(["!disabled"])
        self.status.config(text=str(e), foreground="#c0392b")


class UnlockScreen(ttk.Frame):
    def __init__(self, app: "App", message: str = ""):
        super().__init__(app.root, padding=30)
        self.app = app
        self.pw = tk.StringVar()
        self.keyfile = tk.StringVar(value=app.remembered_keyfile() or "")
        try:
            self.needs_keyfile = vault_requires_keyfile(app.vault_path)
            self.has_recovery = vault_has_recovery(app.vault_path)
        except (OSError, crypto.DecryptionError) as e:
            self.needs_keyfile = self.has_recovery = False
            message = message or str(e)

        ttk.Label(self, text="🔒  Vault locked", style="Title.TLabel").pack(anchor="w")
        ttk.Label(self, text=str(app.vault_path), foreground="#888").pack(anchor="w", pady=(2, 16))
        ttk.Label(self, text="Master password").pack(anchor="w")
        field = PasswordField(self, self.pw); field.pack(fill="x")
        if self.needs_keyfile:
            ttk.Label(self, text="Key file").pack(anchor="w", pady=(10, 0))
            row = ttk.Frame(self); row.pack(fill="x")
            ttk.Entry(row, textvariable=self.keyfile).pack(side="left", fill="x", expand=True)
            ttk.Button(row, text="Browse…", command=self.browse).pack(side="left", padx=(4, 0))
        self.status = ttk.Label(self, text=message, foreground="#666")
        self.status.pack(anchor="w", pady=8)

        bottom = ttk.Frame(self); bottom.pack(fill="x")
        ttk.Button(bottom, text="Forgot password or lost key file?", style="Link.TButton",
                   command=self.forgot).pack(side="left")
        self.btn = ttk.Button(bottom, text="Unlock", style="Accent.TButton", command=self.submit)
        self.btn.pack(side="right")
        field.entry.focus_set()
        field.entry.bind("<Return>", lambda _: self.submit())

    def browse(self):
        path = filedialog.askopenfilename(parent=self, title="Select your key file")
        if path:
            self.keyfile.set(path)

    def forgot(self):
        if not self.has_recovery:
            return messagebox.showinfo(APP_NAME, (
                "No recovery kit was set up for this vault.\n\n"
                "Without the master password (and key file, if one is used) the vault cannot be "
                "opened by anyone - including you. That is what keeps it secure."), parent=self)
        self.app.show(RecoveryUnlockScreen(self.app))

    def submit(self):
        wait = self.app.lockout_remaining()
        if wait > 0:
            return self.status.config(text=f"Too many attempts. Wait {wait:.0f}s.", foreground="#c0392b")
        pw = self.pw.get()
        if not pw:
            return
        keyfile = Path(self.keyfile.get()) if self.needs_keyfile and self.keyfile.get().strip() else None
        if self.needs_keyfile and not keyfile:
            return self.status.config(text="This vault needs its key file - click Browse.", foreground="#c0392b")
        self.btn.state(["disabled"])
        self.status.config(text="Unlocking...", foreground="#666")
        run_in_background(self.app.root,
                          lambda: Vault.unlock(self.app.vault_path, pw, keyfile),
                          lambda v: self.done(v, keyfile), self.on_error)

    def done(self, vault, keyfile):
        if keyfile:
            self.app.remember_keyfile(keyfile)
        self.app.on_unlocked(vault)

    def on_error(self, e):
        self.btn.state(["!disabled"])
        self.pw.set("")
        if isinstance(e, crypto.DecryptionError):
            self.app.register_failed_attempt()
        if isinstance(e, FileNotFoundError):
            e = "Key file not found - check the path."
        self.status.config(text=str(e), foreground="#c0392b")


class RecoveryUnlockScreen(ttk.Frame):
    def __init__(self, app: "App"):
        super().__init__(app.root, padding=30)
        self.app = app
        self.key = tk.StringVar()
        ttk.Label(self, text="Recover your vault", style="Title.TLabel").pack(anchor="w")
        ttk.Label(self, wraplength=460, justify="left", text=(
            "Enter the recovery key from your recovery kit. You'll then choose a new master "
            "password, and a new recovery kit will be issued.")).pack(anchor="w", pady=(6, 16))
        ttk.Label(self, text="Recovery key").pack(anchor="w")
        entry = ttk.Entry(self, textvariable=self.key, font=("Consolas", 12))
        entry.pack(fill="x")
        ttk.Label(self, text="Dashes, spaces and upper/lower case don't matter.", foreground="#888").pack(anchor="w")
        self.status = ttk.Label(self, text="", foreground="#666"); self.status.pack(anchor="w", pady=8)
        bottom = ttk.Frame(self); bottom.pack(fill="x")
        ttk.Button(bottom, text="← Back", command=lambda: app.show(UnlockScreen(app))).pack(side="left")
        self.btn = ttk.Button(bottom, text="Unlock", style="Accent.TButton", command=self.submit)
        self.btn.pack(side="right")
        entry.focus_set()
        entry.bind("<Return>", lambda _: self.submit())

    def submit(self):
        wait = self.app.lockout_remaining()
        if wait > 0:
            return self.status.config(text=f"Too many attempts. Wait {wait:.0f}s.", foreground="#c0392b")
        key = self.key.get()
        if not key.strip():
            return
        self.btn.state(["disabled"])
        self.status.config(text="Checking recovery key...", foreground="#666")
        run_in_background(self.app.root, lambda: Vault.unlock_with_recovery(self.app.vault_path, key),
                          self.app.on_unlocked, self.on_error)

    def on_error(self, e):
        self.btn.state(["!disabled"])
        if isinstance(e, crypto.DecryptionError):
            self.app.register_failed_attempt()
        self.status.config(text=str(e), foreground="#c0392b")


class ResetPasswordScreen(ttk.Frame):
    """Shown after a recovery-key unlock: the user must pick a new master password."""
    def __init__(self, app: "App"):
        super().__init__(app.root, padding=30)
        self.app = app
        self.pw, self.confirm = tk.StringVar(), tk.StringVar()
        ttk.Label(self, text="Choose a new master password", style="Title.TLabel").pack(anchor="w")
        ttk.Label(self, wraplength=460, justify="left", text=(
            "Recovery key accepted. Choose a new master password to finish.\n\n"
            "• Any key-file requirement will be removed (you can add one again under Security).\n"
            "• A new recovery kit will be shown next - your old recovery key will stop working.")
                  ).pack(anchor="w", pady=(6, 16))
        ttk.Label(self, text="New master password").pack(anchor="w")
        f1 = PasswordField(self, self.pw); f1.pack(fill="x")
        self.meter = StrengthMeter(self); self.meter.pack(fill="x", pady=(4, 10))
        ttk.Label(self, text="Confirm new master password").pack(anchor="w")
        f2 = PasswordField(self, self.confirm); f2.pack(fill="x")
        self.status = ttk.Label(self, text="", foreground="#c0392b"); self.status.pack(anchor="w", pady=8)
        self.btn = ttk.Button(self, text="Save new password", style="Accent.TButton", command=self.submit)
        self.btn.pack(anchor="e")
        self.pw.trace_add("write", lambda *_: self.meter.update_for(self.pw.get()))
        f1.entry.focus_set()
        f2.entry.bind("<Return>", lambda _: self.submit())

    def submit(self):
        pw = self.pw.get()
        problem = new_password_problem(pw, self.confirm.get())
        if problem:
            return self.status.config(text=problem, foreground="#c0392b")
        self.btn.state(["disabled"])
        self.status.config(text="Saving...", foreground="#666")
        run_in_background(self.app.root, lambda: self.app.vault.reset_password(pw), self.done, self.on_error)

    def done(self, recovery_key):
        self.app.forget_keyfile()
        self.app.show(MainScreen(self.app))
        RecoveryKitDialog(self.app, recovery_key)

    def on_error(self, e):
        self.btn.state(["!disabled"])
        self.status.config(text=str(e), foreground="#c0392b")


class RecoveryKitDialog(tk.Toplevel):
    """Shows a new recovery key once and makes the user confirm they've stored it."""
    def __init__(self, app: "App", recovery_key: str):
        super().__init__(app.root)
        self.app, self.key = app, recovery_key
        self.title("Your recovery kit")
        self.transient(app.root)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.try_close)
        self.stored = tk.BooleanVar(value=False)

        body = ttk.Frame(self, padding=20); body.pack()
        ttk.Label(body, text="Save your recovery key", style="Title.TLabel").pack(anchor="w")
        ttk.Label(body, wraplength=440, justify="left", text=(
            "This key unlocks your vault if you forget your master password or lose your key file. "
            "Anyone who has it can open your vault - guard it like the master password itself.\n\n"
            "• Print it or write it down, and keep it with your important documents.\n"
            "• Don't keep it on this computer, in email, or in cloud storage.\n"
            "• It is shown only now. You can create a new one later under Security.")
                  ).pack(anchor="w", pady=(6, 12))
        key_box = tk.Entry(body, font=("Consolas", 14, "bold"), justify="center", relief="solid",
                           readonlybackground="#f6f6f6", width=len(recovery_key) + 2)
        key_box.insert(0, recovery_key)
        key_box.config(state="readonly")
        key_box.pack(fill="x", ipady=8)
        row = ttk.Frame(body); row.pack(fill="x", pady=8)
        ttk.Button(row, text="Save as text file…", command=self.save).pack(side="left")
        ttk.Button(row, text="Copy", command=lambda: self.app.copy_secret(self.key)).pack(side="left", padx=4)
        ttk.Checkbutton(body, text="I have stored my recovery key somewhere safe", variable=self.stored,
                        command=self.update_done).pack(anchor="w", pady=(8, 0))
        self.done_btn = ttk.Button(body, text="Done", style="Accent.TButton", command=self.destroy)
        self.done_btn.pack(anchor="e", pady=(8, 0))
        self.done_btn.state(["disabled"])
        self.grab_set()

    def update_done(self):
        self.done_btn.state(["!disabled"] if self.stored.get() else ["disabled"])

    def try_close(self):
        if self.stored.get() or messagebox.askyesno(APP_NAME, (
                "You haven't confirmed that you stored the recovery key. It won't be shown again.\n\n"
                "Close anyway?"), icon="warning", parent=self):
            self.destroy()

    def save(self):
        path = filedialog.asksaveasfilename(parent=self, title="Save recovery kit",
                                            initialfile="SecureVault-Recovery-Kit.txt",
                                            defaultextension=".txt", filetypes=[("Text file", "*.txt")])
        if not path:
            return
        Path(path).write_text(
            "SecureVault Recovery Kit\n"
            "========================\n\n"
            f"Created: {time.strftime('%Y-%m-%d')}\n"
            f"Vault:   {self.app.vault_path}\n\n"
            f"Recovery key:\n\n    {self.key}\n\n"
            "How to use: on the unlock screen click \"Forgot password or lost key file?\"\n"
            "and enter this key. You will then choose a new master password.\n\n"
            "KEEP THIS PRIVATE AND OFFLINE. Anyone with this key can open your vault.\n",
            encoding="utf-8")
        messagebox.showinfo(APP_NAME, (
            f"Saved to:\n{path}\n\nPrint it, then move the file to a USB stick you keep safe, "
            "or delete it. Don't leave it on this computer."), parent=self)


class EntryDialog(tk.Toplevel):
    def __init__(self, app: "App", entry: Entry | None):
        super().__init__(app.root)
        self.app, self.entry = app, entry
        self.title("Edit entry" if entry else "New entry")
        self.transient(app.root)
        self.resizable(False, False)
        self.result: Entry | None = None

        e = entry or Entry(title="")
        self.vars = {k: tk.StringVar(value=getattr(e, k)) for k in ("title", "username", "password", "url", "totp")}
        body = ttk.Frame(self, padding=16); body.pack(fill="both")
        widgets = []

        def add_row(label, widget):
            widgets.append(ttk.Label(body, text=label))
            widgets.append(widget)

        title = ttk.Entry(body, textvariable=self.vars["title"], width=44)
        add_row("Title *", title)
        add_row("Username / email", ttk.Entry(body, textvariable=self.vars["username"], width=44))
        pf = ttk.Frame(body)
        PasswordField(pf, self.vars["password"], width=28).pack(side="left", fill="x", expand=True)
        ttk.Button(pf, text="Generate", command=self.open_generator).pack(side="left", padx=(4, 0))
        add_row("Password", pf)
        self.meter = StrengthMeter(body)
        widgets.append(self.meter)
        add_row("Website", ttk.Entry(body, textvariable=self.vars["url"], width=44))
        add_row("2FA secret (optional - base32 key or otpauth:// link)", PasswordField(body, self.vars["totp"], width=36))
        self.notes = tk.Text(body, width=44, height=5, wrap="word", font=("Segoe UI", 9))
        self.notes.insert("1.0", e.notes)
        add_row("Notes", self.notes)

        for row, w in enumerate(widgets):
            is_label = isinstance(w, ttk.Label)
            w.grid(row=row, column=0, sticky="w" if is_label else "ew", pady=(6, 0) if is_label else (2, 0))
        title.focus_set()
        self.vars["password"].trace_add("write", lambda *_: self.meter.update_for(self.vars["password"].get()))

        btns = ttk.Frame(body); btns.grid(row=len(widgets), column=0, sticky="e", pady=(12, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        ttk.Button(btns, text="Save", style="Accent.TButton", command=self.save).pack(side="left")
        self.bind("<Escape>", lambda _: self.destroy())
        self.after(50, lambda: self.meter.update_for(self.vars["password"].get()))
        self.grab_set()

    def open_generator(self):
        GeneratorDialog(self, on_use=self.vars["password"].set)

    def save(self):
        title = self.vars["title"].get().strip()
        if not title:
            return messagebox.showwarning(APP_NAME, "Title is required.", parent=self)
        secret = self.vars["totp"].get().strip()
        if secret:
            try:
                totp.parse(secret)
            except ValueError as err:
                return messagebox.showwarning(APP_NAME, str(err), parent=self)
        e = self.entry or Entry(title=title)
        e.totp = secret
        e.title = title
        e.username = self.vars["username"].get().strip()
        e.password = self.vars["password"].get()
        e.url = self.vars["url"].get().strip()
        e.notes = self.notes.get("1.0", "end-1c")
        self.result = e
        self.destroy()


class GeneratorDialog(tk.Toplevel):
    def __init__(self, master, on_use):
        super().__init__(master)
        self.title("Password generator")
        self.transient(master)
        self.resizable(False, False)
        self.on_use = on_use
        self.length = tk.IntVar(value=20)
        self.opts = {k: tk.BooleanVar(value=True) for k in ("lower", "upper", "digits", "symbols", "avoid_ambiguous")}
        self.out = tk.StringVar()

        body = ttk.Frame(self, padding=16); body.pack()
        ttk.Entry(body, textvariable=self.out, width=40, font=("Consolas", 11)).grid(row=0, column=0, columnspan=2, sticky="ew")
        self.meter = StrengthMeter(body); self.meter.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        ttk.Label(body, text="Length").grid(row=2, column=0, sticky="w")
        self.len_label = ttk.Label(body, text="20"); self.len_label.grid(row=2, column=1, sticky="e")
        ttk.Scale(body, from_=8, to=64, variable=self.length, command=lambda _: self.regen()).grid(
            row=3, column=0, columnspan=2, sticky="ew")
        labels = {"lower": "a-z", "upper": "A-Z", "digits": "0-9", "symbols": "!@#$...", "avoid_ambiguous": "Avoid look-alikes (l, 1, O, 0)"}
        for i, (k, text) in enumerate(labels.items()):
            ttk.Checkbutton(body, text=text, variable=self.opts[k], command=self.regen).grid(
                row=4 + i // 2, column=i % 2, sticky="w")
        btns = ttk.Frame(body); btns.grid(row=8, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btns, text="Regenerate", command=self.regen).pack(side="left", padx=4)
        ttk.Button(btns, text="Use password", style="Accent.TButton", command=self.use).pack(side="left")
        self.regen()
        self.grab_set()

    def regen(self):
        n = int(self.length.get())
        self.len_label.config(text=str(n))
        try:
            pw = generate_password(n, **{k: v.get() for k, v in self.opts.items()})
        except ValueError as e:
            pw = ""
            self.meter.label.config(text=str(e))
        self.out.set(pw)
        if pw:
            self.meter.update_for(pw)

    def use(self):
        if self.out.get():
            self.on_use(self.out.get())
        self.destroy()


class SecurityDialog(tk.Toplevel):
    """Master password, key file and recovery kit settings."""
    def __init__(self, app: "App"):
        super().__init__(app.root)
        self.app = app
        self.title("Security settings")
        self.transient(app.root)
        self.resizable(False, False)
        self.cur, self.new, self.confirm = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.buttons: list[ttk.Button] = []

        body = ttk.Frame(self, padding=16); body.pack(fill="both")
        ttk.Label(body, text="Current master password (required for any change)").pack(anchor="w")
        cur = PasswordField(body, self.cur); cur.pack(fill="x")
        cur.entry.focus_set()

        pw = ttk.LabelFrame(body, text="Master password", padding=10); pw.pack(fill="x", pady=(12, 0))
        ttk.Label(pw, text="New master password").pack(anchor="w")
        PasswordField(pw, self.new).pack(fill="x")
        self.meter = StrengthMeter(pw); self.meter.pack(fill="x", pady=4)
        ttk.Label(pw, text="Confirm new password").pack(anchor="w")
        PasswordField(pw, self.confirm).pack(fill="x")
        self._button(pw, "Change master password", self.change_password).pack(anchor="e", pady=(8, 0))
        self.new.trace_add("write", lambda *_: self.meter.update_for(self.new.get()))

        kf = ttk.LabelFrame(body, text="Key file (second factor)", padding=10); kf.pack(fill="x", pady=(12, 0))
        self.kf_status = ttk.Label(kf, wraplength=420, justify="left"); self.kf_status.pack(anchor="w")
        row = ttk.Frame(kf); row.pack(anchor="w", pady=(8, 0))
        self._button(row, "Create new key file…", self.create_keyfile).pack(side="left")
        self._button(row, "Use existing file…", self.use_keyfile).pack(side="left", padx=4)
        self.kf_remove = self._button(row, "Remove requirement", self.remove_keyfile)
        self.kf_remove.pack(side="left")

        rc = ttk.LabelFrame(body, text="Recovery kit", padding=10); rc.pack(fill="x", pady=(12, 0))
        self.rc_status = ttk.Label(rc, wraplength=420, justify="left"); self.rc_status.pack(anchor="w")
        row = ttk.Frame(rc); row.pack(anchor="w", pady=(8, 0))
        self._button(row, "Create new recovery kit", self.new_recovery).pack(side="left")
        self.rc_remove = self._button(row, "Remove recovery kit", self.remove_recovery)
        self.rc_remove.pack(side="left", padx=4)

        self.status = ttk.Label(body, text="", wraplength=440); self.status.pack(anchor="w", pady=(10, 0))
        ttk.Button(body, text="Close", command=self.destroy).pack(anchor="e", pady=(6, 0))
        self.refresh()
        self.grab_set()

    def _button(self, parent, text, command) -> ttk.Button:
        b = ttk.Button(parent, text=text, command=command)
        self.buttons.append(b)
        return b

    def refresh(self):
        v = self.app.vault
        self.kf_status.config(text=(
            "✓ Required. Unlocking needs your master password AND your key file." if v.requires_keyfile else
            "Not used. Optionally require a file (e.g. on a USB stick) in addition to your password."))
        self.kf_remove.state(["!disabled"] if v.requires_keyfile else ["disabled"])
        self.rc_status.config(text=(
            "✓ Set up. Creating a new kit makes the old recovery key stop working." if v.has_recovery else
            "⚠ Not set up. If you forget your master password, your data is lost."))
        self.rc_remove.state(["!disabled"] if v.has_recovery else ["disabled"])

    def run(self, work, success: str, after=None):
        """Verify the current password, then run work(current_password) in the background."""
        cur = self.cur.get()
        if not cur:
            return self.status.config(text="Enter your current master password first.", foreground="#c0392b")
        for b in self.buttons:
            b.state(["disabled"])
        self.status.config(text="Working...", foreground="#666")
        vault = self.app.vault

        def job():
            vault.require_password(cur)
            return work(cur)

        def done(result):
            if not self.winfo_exists():
                return
            for b in self.buttons:
                b.state(["!disabled"])
            self.refresh()
            self.status.config(text=success, foreground="#1e8449")
            if after:
                after(result)

        def failed(e):
            if not self.winfo_exists():
                return
            for b in self.buttons:
                b.state(["!disabled"])
            self.refresh()
            self.status.config(text=str(e), foreground="#c0392b")
        run_in_background(self.app.root, job, done, failed)

    # ----- master password -----
    def change_password(self):
        new = self.new.get()
        problem = new_password_problem(new, self.confirm.get())
        if problem:
            return self.status.config(text=problem, foreground="#c0392b")
        self.run(lambda cur: self.app.vault.change_master_password(cur, new), "Master password changed.",
                 after=lambda _: (self.new.set(""), self.confirm.set("")))

    # ----- key file -----
    def create_keyfile(self):
        path = filedialog.asksaveasfilename(parent=self, title="Create key file", initialfile="SecureVault.key",
                                            defaultextension=".key", filetypes=[("Key file", "*.key")])
        if not path:
            return
        if Path(path).exists():
            return self.status.config(text="That file already exists - choose a new name.", foreground="#c0392b")
        path = Path(path)

        def work(cur):
            crypto.create_keyfile(path)
            self.app.vault.set_keyfile(cur, path)
        self.run(work, "Key file is now required.", after=lambda _: self.keyfile_enabled(path, created=True))

    def use_keyfile(self):
        path = filedialog.askopenfilename(parent=self, title="Choose a file to use as key file")
        if not path:
            return
        if not messagebox.askokcancel(APP_NAME, (
                "The file's exact contents become part of your key. If the file is ever modified "
                "(even re-saved), it will stop working.\n\nA generated key file is safer than a photo or "
                "document. Continue?"), parent=self):
            return
        path = Path(path)
        self.run(lambda cur: self.app.vault.set_keyfile(cur, path), "Key file is now required.",
                 after=lambda _: self.keyfile_enabled(path, created=False))

    def keyfile_enabled(self, path: Path, created: bool):
        self.app.remember_keyfile(path)
        messagebox.showwarning(APP_NAME, (
            f"{'Created' if created else 'Using'} key file:\n{path}\n\n"
            "BACK IT UP NOW - copy it to a USB stick or second drive. Without it you can only "
            "get in with your recovery kit."
            + ("" if self.app.vault.has_recovery else
               "\n\nYou have NO recovery kit. Strongly consider creating one.")), parent=self)

    def remove_keyfile(self):
        if messagebox.askyesno(APP_NAME, "Stop requiring the key file? Only the master password will be needed.",
                               parent=self):
            self.run(lambda cur: self.app.vault.set_keyfile(cur, None), "Key file is no longer required.",
                     after=lambda _: self.app.forget_keyfile())

    # ----- recovery kit -----
    def new_recovery(self):
        if self.app.vault.has_recovery and not messagebox.askyesno(APP_NAME, (
                "Create a new recovery kit? Your current recovery key will stop working."), parent=self):
            return
        self.run(lambda cur: self.app.vault.new_recovery_key(), "New recovery kit created.",
                 after=lambda key: RecoveryKitDialog(self.app, key))

    def remove_recovery(self):
        if messagebox.askyesno(APP_NAME, (
                "Remove the recovery kit?\n\nIf you then forget your master password (or lose your key "
                "file), your data will be permanently lost."), icon="warning", parent=self):
            self.run(lambda cur: self.app.vault.remove_recovery(), "Recovery kit removed.")


class MainScreen(ttk.Frame):
    def __init__(self, app: "App"):
        super().__init__(app.root, padding=12)
        self.app = app
        self.query = tk.StringVar()

        top = ttk.Frame(self); top.pack(fill="x")
        ttk.Label(top, text="Search").pack(side="left")
        search = ttk.Entry(top, textvariable=self.query, width=30); search.pack(side="left", padx=6)
        self.query.trace_add("write", lambda *_: self.refresh())
        ttk.Button(top, text="🔒 Lock", command=app.lock).pack(side="right")
        ttk.Button(top, text="Security…", command=lambda: SecurityDialog(app)).pack(side="right", padx=6)
        ttk.Button(top, text="Import CSV…", command=self.import_csv).pack(side="right")

        cols = ("title", "username", "url", "2fa")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse")
        for c, label, w, stretch in (("title", "Title", 200, True), ("username", "Username", 220, True),
                                     ("url", "Website", 240, True), ("2fa", "2FA", 50, False)):
            self.tree.heading(c, text=label)
            self.tree.column(c, width=w, stretch=stretch, anchor="center" if c == "2fa" else "w")
        self.tree.pack(fill="both", expand=True, pady=10)
        self.tree.bind("<Double-1>", lambda _: self.edit())
        self.tree.bind("<Delete>", lambda _: self.delete())
        self.tree.bind("<<TreeviewSelect>>", lambda _: self.tick_totp(reschedule=False))

        self.totp_panel = ttk.Frame(self)
        ttk.Label(self.totp_panel, text="2FA code:").pack(side="left")
        self.totp_code = ttk.Label(self.totp_panel, text="", font=("Consolas", 16, "bold"))
        self.totp_code.pack(side="left", padx=8)
        self.totp_bar = ttk.Progressbar(self.totp_panel, length=120, maximum=30)
        self.totp_bar.pack(side="left")
        self.totp_secs = ttk.Label(self.totp_panel, text="", foreground="#666", width=4)
        self.totp_secs.pack(side="left", padx=4)
        ttk.Button(self.totp_panel, text="Copy 2FA code", command=self.copy_totp).pack(side="left", padx=8)

        bar = ttk.Frame(self); bar.pack(fill="x")
        ttk.Button(bar, text="+ Add", style="Accent.TButton", command=self.add).pack(side="left")
        ttk.Button(bar, text="Edit", command=self.edit).pack(side="left", padx=4)
        ttk.Button(bar, text="Delete", command=self.delete).pack(side="left")
        ttk.Button(bar, text="Copy password", command=lambda: self.copy("password")).pack(side="right")
        ttk.Button(bar, text="Copy username", command=lambda: self.copy("username")).pack(side="right", padx=4)
        self.status = ttk.Label(self, text="", foreground="#666"); self.status.pack(anchor="w", pady=(8, 0))

        self.bind_all("<Control-f>", lambda _: search.focus_set())
        self.bind_all("<Control-n>", lambda _: self.add())
        self.bind_all("<Control-l>", lambda _: app.lock())
        self.bind_all("<Control-b>", lambda _: self.copy("username"))
        self.bind_all("<Control-c>", lambda e: self.copy("password") if e.widget is self.tree else None)
        self.bind_all("<Control-t>", lambda _: self.copy_totp())
        self._totp_job = None
        self.refresh()
        self.tick_totp()
        search.focus_set()

    def destroy(self):
        for seq in ("<Control-f>", "<Control-n>", "<Control-l>", "<Control-b>", "<Control-c>", "<Control-t>"):
            self.unbind_all(seq)
        if self._totp_job:
            self.after_cancel(self._totp_job)
        super().destroy()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for e in self.app.vault.search(self.query.get()):
            self.tree.insert("", "end", iid=e.id, values=(e.title, e.username, e.url, "✓" if e.totp else ""))
        n = len(self.app.vault.entries)
        self.status.config(text=f"{n} entr{'y' if n == 1 else 'ies'}  ·  auto-locks after "
                                f"{AUTO_LOCK_SECONDS // 60} min idle  ·  Ctrl+N add, Ctrl+F search, "
                                f"Ctrl+T copy 2FA, Ctrl+L lock")
        self.tick_totp(reschedule=False)

    # ----- 2FA -----
    def _selected_totp(self) -> totp.TotpConfig | None:
        e = self.selected()
        if not e or not e.totp:
            return None
        try:
            return totp.parse(e.totp)
        except ValueError:
            return None

    def tick_totp(self, reschedule: bool = True):
        cfg = self._selected_totp()
        if cfg:
            c = totp.code(cfg)
            left = totp.seconds_remaining(cfg)
            self.totp_code.config(text=f"{c[:len(c) // 2]} {c[len(c) // 2:]}",
                                  foreground="#c0392b" if left <= 5 else "")
            self.totp_bar.config(maximum=cfg.period, value=left)
            self.totp_secs.config(text=f"{left}s")
            if not self.totp_panel.winfo_manager():
                self.totp_panel.pack(fill="x", before=self.status, pady=(0, 4))
        elif self.totp_panel.winfo_manager():
            self.totp_panel.pack_forget()
        if reschedule:
            self._totp_job = self.after(1000, self.tick_totp)

    def copy_totp(self):
        e, cfg = self.selected(), self._selected_totp()
        if not cfg:
            return self.status.config(text="Selected entry has no 2FA secret.")
        self.app.copy_secret(totp.code(cfg))
        self.status.config(text=f"2FA code for '{e.title}' copied - valid for {totp.seconds_remaining(cfg)}s.")

    # ----- import -----
    def import_csv(self):
        path = filedialog.askopenfilename(
            parent=self, title="Import passwords from CSV",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            result = importer.parse_csv_file(Path(path), self.app.vault.entries)
        except (ValueError, OSError, UnicodeDecodeError) as err:
            return messagebox.showerror(APP_NAME, f"Could not import:\n{err}", parent=self)

        skipped = []
        if result.skipped_duplicates:
            skipped.append(f"{result.skipped_duplicates} already in your vault")
        if result.skipped_empty:
            skipped.append(f"{result.skipped_empty} empty rows")
        summary = (f"Detected format: {result.source_format}\n\n"
                   f"{len(result.entries)} new entries will be imported."
                   + (f"\nSkipped: {', '.join(skipped)}." if skipped else ""))
        if not result.entries:
            return messagebox.showinfo(APP_NAME, summary + "\n\nNothing to import.", parent=self)
        if not messagebox.askokcancel(APP_NAME, summary + "\n\nImport now?", parent=self):
            return
        self.app.vault.add_many(result.entries)
        self.refresh()

        if messagebox.askyesno(APP_NAME, (
                f"Imported {len(result.entries)} entries.\n\n"
                "The CSV file contains ALL your passwords in plain text. "
                "Delete it now?\n\n" + path), icon="warning", parent=self):
            try:
                Path(path).unlink()
                messagebox.showinfo(APP_NAME, (
                    "CSV deleted.\n\nAlso check your Downloads folder and Recycle Bin for other copies, "
                    "and remove saved passwords from your browser if you no longer want them there."),
                    parent=self)
            except OSError as err:
                messagebox.showerror(APP_NAME, f"Couldn't delete the file - please delete it manually:\n{err}",
                                     parent=self)

    def selected(self) -> Entry | None:
        sel = self.tree.selection()
        return next((e for e in self.app.vault.entries if sel and e.id == sel[0]), None)

    def add(self):
        dlg = EntryDialog(self.app, None)
        self.wait_window(dlg)
        if dlg.result and not self.app.vault.is_locked:
            self.app.vault.add(dlg.result)
            self.refresh()

    def edit(self):
        e = self.selected()
        if not e:
            return
        dlg = EntryDialog(self.app, Entry(**vars(e)))
        self.wait_window(dlg)
        if dlg.result and not self.app.vault.is_locked:
            self.app.vault.update(dlg.result)
            self.refresh()

    def delete(self):
        e = self.selected()
        if e and messagebox.askyesno(APP_NAME, f"Delete '{e.title}'? This cannot be undone."):
            self.app.vault.delete(e.id)
            self.refresh()

    def copy(self, field: str):
        e = self.selected()
        if not e:
            return self.status.config(text="Select an entry first.")
        self.app.copy_secret(getattr(e, field))
        self.status.config(text=f"{field.capitalize()} for '{e.title}' copied - clipboard clears in "
                                f"{CLIPBOARD_CLEAR_SECONDS}s.")


# --------------------------------------------------------------------------
# App controller
# --------------------------------------------------------------------------
class App:
    def __init__(self, vault_path: Path):
        self.vault_path = vault_path
        self.vault: Vault | None = None
        self.screen: ttk.Frame | None = None
        self.failed_attempts = 0
        self.locked_until = 0.0
        self.last_activity = time.monotonic()
        self._clip_job = None

        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("780x580")
        self.root.minsize(600, 480)
        self.clipboard = SecureClipboard(self.root)
        self._style()

        for seq in ("<Key>", "<Button>", "<Motion>"):
            self.root.bind_all(seq, self._touch, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self.root.after(1000, self._idle_check)

        if vault_path.exists():
            self.show(UnlockScreen(self))
        else:
            self.show(SetupScreen(self))

    def _style(self):
        s = ttk.Style(self.root)
        if "vista" in s.theme_names():
            s.theme_use("vista")
        s.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        s.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))
        s.configure("Treeview", rowheight=26)
        s.configure("Link.TButton", foreground="#1a5fb4", padding=0)

    def show(self, screen: ttk.Frame):
        if self.screen:
            self.screen.destroy()
        self.screen = screen
        screen.pack(fill="both", expand=True)

    # ----- settings (only stores the key file's location, never its contents) -----
    @property
    def _settings_path(self) -> Path:
        return default_vault_path().parent / "settings.json"

    def _settings(self) -> dict:
        try:
            return json.loads(self._settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _vault_key(self) -> str:
        return str(self.vault_path.resolve()).lower()

    def remembered_keyfile(self) -> str | None:
        return self._settings().get("keyfiles", {}).get(self._vault_key())

    def remember_keyfile(self, path: Path | None):
        settings = self._settings()
        keyfiles = settings.setdefault("keyfiles", {})
        if path:
            keyfiles[self._vault_key()] = str(Path(path).resolve())
        else:
            keyfiles.pop(self._vault_key(), None)
        try:
            self._settings_path.parent.mkdir(parents=True, exist_ok=True)
            self._settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        except OSError:
            pass

    def forget_keyfile(self):
        self.remember_keyfile(None)

    # ----- lock / unlock -----
    def on_unlocked(self, vault: Vault):
        self.vault = vault
        self.failed_attempts = 0
        self._touch()
        self.show(ResetPasswordScreen(self) if vault.must_reset_password else MainScreen(self))

    def lock(self, reason: str = ""):
        for w in self.root.winfo_children():  # close any open dialogs
            if isinstance(w, tk.Toplevel):
                w.destroy()
        if self.vault:
            self.vault.lock()
            self.vault = None
        self.clear_clipboard()
        self.show(UnlockScreen(self, reason))

    def register_failed_attempt(self):
        # Exponential back-off after 3 failures (on top of Argon2's own cost).
        self.failed_attempts += 1
        if self.failed_attempts >= 3:
            self.locked_until = time.monotonic() + min(2 ** (self.failed_attempts - 2), 300)

    def lockout_remaining(self) -> float:
        return max(0.0, self.locked_until - time.monotonic())

    def _touch(self, *_):
        self.last_activity = time.monotonic()

    def _idle_check(self):
        if self.vault and time.monotonic() - self.last_activity > AUTO_LOCK_SECONDS:
            self.lock("Locked automatically due to inactivity.")
        self.root.after(1000, self._idle_check)

    # ----- clipboard -----
    def copy_secret(self, text: str):
        self.clipboard.copy(text)
        if self._clip_job:
            self.root.after_cancel(self._clip_job)
        self._clip_job = self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000, self.clear_clipboard)

    def clear_clipboard(self):
        self._clip_job = None
        try:
            self.clipboard.clear_if_ours()
        except OSError:
            pass

    def quit(self):
        if self.vault:
            self.vault.lock()
        self.clear_clipboard()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    if sys.platform == "win32":
        try:  # crisp text on high-DPI displays
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default_vault_path()
    App(path).run()


if __name__ == "__main__":
    main()
