"""Import passwords from CSV exports of common browsers / password managers.

Supported (auto-detected by column names): Chrome, Edge, Brave, Firefox, Safari,
Bitwarden, LastPass, 1Password, KeePass/KeePassXC, Dashlane, Proton Pass.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .store import Entry

# Our field -> header names used by various exporters (compared lower-cased).
ALIASES = {
    "title": ["name", "title", "account", "item name"],
    "url": ["url", "login_uri", "web site", "website", "uri", "urls", "origin_url"],
    "username": ["username", "login_username", "login name", "login", "user name", "email", "user"],
    "password": ["password", "login_password"],
    "notes": ["notes", "note", "comments", "extra", "note text"],
    "totp": ["totp", "login_totp", "otpauth", "one-time password", "otp", "otpurl"],
}


@dataclass
class ImportResult:
    entries: list[Entry] = field(default_factory=list)
    skipped_duplicates: int = 0
    skipped_empty: int = 0
    source_format: str = ""


def _detect(header: list[str]) -> str:
    h = set(header)
    if "login_password" in h:
        return "Bitwarden"
    if "httprealm" in h or "formactionorigin" in h:
        return "Firefox"
    if "grouping" in h:
        return "LastPass"
    if "otpauth" in h:
        return "1Password"
    if "login name" in h:
        return "KeePass"
    if {"name", "url", "username", "password"} <= h:
        return "Chrome / Edge / Brave"
    return "Generic CSV"


def _title_from_url(url: str) -> str:
    host = urlparse(url if "://" in url else f"https://{url}").hostname or ""
    return host.removeprefix("www.") or url


def parse_csv(text: str, existing: list[Entry] | None = None) -> ImportResult:
    text = text.lstrip("﻿")
    reader = csv.reader(io.StringIO(text))
    try:
        raw_header = next(reader)
    except StopIteration:
        raise ValueError("The file is empty")
    header = [h.strip().lower() for h in raw_header]

    col: dict[str, int] = {}
    for ours, names in ALIASES.items():
        for name in names:
            if name in header:
                col[ours] = header.index(name)
                break
    if "password" not in col:
        raise ValueError("Couldn't find a 'password' column - is this a password export CSV?")

    result = ImportResult(source_format=_detect(header))
    seen = {(e.title.lower(), e.username, e.password) for e in (existing or [])}
    seen |= {(e.url.lower(), e.username, e.password) for e in (existing or [])}

    for row in reader:
        get = lambda k: row[col[k]].strip() if k in col and col[k] < len(row) else ""  # noqa: E731
        password, username, url = get("password"), get("username"), get("url")
        if not password and not username:
            result.skipped_empty += 1
            continue
        title = get("title") or _title_from_url(url) or "Untitled"
        if (title.lower(), username, password) in seen or (url and (url.lower(), username, password) in seen):
            result.skipped_duplicates += 1
            continue
        seen.add((title.lower(), username, password))
        if url:
            seen.add((url.lower(), username, password))
        result.entries.append(Entry(title=title, username=username, password=get("password"),
                                    url=url, notes=get("notes"), totp=get("totp")))
    return result


def parse_csv_file(path: Path, existing: list[Entry] | None = None) -> ImportResult:
    # utf-8-sig handles the BOM some exporters (Excel, KeePass) add.
    return parse_csv(Path(path).read_text(encoding="utf-8-sig"), existing)
