#!/usr/bin/env python3
"""Fails on CJK text outside the allowlist: the repository is English-only.

Scans every tracked text file (git ls-files) for Han, kana, hangul and CJK/fullwidth punctuation. A line passes when
an allowlist entry matches its path (fnmatch glob, `*` crosses directories) and, if the entry has one, its line regex.
An entry that no longer matches any CJK line is stale and fails too, so the allowlist only shrinks with the code.

Allowlist (default .github/cjk-allowlist.txt), one entry per line, `#` starts a comment:
    <path glob> | <line regex or empty> | <reason>

usage: cjk_check.py [--allowlist FILE] [--root DIR]    exit 0 = clean, 1 = findings, 2 = bad allowlist
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys

CJK = re.compile("[\u3000-\u303f\u3040-\u30ff\u3100-\u312f\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff\uff00-\uffef]")
MAX_SHOWN = 200


def load(path: str) -> list[tuple[str, re.Pattern | None, str]]:
    entries = []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|", 2)]
            if len(parts) != 3 or not parts[0] or len(parts[2]) < 10:
                sys.exit(f"{path}:{n}: expected '<path glob> | <line regex or empty> | <reason of 10+ characters>'")
            try:
                regex = re.compile(parts[1]) if parts[1] else None
            except re.error as e:
                sys.exit(f"{path}:{n}: bad line regex: {e}")
            entries.append((parts[0], regex, parts[2]))
    return entries


def tracked(root: str) -> list[str]:
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--allowlist", default=".github/cjk-allowlist.txt")
    ap.add_argument("--root", default=".")
    a = ap.parse_args()
    entries = load(f"{a.root}/{a.allowlist}")
    used = [False] * len(entries)
    findings = []
    for path in tracked(a.root):
        if path == a.allowlist:
            continue
        try:
            with open(f"{a.root}/{path}", "rb") as f:
                data = f.read()
        except (IsADirectoryError, FileNotFoundError):  # submodule or deleted in the work tree
            continue
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", "replace")
        if not CJK.search(text):
            continue
        mine = [i for i, (glob, _, _) in enumerate(entries) if fnmatch.fnmatchcase(path, glob)]
        for n, line in enumerate(text.splitlines(), 1):
            if not CJK.search(line):
                continue
            hit = next((i for i in mine if entries[i][1] is None or entries[i][1].search(line)), None)
            if hit is None:
                findings.append(f"{path}:{n}: {line.strip()[:120]}")
            else:
                used[hit] = True
    stale = [f"{g} | {r.pattern if r else ''} | {why}" for (g, r, why), u in zip(entries, used) if not u]
    for f in findings[:MAX_SHOWN]:
        print(f)
    if len(findings) > MAX_SHOWN:
        print(f"... and {len(findings) - MAX_SHOWN} more")
    for s in stale:
        print(f"stale allowlist entry (matches no CJK line): {s}")
    if findings or stale:
        print(f"cjk-check: {len(findings)} CJK line(s) outside {a.allowlist}, {len(stale)} stale entr(ies). "
              "Write English; CJK belongs only in locale files and in tests of CJK handling, each listed with a reason.")
        return 1
    print(f"cjk-check: clean ({len(entries)} allowlist entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
