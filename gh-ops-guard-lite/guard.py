#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import os
import re
import sys
import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

EXIT_OK = 0
EXIT_FINDINGS = 2
EXIT_ERROR = 1

DEFAULT_CONFIG = "ops_guard.yml"


@dataclass
class Finding:
    kind: str
    path: str
    message: str
    line: int | None = None

    def format(self) -> str:
        loc = f":{self.line}" if self.line is not None else ""
        return f"[{self.kind}] {self.path}{loc} - {self.message}"


def load_config(repo_root: Path, config_path: str) -> dict:
    p = repo_root / config_path
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {p}")
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def repo_root_from_cwd() -> Path:
    # Lite: assume current dir is repo root if .git exists, else use cwd.
    cwd = Path.cwd().resolve()
    if (cwd / ".git").exists():
        return cwd
    return cwd


def glob_paths(root: Path, patterns: List[str]) -> List[Path]:
    out: List[Path] = []
    for pat in patterns:
        # fnmatch doesn't support ** by itself with Path.rglob nicely, so use rglob('*') then filter.
        for p in root.rglob("*"):
            rel = p.relative_to(root).as_posix()
            if fnmatch.fnmatch(rel, pat):
                out.append(p)
    # unique + stable
    seen = set()
    uniq = []
    for p in out:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    return uniq


def is_excluded(rel_posix: str, exclude_globs: List[str]) -> bool:
    for pat in exclude_globs:
        if fnmatch.fnmatch(rel_posix, pat):
            return True
    return False


def check_required_env(cfg: dict, root: Path) -> List[Finding]:
    req = cfg.get("required_env") or []
    findings: List[Finding] = []
    for name in req:
        val = os.environ.get(name, "")
        if val is None or str(val).strip() == "":
            findings.append(Finding(
                kind="missing-env",
                path="(env)",
                message=f"Required env var is missing or empty: {name}"
            ))
    return findings


def scan_secrets(cfg: dict, root: Path) -> List[Finding]:
    ss = cfg.get("secret_scan") or {}
    if not ss.get("enabled", True):
        return []
    include_globs = ss.get("include_globs") or ["**/*"]
    exclude_globs = ss.get("exclude_globs") or []
    patterns = ss.get("patterns") or []

    compiled: List[Tuple[str, re.Pattern]] = []
    for it in patterns:
        name = it.get("name", "pattern")
        rx = it.get("regex", "")
        if not rx:
            continue
        compiled.append((name, re.compile(rx)))

    candidates = glob_paths(root, include_globs)
    findings: List[Finding] = []
    for p in candidates:
        if p.is_dir():
            continue
        rel = p.relative_to(root).as_posix()
        if is_excluded(rel, exclude_globs):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            for name, rx in compiled:
                if rx.search(line):
                    findings.append(Finding(
                        kind="secret-scan",
                        path=rel,
                        line=i,
                        message=f"Possible secret detected ({name})"
                    ))
    return findings


_SLEEP_RX = re.compile(r"\bsleep\s+([0-9]+)\b")


def scan_workflow_waste(cfg: dict, root: Path) -> List[Finding]:
    ws = cfg.get("workflow_waste_scan") or {}
    if not ws.get("enabled", True):
        return []
    max_sleep = int(ws.get("max_sleep_seconds", 300))
    globs = ws.get("workflow_globs") or [".github/workflows/*.yml", ".github/workflows/*.yaml"]
    paths = glob_paths(root, globs)

    findings: List[Finding] = []
    for p in paths:
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(txt.splitlines(), start=1):
            m = _SLEEP_RX.search(line)
            if not m:
                continue
            secs = int(m.group(1))
            if secs > max_sleep:
                findings.append(Finding(
                    kind="workflow-waste",
                    path=rel,
                    line=i,
                    message=f"sleep {secs}s exceeds max_sleep_seconds={max_sleep}"
                ))
    return findings


_USES_RX = re.compile(r"^\s*uses:\s*([^\s]+)\s*$")


def scan_action_pinning(cfg: dict, root: Path) -> Tuple[List[Finding], str]:
    ap = cfg.get("action_pinning") or {}
    if not ap.get("enabled", True):
        return [], "warn"
    mode = (ap.get("mode") or "warn").strip().lower()
    globs = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
    paths = glob_paths(root, globs)

    findings: List[Finding] = []
    for p in paths:
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(txt.splitlines(), start=1):
            m = _USES_RX.match(line)
            if not m:
                continue
            uses = m.group(1)
            # Skip local actions
            if uses.startswith("./"):
                continue
            # If pinned to full SHA, OK
            if "@" not in uses:
                continue
            ref = uses.split("@", 1)[1]
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            # Tag or branch => warn/fail depending on mode
            findings.append(Finding(
                kind="action-pinning",
                path=rel,
                line=i,
                message=f"Action not pinned to a commit SHA: {uses}"
            ))
    return findings, mode


def print_report(findings: List[Finding]) -> None:
    if not findings:
        print("OK: no findings")
        return
    print("Findings:")
    for f in findings:
        print(" - " + f.format())


def init_config_if_missing(root: Path, config_path: str) -> None:
    p = root / config_path
    if p.exists():
        print(f"Config already exists: {p}")
        return
    # Ship a default config by copying from repo file if present; otherwise create minimal.
    default = root / "ops_guard.yml"
    if default.exists() and default.name == config_path:
        print(f"Config already exists: {p}")
        return
    minimal = """required_env: []
secret_scan:
  enabled: true
  include_globs: ["**/*.py", "**/*.yml", "**/*.yaml", "**/*.json", "**/*.md"]
  exclude_globs: [".git/**", ".venv/**", "node_modules/**", "dist/**", "build/**"]
  patterns:
    - name: "Private key block"
      regex: "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
workflow_waste_scan:
  enabled: true
  max_sleep_seconds: 300
  workflow_globs: [".github/workflows/*.yml", ".github/workflows/*.yaml"]
action_pinning:
  enabled: true
  mode: "warn"
"""
    p.write_text(minimal, encoding="utf-8")
    print(f"Wrote: {p}")


def main() -> int:
    parser = argparse.ArgumentParser(description="GH Ops Guard Lite")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--init", action="store_true", help="Create a minimal config file if missing")
    parser.add_argument("--check", action="store_true", help="Run checks (default action)")
    args = parser.parse_args()

    root = repo_root_from_cwd()

    try:
        if args.init:
            init_config_if_missing(root, args.config)
            if not args.check:
                return EXIT_OK

        cfg = load_config(root, args.config)

        findings: List[Finding] = []
        findings += check_required_env(cfg, root)
        findings += scan_secrets(cfg, root)
        findings += scan_workflow_waste(cfg, root)

        pin_findings, pin_mode = scan_action_pinning(cfg, root)
        # If warn-mode, print but do not fail.
        if pin_findings and pin_mode == "warn":
            print("Warnings:")
            for f in pin_findings:
                print(" - " + f.format())
        elif pin_findings and pin_mode == "fail":
            findings += pin_findings

        print_report(findings)
        return EXIT_FINDINGS if findings else EXIT_OK

    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        print("Tip: run `python guard.py --init` to create a config file.")
        return EXIT_ERROR
    except Exception as e:
        print(f"ERROR: {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
