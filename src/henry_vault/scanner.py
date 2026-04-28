from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    kind: str
    preview: str
    matched_vault_name: str | None = None


TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("discord-bot-token", re.compile(r"\bMTA[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{20,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {
    "",
    ".env",
    ".txt",
    ".py",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".sh",
    ".ini",
    ".cfg",
}


def scan_path(path: str | Path, known_secret_values: dict[str, str] | None = None) -> list[Finding]:
    root = Path(path)
    files = [root] if root.is_file() else _iter_files(root)
    findings: list[Finding] = []
    for file_path in files:
        if file_path.name == ".env" or file_path.name.startswith(".env."):
            findings.append(Finding(path=file_path, line=1, kind="dotenv-file", preview="dotenv file present"))
        if not _looks_text(file_path):
            continue
        try:
            lines = file_path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            for kind, pattern in TOKEN_PATTERNS:
                for match in pattern.finditer(line):
                    findings.append(Finding(path=file_path, line=line_no, kind=kind, preview=_mask(match.group(0))))
            for name, value in (known_secret_values or {}).items():
                if value and value in line:
                    findings.append(
                        Finding(
                            path=file_path,
                            line=line_no,
                            kind="known-vault-secret",
                            preview=_mask(value),
                            matched_vault_name=name,
                        )
                    )
    return findings


def _iter_files(root: Path):
    for file_path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in file_path.parts):
            continue
        if file_path.is_file():
            yield file_path


def _looks_text(path: Path) -> bool:
    return path.suffix in TEXT_SUFFIXES or path.name.startswith(".env")


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return "***"
    return f"{secret[:3]}...{secret[-3:]} ({len(secret)} chars)"
