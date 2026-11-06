"""Validate the deliberately small public tree; never fetch private material."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = frozenset({
    ".gitignore", ".github/workflows/synthetic-tests.yml", "AGENTS.md", "README.md",
    "export-manifest.json", "rewizard/__init__.py", "rewizard/formats/__init__.py",
    "rewizard/formats/model.py", "rewizard/formats/elf_writer.py",
    "tests/test_formats.py", "tools/check_public_tree.py",
})
SOURCES = frozenset({"rewizard/formats/model.py", "rewizard/formats/elf_writer.py"})


def verify(root: Path = ROOT) -> dict:
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        files = {p for p in result.stdout.decode("utf-8").split("\0") if p}
    else:
        files = set()
        for path in root.rglob("*"):
            rel = path.relative_to(root)
            if "__pycache__" in rel.parts or rel.parts[0] == ".git":
                continue
            if path.is_symlink():
                raise ValueError("Symlinks are outside the public file boundary")
            if path.is_file():
                files.add(rel.as_posix())
    if files != ALLOWED:
        raise ValueError("Public file inventory differs from the reviewed allowlist")
    total = 0
    for name in sorted(files):
        path = root / name
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root.parent):
            raise ValueError("Symlinks are outside the public file boundary")
        data = path.read_bytes()
        if len(data) > 65536 or b"\0" in data:
            raise ValueError("Public files must be small UTF-8 text")
        data.decode("utf-8")
        total += len(data)
    if total > 131072:
        raise ValueError("Public snapshot exceeds its 128 KiB boundary")
    manifest = json.loads((root / "export-manifest.json").read_text(encoding="utf-8"))
    if set(manifest) != {"schema_version", "project", "scope", "files"}:
        raise ValueError("Unexpected manifest fields")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("Unsupported manifest schema")
    if manifest["project"] != "RE-Wizard-Public-Tests" or manifest["scope"] != "synthetic-format-components":
        raise ValueError("Unexpected manifest scope")
    entries = manifest["files"]
    if not isinstance(entries, list) or len(entries) != len(SOURCES):
        raise ValueError("Unexpected source list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
            raise ValueError("Unexpected source fields")
        name = entry["path"]
        if not isinstance(name, str) or name not in SOURCES or name in seen:
            raise ValueError("Unexpected or duplicate source path")
        seen.add(name)
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("Invalid source hash")
        data = (root / name).read_bytes()
        if type(entry["bytes"]) is not int or len(data) != entry["bytes"]:
            raise ValueError("Source size differs from reviewed manifest")
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Source hash differs from reviewed manifest")
    return {"files": len(files), "bytes": total, "source_files": len(seen)}


if __name__ == "__main__":
    try:
        print(json.dumps(verify(), sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print("Public boundary verification failed; inspect the local snapshot.", file=sys.stderr)
        raise SystemExit(1)
