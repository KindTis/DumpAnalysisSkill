from __future__ import annotations

from pathlib import Path


TEXT_EXTENSIONS = {
    ".md",
    ".py",
    ".yaml",
    ".yml",
    ".json",
    ".txt",
    ".ini",
}

SKIP_PARTS = {".git", ".pytest_cache", "__pycache__"}
UTF8_BOM = b"\xef\xbb\xbf"


def _should_check(path: Path, repo_root: Path) -> bool:
    rel = path.relative_to(repo_root)
    if any(part in SKIP_PARTS for part in rel.parts):
        return False
    if path.name in {"LICENSE"}:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def test_repository_text_files_are_utf8_without_bom() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bom_files: list[str] = []

    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if not _should_check(path, repo_root):
            continue
        if path.read_bytes().startswith(UTF8_BOM):
            bom_files.append(str(path.relative_to(repo_root)))

    assert not bom_files, f"UTF-8 BOM detected: {bom_files}"
