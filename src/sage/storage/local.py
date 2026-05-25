"""LocalStorage — filesystem-backed StorageBackend implementation.

Writes artifacts to ``<base_dir>/<category>/<filename>``.
Directories are created on demand.
"""

from __future__ import annotations

from pathlib import Path

from .backend import StorageBackend


class LocalStorage(StorageBackend):
    """Store artifacts on the local filesystem under *base_dir*.

    Args:
        base_dir: Root directory for all artifact categories.
                  Relative paths are resolved relative to the current
                  working directory at instantiation time.
    """

    def __init__(self, base_dir: str | Path = "input") -> None:
        self._base = Path(base_dir).resolve()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _path(self, category: str, filename: str) -> Path:
        return self._base / category / filename

    # ------------------------------------------------------------------
    # StorageBackend interface
    # ------------------------------------------------------------------

    def save(self, category: str, filename: str, data: bytes | str) -> None:
        target = self._path(category, filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            target.write_text(data, encoding="utf-8")
        else:
            target.write_bytes(data)

    def load(self, category: str, filename: str) -> str:
        target = self._path(category, filename)
        if not target.exists():
            raise FileNotFoundError(f"Not found in local storage: {target}")
        return target.read_text(encoding="utf-8")

    def list_files(self, category: str) -> list[str]:
        cat_dir = self._base / category
        if not cat_dir.is_dir():
            return []
        return sorted(p.name for p in cat_dir.iterdir() if p.is_file())

    def exists(self, category: str, filename: str) -> bool:
        return self._path(category, filename).exists()
