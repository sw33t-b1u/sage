"""StorageBackend ABC — defines the interface for artifact I/O.

Implementations: LocalStorage (local.py), GCSStorage (gcs.py).
Use create_storage_backend() in __init__.py to instantiate the correct
backend from Config.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class StorageBackend(ABC):
    """Abstract base class for artifact storage.

    Categories map to subdirectories or GCS prefixes:
      - pir          BEACON PIR outputs
      - assets       BEACON assets outputs
      - stix         TRACE STIX bundles
      - plans        collection_plan, sources_candidate
      - crawl_state  TRACE crawl state files
    """

    @abstractmethod
    def save(self, category: str, filename: str, data: bytes | str) -> None:
        """Persist *data* to <category>/<filename>.

        If *data* is str it is encoded as UTF-8 before writing.
        Overwrites any existing file at the same path.
        """

    @abstractmethod
    def load(self, category: str, filename: str) -> str:
        """Return the contents of <category>/<filename> as a UTF-8 string.

        Raises FileNotFoundError if the file does not exist.
        """

    @abstractmethod
    def load_bytes(self, category: str, filename: str) -> bytes:
        """Return the raw bytes of <category>/<filename>.

        Binary-safe counterpart of :meth:`load` for artifacts that are not
        UTF-8 text (e.g. the ``db/sage.db`` SQLite file).

        Raises FileNotFoundError if the file does not exist.
        """

    @abstractmethod
    def list_files(self, category: str) -> list[str]:
        """Return filenames (not full paths) present under *category*.

        Returns an empty list if the category does not exist yet.
        """

    @abstractmethod
    def exists(self, category: str, filename: str) -> bool:
        """Return True if <category>/<filename> exists in the backend."""
