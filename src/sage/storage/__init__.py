"""sage.storage — artifact I/O abstraction layer.

Public API:
    StorageBackend   Abstract base class (backend.py)
    LocalStorage     Filesystem implementation (local.py)
    GCSStorage       Google Cloud Storage implementation (gcs.py)
    create_storage_backend   Factory function — picks impl from Config

Usage::

    from sage.storage import create_storage_backend
    from sage.config import Config

    config = Config.from_env()
    storage = create_storage_backend(config)
    content = storage.load("stix", "bundle_202605251700.json")
    files = storage.list_files("stix")
    found = storage.exists("assets", "assets_202605251700.json")
"""

from __future__ import annotations

from .backend import StorageBackend
from .local import LocalStorage

__all__ = [
    "StorageBackend",
    "LocalStorage",
    "GCSStorage",
    "create_storage_backend",
]


def create_storage_backend(config: object) -> StorageBackend:
    """Instantiate and return a StorageBackend based on *config*.

    Args:
        config: A ``sage.config.Config`` instance (typed as object to
                avoid circular imports; duck-typed access only).

    Returns:
        LocalStorage  when ``config.sage_storage == "local"`` (default).
        GCSStorage    when ``config.sage_storage == "gcs"``.

    Raises:
        ValueError:   If ``sage_storage`` is set to an unknown value.
        ImportError:  If ``sage_storage == "gcs"`` and
                      ``google-cloud-storage`` is not installed.
    """
    backend_name: str = getattr(config, "sage_storage", "local")

    if backend_name == "local":
        base_dir: str = getattr(config, "sage_storage_base_dir", "input")
        return LocalStorage(base_dir=base_dir)

    if backend_name == "gcs":
        from .gcs import GCSStorage  # deferred — optional dependency

        bucket: str = getattr(config, "sage_gcs_bucket", "")
        if not bucket:
            raise ValueError("SAGE_GCS_BUCKET must be set when SAGE_STORAGE=gcs")
        prefix: str = getattr(config, "sage_gcs_prefix", "")
        return GCSStorage(bucket=bucket, prefix=prefix)

    raise ValueError(f"Unknown storage backend '{backend_name}'. Valid values: 'local', 'gcs'.")


# Re-export GCSStorage lazily so `from sage.storage import GCSStorage`
# still works without importing google-cloud-storage at module load time.
def __getattr__(name: str) -> object:
    if name == "GCSStorage":
        from .gcs import GCSStorage  # noqa: PLC0415

        return GCSStorage
    raise AttributeError(f"module 'sage.storage' has no attribute {name!r}")
