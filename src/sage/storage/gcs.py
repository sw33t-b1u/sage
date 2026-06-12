"""GCSStorage — Google Cloud Storage backed StorageBackend implementation.

Requires the ``google-cloud-storage`` package, which is intentionally NOT
listed as a hard dependency in pyproject.toml.  Install it separately when
using GCS mode:

    pip install google-cloud-storage

An ImportError is raised at instantiation time (not import time) so that
importing this module never fails, allowing LocalStorage to remain usable
without GCP dependencies.

Object key layout:  gs://<bucket>/<prefix>/<category>/<filename>
If *prefix* is empty the leading slash is omitted:
    gs://<bucket>/<category>/<filename>
"""

from __future__ import annotations

from .backend import StorageBackend


class GCSStorage(StorageBackend):
    """Store artifacts in Google Cloud Storage.

    Args:
        bucket:  GCS bucket name (without ``gs://``).
        prefix:  Optional key prefix applied before every category segment.
                 Empty string means no prefix.

    Raises:
        ImportError: If ``google-cloud-storage`` is not installed.
    """

    def __init__(self, bucket: str, prefix: str = "") -> None:
        try:
            from google.cloud import storage as gcs  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "GCS storage backend requires 'google-cloud-storage'. "
                "Install it with: pip install google-cloud-storage"
            ) from exc

        self._bucket_name = bucket
        self._prefix = prefix.rstrip("/")
        self._client = gcs.Client()
        self._bucket = self._client.bucket(bucket)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _blob_name(self, category: str, filename: str) -> str:
        parts = [p for p in (self._prefix, category, filename) if p]
        return "/".join(parts)

    # ------------------------------------------------------------------
    # StorageBackend interface
    # ------------------------------------------------------------------

    def save(self, category: str, filename: str, data: bytes | str) -> None:
        blob = self._bucket.blob(self._blob_name(category, filename))
        if isinstance(data, str):
            blob.upload_from_string(data.encode("utf-8"), content_type="application/octet-stream")
        else:
            blob.upload_from_string(data, content_type="application/octet-stream")

    def load(self, category: str, filename: str) -> str:
        blob = self._bucket.blob(self._blob_name(category, filename))
        if not blob.exists():
            raise FileNotFoundError(
                f"Not found in GCS: gs://{self._bucket_name}/{self._blob_name(category, filename)}"
            )
        return blob.download_as_text(encoding="utf-8")

    def load_bytes(self, category: str, filename: str) -> bytes:
        blob = self._bucket.blob(self._blob_name(category, filename))
        if not blob.exists():
            raise FileNotFoundError(
                f"Not found in GCS: gs://{self._bucket_name}/{self._blob_name(category, filename)}"
            )
        return blob.download_as_bytes()

    def list_files(self, category: str) -> list[str]:
        parts = [p for p in (self._prefix, category) if p]
        prefix_path = "/".join(parts) + "/"
        blobs = self._client.list_blobs(self._bucket_name, prefix=prefix_path, delimiter="/")
        names: list[str] = []
        for blob in blobs:
            # blob.name is the full object name; strip the prefix_path to get filename
            name = blob.name[len(prefix_path) :]
            if name:
                names.append(name)
        return sorted(names)

    def exists(self, category: str, filename: str) -> bool:
        blob = self._bucket.blob(self._blob_name(category, filename))
        return blob.exists()
