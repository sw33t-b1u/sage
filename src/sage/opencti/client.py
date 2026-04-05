"""OpenCTI client for fetching STIX 2.1 bundles.

Uses pycti's OpenCTIApiClient to call the STIX 2.1 export endpoint.
Bundles are saved to the GCS Landing Zone before being passed to the ETL worker.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog
from pycti import OpenCTIApiClient

logger = structlog.get_logger(__name__)

# Entity types returned by OpenCTI STIX export
EXPORT_TYPES = [
    "threat-actor",
    "intrusion-set",
    "attack-pattern",
    "vulnerability",
    "malware",
    "tool",
    "indicator",
    "relationship",
]


class OpenCTIClient:
    def __init__(self, url: str, token: str) -> None:
        self._api = OpenCTIApiClient(url, token, log_level="ERROR")

    def fetch_stix_bundle(
        self,
        modified_after: datetime | None = None,
    ) -> dict[str, Any]:
        """Fetch a STIX 2.1 bundle from OpenCTI.

        Args:
            modified_after: Only fetch objects updated after this timestamp.
                            Fetches all objects when None.

        Returns:
            STIX 2.1 Bundle dict (type="bundle", objects=[...])
        """
        filters = []
        if modified_after:
            filters.append(
                {
                    "key": "updated_at",
                    "values": [modified_after.strftime("%Y-%m-%dT%H:%M:%SZ")],
                    "operator": "gt",
                }
            )

        objects: list[dict] = []
        for entity_type in EXPORT_TYPES:
            try:
                items = self._api.stix2.export_entity(
                    entity_type=entity_type,
                    filters=filters,
                )
                if items:
                    objects.extend(items if isinstance(items, list) else [items])
                logger.info("fetched", entity_type=entity_type, count=len(objects))
            except Exception as exc:
                # Log a warning and continue fetching other types
                logger.warning(
                    "fetch_failed",
                    entity_type=entity_type,
                    error=str(exc),
                )

        bundle = {
            "type": "bundle",
            "id": f"bundle--{_new_uuid()}",
            "spec_version": "2.1",
            "objects": objects,
        }
        logger.info("bundle_ready", total_objects=len(objects))
        return bundle

    def save_bundle_to_gcs(
        self,
        bundle: dict[str, Any],
        bucket_name: str,
        source: str = "opencti",
    ) -> str:
        """Save the bundle to the GCS Landing Zone and return the GCS path."""
        from google.cloud import storage

        client = storage.Client()
        bucket = client.bucket(bucket_name)

        date_str = datetime.now(tz=UTC).strftime("%Y%m%d")
        blob_path = f"raw/stix/{date_str}/{source}/{bundle['id']}.json"
        blob = bucket.blob(blob_path)
        blob.upload_from_string(
            json.dumps(bundle, default=str),
            content_type="application/json",
        )
        logger.info("saved_to_gcs", path=blob_path)
        return f"gs://{bucket_name}/{blob_path}"


def _new_uuid() -> str:
    import uuid

    return str(uuid.uuid4())
