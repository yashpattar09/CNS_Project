"""Pluggable blob storage for the vault.

The vault only ever hands the storage layer *already-encrypted* bytes and
plaintext JSON metadata — it has no idea whether those land on the local disk or
in a Supabase bucket. Two backends are provided:

* `LocalStorage`    — a folder on disk. Zero configuration, works offline; the
  default for local runs, the CLI demo and the tests.
* `SupabaseStorage` — a Supabase Storage bucket, reached over HTTPS/TLS. Used for
  real cloud persistence and Streamlit Cloud deployment. Requires the optional
  `supabase` package and credentials; nothing else in the Supabase project is
  touched (no tables, no RLS) — this is a brand-new bucket.

Object paths are POSIX-style strings, e.g. `docs/alice/ab12cd.enc`.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from .exceptions import StorageError


class StorageBackend(ABC):
    """A minimal key/value blob store keyed by POSIX-style object paths."""

    @abstractmethod
    def put_bytes(self, path: str, data: bytes) -> None: ...

    @abstractmethod
    def get_bytes(self, path: str) -> bytes: ...

    @abstractmethod
    def delete(self, path: str) -> None: ...

    @abstractmethod
    def exists(self, path: str) -> bool: ...

    @abstractmethod
    def list_prefix(self, prefix: str) -> List[str]:
        """Return the full object paths of every blob directly under `prefix`."""

    # Human-readable label for the UI ("Local vault" / "Supabase bucket ...").
    label: str = "storage"


class LocalStorage(StorageBackend):
    """Stores blobs as files under `root`."""

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.label = f"Local vault ({self.root})"

    def _full(self, path: str) -> Path:
        return self.root / path

    def put_bytes(self, path: str, data: bytes) -> None:
        p = self._full(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def get_bytes(self, path: str) -> bytes:
        p = self._full(path)
        if not p.exists():
            raise StorageError(f"Object not found: {path}")
        return p.read_bytes()

    def delete(self, path: str) -> None:
        p = self._full(path)
        if p.exists():
            p.unlink()

    def exists(self, path: str) -> bool:
        return self._full(path).exists()

    def list_prefix(self, prefix: str) -> List[str]:
        folder = self._full(prefix)
        if not folder.exists():
            return []
        return [
            f"{prefix.rstrip('/')}/{child.name}"
            for child in sorted(folder.iterdir())
            if child.is_file()
        ]


class SupabaseStorage(StorageBackend):
    """Stores blobs in a Supabase Storage bucket over HTTPS.

    `key` should be a service-role key (kept server-side in Streamlit secrets) so
    the app can manage objects; confidentiality never relies on it because every
    stored blob is already encrypted and every private key is passphrase-wrapped.
    """

    def __init__(self, url: str, key: str, bucket: str = "ehr-documents"):
        try:
            from supabase import create_client
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise StorageError(
                "The 'supabase' package is required for the Supabase backend. "
                "Install it with: pip install supabase"
            ) from exc
        self._client = create_client(url, key)
        self._bucket = bucket
        self.label = f"Supabase bucket '{bucket}'"

    @property
    def _store(self):
        return self._client.storage.from_(self._bucket)

    def put_bytes(self, path: str, data: bytes) -> None:
        try:
            self._store.upload(
                path=path,
                file=data,
                file_options={"upsert": "true", "content-type": "application/octet-stream"},
            )
        except Exception as exc:  # noqa: BLE001 - surface any client error uniformly
            raise StorageError(f"Supabase upload failed for {path}: {exc}") from exc

    def get_bytes(self, path: str) -> bytes:
        try:
            return self._store.download(path)
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Supabase download failed for {path}: {exc}") from exc

    def delete(self, path: str) -> None:
        try:
            self._store.remove([path])
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Supabase delete failed for {path}: {exc}") from exc

    def exists(self, path: str) -> bool:
        folder, _, name = path.rpartition("/")
        try:
            entries = self._store.list(folder or None)
        except Exception:  # noqa: BLE001
            return False
        return any(e.get("name") == name for e in entries)

    def list_prefix(self, prefix: str) -> List[str]:
        folder = prefix.rstrip("/")
        try:
            entries = self._store.list(folder or None)
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"Supabase list failed for {prefix}: {exc}") from exc
        # `.list` returns placeholder rows for empty folders; keep only real files.
        return [
            f"{folder}/{e['name']}"
            for e in entries
            if e.get("name") and e.get("id") is not None
        ]
