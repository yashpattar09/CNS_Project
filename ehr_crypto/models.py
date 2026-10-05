"""Serialisable records that travel alongside the ciphertext.

Two JSON documents describe the vault's state:

* `UserRecord`  — one per user: their public key + the passphrase-wrapped
  private key + when they registered. Never contains the passphrase.
* `Sidecar`     — one per encrypted file: everything needed to decrypt it
  *except* the private key, i.e. the RSA-wrapped AES key, the GCM nonce and
  tag, the SHA-256 of the original bytes, and human-readable metadata.

Neither record ever contains plaintext PDF bytes or a raw AES key.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict

SCHEME = "RSA-3072-OAEP-SHA256 + AES-256-GCM"


@dataclass
class UserRecord:
    username: str
    public_pem: str
    protected_private_key: Dict[str, Any]  # {kdf, salt, nonce, ciphertext}
    rsa_bits: int
    created_at: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "UserRecord":
        d = json.loads(raw)
        return cls(
            username=d["username"],
            public_pem=d["public_pem"],
            protected_private_key=d["protected_private_key"],
            rsa_bits=int(d["rsa_bits"]),
            created_at=d["created_at"],
        )


@dataclass
class Sidecar:
    file_id: str
    filename: str
    size: int  # size of the *original* plaintext, in bytes
    created_at: str
    scheme: str
    wrapped_key: str  # base64 — AES key encrypted with the owner's RSA public key
    nonce: str        # base64 — 96-bit AES-GCM nonce
    tag: str          # base64 — 128-bit AES-GCM authentication tag
    sha256: str       # hex — SHA-256 of the original plaintext (integrity check)
    aad: str          # additional authenticated data (the file_id) bound into GCM
    owner: str = ""   # username of the owner (metadata only; not a security control)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "Sidecar":
        d = json.loads(raw)
        return cls(
            file_id=d["file_id"],
            filename=d["filename"],
            size=int(d["size"]),
            created_at=d["created_at"],
            scheme=d["scheme"],
            wrapped_key=d["wrapped_key"],
            nonce=d["nonce"],
            tag=d["tag"],
            sha256=d["sha256"],
            aad=d["aad"],
            owner=d.get("owner", ""),
            extra=dict(d.get("extra", {})),
        )
