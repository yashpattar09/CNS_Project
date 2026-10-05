"""The hybrid RSA + AES encryption scheme (the heart of the project).

Encrypt (per file):
  1. digest   = SHA-256(plaintext)                       # for integrity
  2. aes_key  = 32 random bytes                          # AES-256
     nonce    = 12 random bytes                          # GCM standard nonce
  3. ct||tag  = AES-256-GCM(aes_key, nonce, plaintext,   # confidentiality +
                            aad = file_id)               #   authenticity
  4. wrapped  = RSA-OAEP-SHA256(public_key, aes_key)     # only owner can unwrap
  -> store ciphertext + Sidecar{wrapped, nonce, tag, sha256, aad}. The raw
     aes_key and the plaintext are discarded.

Decrypt (per file):
  1. aes_key  = RSA-OAEP-SHA256(private_key, wrapped)    # fails for other users
  2. plaintext= AES-256-GCM.decrypt(...)                 # fails if tampered (tag)
  3. assert SHA-256(plaintext) == stored digest          # second integrity layer

Only well-established primitives from `cryptography` are used — no custom crypto.
"""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import DecryptionError, IntegrityError, TamperError
from .models import SCHEME, Sidecar

AES_KEY_LEN = 32   # 256-bit
GCM_NONCE_LEN = 12  # 96-bit (recommended for GCM)
GCM_TAG_LEN = 16   # 128-bit

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def encrypt_document(
    plaintext: bytes,
    public_key: RSAPublicKey,
    filename: str,
    *,
    owner: str = "",
    file_id: Optional[str] = None,
) -> Tuple[bytes, Sidecar]:
    """Encrypt one document. Returns (ciphertext_bytes, sidecar)."""
    file_id = file_id or uuid.uuid4().hex
    digest = hashlib.sha256(plaintext).hexdigest()

    aes_key = os.urandom(AES_KEY_LEN)
    nonce = os.urandom(GCM_NONCE_LEN)
    aad = file_id.encode("ascii")

    # AESGCM.encrypt returns ciphertext with the 16-byte tag appended; we split
    # the tag out and store it separately so the sidecar mirrors the standard
    # {ciphertext, nonce, tag} layout expected in the report.
    combined = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = combined[:-GCM_TAG_LEN], combined[-GCM_TAG_LEN:]

    wrapped_key = public_key.encrypt(aes_key, _OAEP)

    sidecar = Sidecar(
        file_id=file_id,
        filename=filename,
        size=len(plaintext),
        created_at=datetime.now(timezone.utc).isoformat(),
        scheme=SCHEME,
        wrapped_key=_b64e(wrapped_key),
        nonce=_b64e(nonce),
        tag=_b64e(tag),
        sha256=digest,
        aad=file_id,
        owner=owner,
    )
    return ciphertext, sidecar


def decrypt_document(
    ciphertext: bytes,
    sidecar: Sidecar,
    private_key: RSAPrivateKey,
) -> bytes:
    """Decrypt one document, verifying ownership and integrity.

    Raises:
        DecryptionError  – the wrapped key cannot be unwrapped (not this user).
        TamperError      – AES-GCM authentication failed (ciphertext/tag altered).
        IntegrityError   – SHA-256 of the recovered bytes doesn't match.
    """
    # 1) Unwrap the per-file AES key with the private RSA key.
    try:
        aes_key = private_key.decrypt(_b64d(sidecar.wrapped_key), _OAEP)
    except ValueError as exc:
        raise DecryptionError(
            "Could not unwrap the file key - this document was encrypted for a "
            "different user."
        ) from exc

    # 2) Authenticated decryption. A modified ciphertext or tag fails here.
    nonce = _b64d(sidecar.nonce)
    combined = ciphertext + _b64d(sidecar.tag)
    aad = sidecar.aad.encode("ascii")
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, combined, aad)
    except InvalidTag as exc:
        raise TamperError(
            "Integrity check failed: the encrypted file or its metadata was "
            "modified (AES-GCM authentication tag mismatch)."
        ) from exc

    # 3) Independent SHA-256 integrity check on the recovered plaintext.
    if hashlib.sha256(plaintext).hexdigest() != sidecar.sha256:
        raise IntegrityError(
            "Integrity check failed: the decrypted content does not match the "
            "original SHA-256 fingerprint."
        )

    return plaintext
