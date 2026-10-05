"""Per-user RSA key management.

Each user gets their own RSA-3072 key pair:
  * the **public** key wraps (encrypts) per-file AES keys — anyone can hold it;
  * the **private** key unwraps them — only its owner may ever recover it.

The private key is never stored in the clear. We serialise it to PKCS#8 PEM and
encrypt those bytes with AES-256-GCM under a KEK derived from the user's EHR
passphrase (see `kdf.py`). Feeding the wrong passphrase yields a wrong KEK, and
AES-GCM's authentication tag then fails to verify — which is exactly how we
detect an incorrect passphrase without ever storing the passphrase itself.
"""

from __future__ import annotations

import base64
import os
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import AuthError
from .kdf import KdfParams, derive_kek

RSA_BITS = 3072
_PRIVATE_KEY_AAD = b"ehr-private-key-v1"


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def generate_keypair(bits: int = RSA_BITS) -> RSAPrivateKey:
    """Create a fresh RSA private key (the public key is derived from it)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def public_key_to_pem(private_key: RSAPrivateKey) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_public_key(pem: str) -> RSAPublicKey:
    return serialization.load_pem_public_key(pem.encode("ascii"))


def protect_private_key(
    private_key: RSAPrivateKey,
    passphrase: str,
    kdf: KdfParams,
) -> Dict[str, Any]:
    """Encrypt the private key at rest with a passphrase-derived KEK.

    Returns a JSON-serialisable dict holding the KDF descriptor, the random salt,
    the GCM nonce and the ciphertext (which already includes the auth tag).
    """
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # we encrypt it ourselves, below
    )

    salt = os.urandom(16)
    nonce = os.urandom(12)
    kek = derive_kek(passphrase, salt, kdf)
    blob = AESGCM(kek).encrypt(nonce, private_pem, _PRIVATE_KEY_AAD)

    return {
        "kdf": kdf.to_dict(),
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(blob),
    }


def unlock_private_key(protected: Dict[str, Any], passphrase: str) -> RSAPrivateKey:
    """Reverse `protect_private_key`. Raises `AuthError` on a wrong passphrase."""
    kdf = KdfParams.from_dict(protected["kdf"])
    salt = _b64d(protected["salt"])
    nonce = _b64d(protected["nonce"])
    blob = _b64d(protected["ciphertext"])
    kek = derive_kek(passphrase, salt, kdf)

    try:
        private_pem = AESGCM(kek).decrypt(nonce, blob, _PRIVATE_KEY_AAD)
    except InvalidTag as exc:
        # Wrong KEK -> tag mismatch. The passphrase was incorrect.
        raise AuthError("Incorrect EHR passphrase.") from exc

    return serialization.load_pem_private_key(private_pem, password=None)


def new_protected_keypair(passphrase: str, kdf: KdfParams, bits: int = RSA_BITS) -> Tuple[str, Dict[str, Any]]:
    """Convenience: generate a keypair and return (public_pem, protected_private)."""
    private_key = generate_keypair(bits)
    return public_key_to_pem(private_key), protect_private_key(private_key, passphrase, kdf)
