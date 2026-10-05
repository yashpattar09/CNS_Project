"""ehr_crypto — a standalone hybrid RSA + AES encryption library for health records.

This package is deliberately free of any UI / Streamlit dependency so it can be
unit-tested and demoed on its own. The Streamlit app (`app.py`) and the CLI demo
(`demo.py`) are thin layers on top of it.
"""

from .exceptions import (
    AuthError,
    DecryptionError,
    EhrCryptoError,
    IntegrityError,
    StorageError,
    TamperError,
)
from .hybrid import decrypt_document, encrypt_document
from .kdf import KdfParams, default_params, derive_kek
from .keys import (
    generate_keypair,
    load_public_key,
    new_protected_keypair,
    protect_private_key,
    public_key_to_pem,
    unlock_private_key,
)
from .models import SCHEME, Sidecar, UserRecord
from .storage import LocalStorage, StorageBackend, SupabaseStorage
from .vault import Session, Vault

__all__ = [
    "AuthError",
    "DecryptionError",
    "EhrCryptoError",
    "IntegrityError",
    "StorageError",
    "TamperError",
    "encrypt_document",
    "decrypt_document",
    "KdfParams",
    "default_params",
    "derive_kek",
    "generate_keypair",
    "load_public_key",
    "new_protected_keypair",
    "protect_private_key",
    "public_key_to_pem",
    "unlock_private_key",
    "SCHEME",
    "Sidecar",
    "UserRecord",
    "LocalStorage",
    "StorageBackend",
    "SupabaseStorage",
    "Session",
    "Vault",
]
