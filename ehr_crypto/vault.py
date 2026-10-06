"""High-level vault API: register / login / upload / list / view / delete.

This ties the crypto core (`keys`, `hybrid`) to a storage backend and enforces
per-user scoping. Object layout inside any backend:

    users/<username>.json            -> UserRecord (public key + wrapped private key)
    docs/<username>/<file_id>.enc    -> ciphertext
    docs/<username>/<file_id>.json   -> Sidecar (wrapped AES key, nonce, tag, sha256)

Security notes:
* The passphrase is only ever used transiently to unlock the private key; it is
  never written to storage.
* A `Session` holds the decrypted private key in memory only. Callers (the
  Streamlit app) keep it in `st.session_state` for the browser session and drop
  it on logout.
* Ownership is enforced by cryptography, not just by path scoping: even if a user
  fetched another user's ciphertext, RSA-OAEP unwrap with their own private key
  would fail (`DecryptionError`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .exceptions import AuthError, StorageError
from .hybrid import decrypt_document, encrypt_document
from .kdf import default_params
from .keys import RSA_BITS, load_public_key, new_protected_keypair, unlock_private_key
from .models import Sidecar, UserRecord
from .storage import StorageBackend

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _validate_username(username: str) -> str:
    username = username.strip()
    if not _USERNAME_RE.match(username):
        raise AuthError(
            "Username must be 3-32 characters, letters/digits/._- only."
        )
    return username


@dataclass
class Session:
    """An authenticated session — holds the in-memory private key."""

    username: str
    public_key: RSAPublicKey
    private_key: RSAPrivateKey


class Vault:
    def __init__(self, backend: StorageBackend):
        self.backend = backend

    # --- paths --------------------------------------------------------------
    @staticmethod
    def _user_path(username: str) -> str:
        return f"users/{username}.json"

    @staticmethod
    def _doc_dir(username: str) -> str:
        return f"docs/{username}"

    def _enc_path(self, username: str, file_id: str) -> str:
        return f"{self._doc_dir(username)}/{file_id}.enc"

    def _sidecar_path(self, username: str, file_id: str) -> str:
        return f"{self._doc_dir(username)}/{file_id}.json"

    # --- accounts -----------------------------------------------------------
    def user_exists(self, username: str) -> bool:
        return self.backend.exists(self._user_path(username))

    def register(self, username: str, passphrase: str, *, kdf_algorithm: str = "argon2id") -> None:
        username = _validate_username(username)
        if len(passphrase) < 8:
            raise AuthError("Passphrase must be at least 8 characters.")
        if self.user_exists(username):
            raise AuthError(f"User '{username}' already exists.")

        kdf = default_params(kdf_algorithm)
        public_pem, protected = new_protected_keypair(passphrase, kdf)
        record = UserRecord(
            username=username,
            public_pem=public_pem,
            protected_private_key=protected,
            rsa_bits=RSA_BITS,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.backend.put_bytes(self._user_path(username), record.to_json().encode("utf-8"))

    def _load_user(self, username: str) -> UserRecord:
        try:
            raw = self.backend.get_bytes(self._user_path(username))
        except StorageError as exc:
            raise AuthError(f"No such user: '{username}'.") from exc
        return UserRecord.from_json(raw)

    def login(self, username: str, passphrase: str) -> Session:
        username = _validate_username(username)
        record = self._load_user(username)
        private_key = unlock_private_key(record.protected_private_key, passphrase)  # AuthError on bad pass
        public_key = load_public_key(record.public_pem)
        return Session(username=username, public_key=public_key, private_key=private_key)

    # --- documents ----------------------------------------------------------
    def upload(self, session: Session, filename: str, data: bytes) -> Sidecar:
        ciphertext, sidecar = encrypt_document(
            data, session.public_key, filename, owner=session.username
        )
        self.backend.put_bytes(self._enc_path(session.username, sidecar.file_id), ciphertext)
        self.backend.put_bytes(
            self._sidecar_path(session.username, sidecar.file_id),
            sidecar.to_json().encode("utf-8"),
        )
        return sidecar

    def list_documents(self, username: str) -> List[Sidecar]:
        """List a user's documents from their sidecars (no private key needed)."""
        paths = self.backend.list_prefix(self._doc_dir(username))
        sidecars: List[Sidecar] = []
        for path in paths:
            if not path.endswith(".json"):
                continue
            sidecars.append(Sidecar.from_json(self.backend.get_bytes(path)))
        sidecars.sort(key=lambda s: s.created_at, reverse=True)
        return sidecars

    def get_sidecar(self, username: str, file_id: str) -> Sidecar:
        return Sidecar.from_json(self.backend.get_bytes(self._sidecar_path(username, file_id)))

    def encrypted_blob(self, username: str, file_id: str) -> bytes:
        """Return the raw ciphertext exactly as stored at rest (no decryption)."""
        return self.backend.get_bytes(self._enc_path(username, file_id))

    def view(self, session: Session, file_id: str) -> bytes:
        """Decrypt and return one document's plaintext (owner + integrity checked)."""
        sidecar = self.get_sidecar(session.username, file_id)
        ciphertext = self.backend.get_bytes(self._enc_path(session.username, file_id))
        return decrypt_document(ciphertext, sidecar, session.private_key)

    def delete(self, username: str, file_id: str) -> None:
        self.backend.delete(self._enc_path(username, file_id))
        self.backend.delete(self._sidecar_path(username, file_id))

    # --- demo helper --------------------------------------------------------
    def tamper(self, username: str, file_id: str, *, byte_index: int = 0) -> None:
        """Flip one bit of a stored ciphertext, to demonstrate tamper detection.

        For teaching/viva only — corrupts the encrypted blob in place so the next
        `view()` raises `TamperError`.
        """
        path = self._enc_path(username, file_id)
        blob = bytearray(self.backend.get_bytes(path))
        if not blob:
            raise StorageError("Cannot tamper an empty ciphertext.")
        i = byte_index % len(blob)
        blob[i] ^= 0x01
        self.backend.put_bytes(path, bytes(blob))
