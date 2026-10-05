"""A different user cannot decrypt someone else's document.

This is the crux of "only that user can view it": the AES key is wrapped with the
owner's RSA public key, so only the owner's private key can unwrap it. A second
user's private key raises DecryptionError, and a wrong passphrase can't even
unlock a private key in the first place.
"""

import pytest

from ehr_crypto import (
    Vault,
    LocalStorage,
    decrypt_document,
)
from ehr_crypto.exceptions import AuthError, DecryptionError

PLAINTEXT = b"%PDF-1.4 alice private report body"


def test_other_users_private_key_cannot_decrypt(tmp_path):
    vault = Vault(LocalStorage(tmp_path / "vault"))
    vault.register("alice", "alice-passphrase-1")
    vault.register("bob", "bob-passphrase-2")

    alice = vault.login("alice", "alice-passphrase-1")
    bob = vault.login("bob", "bob-passphrase-2")

    sidecar = vault.upload(alice, "alice.pdf", PLAINTEXT)
    ciphertext = vault.backend.get_bytes(f"docs/alice/{sidecar.file_id}.enc")

    # Bob grabs Alice's ciphertext + sidecar but cannot unwrap the key.
    with pytest.raises(DecryptionError):
        decrypt_document(ciphertext, sidecar, bob.private_key)

    # Alice, of course, can.
    assert decrypt_document(ciphertext, sidecar, alice.private_key) == PLAINTEXT


def test_wrong_passphrase_cannot_unlock(tmp_path):
    vault = Vault(LocalStorage(tmp_path / "vault"))
    vault.register("carol", "the-right-passphrase")
    with pytest.raises(AuthError):
        vault.login("carol", "the-wrong-passphrase")
