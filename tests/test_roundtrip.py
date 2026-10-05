"""Encrypt -> decrypt returns the original bytes, and nothing plaintext leaks."""

import os

from ehr_crypto import (
    Vault,
    LocalStorage,
    default_params,
    encrypt_document,
    decrypt_document,
    load_public_key,
    new_protected_keypair,
    unlock_private_key,
)

PASSPHRASE = "correct horse battery staple"
PLAINTEXT = b"%PDF-1.4 confidential health record " + os.urandom(2048)


def test_hybrid_roundtrip_returns_original():
    kdf = default_params("argon2id")
    public_pem, protected = new_protected_keypair(PASSPHRASE, kdf)
    public_key = load_public_key(public_pem)
    private_key = unlock_private_key(protected, PASSPHRASE)

    ciphertext, sidecar = encrypt_document(PLAINTEXT, public_key, "record.pdf", owner="alice")

    assert ciphertext != PLAINTEXT
    assert PLAINTEXT not in ciphertext  # ciphertext never contains the plaintext
    assert decrypt_document(ciphertext, sidecar, private_key) == PLAINTEXT


def test_vault_upload_view_roundtrip(tmp_path):
    vault = Vault(LocalStorage(tmp_path / "vault"))
    vault.register("alice", PASSPHRASE)
    session = vault.login("alice", PASSPHRASE)

    sidecar = vault.upload(session, "record.pdf", PLAINTEXT)
    assert vault.view(session, sidecar.file_id) == PLAINTEXT

    # The stored ciphertext blob must be unreadable and must not contain the PDF.
    stored = vault.backend.get_bytes(f"docs/alice/{sidecar.file_id}.enc")
    assert PLAINTEXT not in stored
    assert stored[:5] != b"%PDF-"

    # Listing works without any private key and reports correct metadata.
    docs = vault.list_documents("alice")
    assert [d.filename for d in docs] == ["record.pdf"]
    assert docs[0].size == len(PLAINTEXT)
