"""Any modification is detected — two independent integrity layers.

1. AES-256-GCM's authentication tag catches changes to the ciphertext or tag
   (raises TamperError).
2. A stored SHA-256 of the original plaintext catches a mismatch even if GCM
   somehow verified (e.g. metadata swapped so the wrong digest is expected)
   (raises IntegrityError).
"""

import copy

import pytest

from ehr_crypto import (
    Vault,
    LocalStorage,
    decrypt_document,
    encrypt_document,
    load_public_key,
    new_protected_keypair,
    unlock_private_key,
    default_params,
)
from ehr_crypto.exceptions import IntegrityError, TamperError

PASSPHRASE = "tamper-test-passphrase"
PLAINTEXT = b"%PDF-1.4 integrity matters in medical records"


def _fresh_keys():
    kdf = default_params("argon2id")
    public_pem, protected = new_protected_keypair(PASSPHRASE, kdf)
    return load_public_key(public_pem), unlock_private_key(protected, PASSPHRASE)


def test_flipped_ciphertext_byte_is_detected():
    public_key, private_key = _fresh_keys()
    ciphertext, sidecar = encrypt_document(PLAINTEXT, public_key, "r.pdf")

    corrupted = bytearray(ciphertext)
    corrupted[0] ^= 0x01
    with pytest.raises(TamperError):
        decrypt_document(bytes(corrupted), sidecar, private_key)


def test_altered_tag_is_detected():
    public_key, private_key = _fresh_keys()
    ciphertext, sidecar = encrypt_document(PLAINTEXT, public_key, "r.pdf")

    bad = copy.deepcopy(sidecar)
    # Corrupt the base64 auth tag by flipping a character to a different valid one.
    ch = bad.tag[0]
    bad.tag = ("A" if ch != "A" else "B") + bad.tag[1:]
    with pytest.raises(TamperError):
        decrypt_document(ciphertext, bad, private_key)


def test_sha256_mismatch_is_detected():
    public_key, private_key = _fresh_keys()
    ciphertext, sidecar = encrypt_document(PLAINTEXT, public_key, "r.pdf")

    bad = copy.deepcopy(sidecar)
    bad.sha256 = "0" * 64  # claim a different original digest
    with pytest.raises(IntegrityError):
        decrypt_document(ciphertext, bad, private_key)


def test_vault_tamper_helper_triggers_detection(tmp_path):
    vault = Vault(LocalStorage(tmp_path / "vault"))
    vault.register("alice", PASSPHRASE)
    session = vault.login("alice", PASSPHRASE)
    sidecar = vault.upload(session, "r.pdf", PLAINTEXT)

    vault.tamper("alice", sidecar.file_id)
    with pytest.raises(TamperError):
        vault.view(session, sidecar.file_id)
