"""Standalone, dependency-light console walkthrough of the hybrid crypto system.

Run:  python demo.py

It proves, step by step, the properties your report/viva needs:
  * a PDF is encrypted with a per-file AES-256 key,
  * the AES key is wrapped with the user's RSA public key,
  * the stored blob is unreadable,
  * only the owner can decrypt it back to the exact original,
  * a different user cannot decrypt it, and
  * any tampering with the ciphertext is detected.

Uses a throwaway local vault directory; nothing touches the network.
"""

from __future__ import annotations

import base64
import os
import tempfile

from ehr_crypto import Vault, LocalStorage
from ehr_crypto.exceptions import DecryptionError, TamperError
from sample_pdf import minimal_pdf

ALICE_PASS = "alice-strong-passphrase-2026"
BOB_PASS = "bob-different-passphrase-2026"


def rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(f"  {title}")
    print("=" * 68)


def hexdump(data: bytes, n: int = 32) -> str:
    return " ".join(f"{b:02x}" for b in data[:n]) + (" ..." if len(data) > n else "")


def short(b64: str, n: int = 44) -> str:
    return b64[:n] + ("..." if len(b64) > n else "")


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="ehr_demo_")
    vault = Vault(LocalStorage(os.path.join(workdir, "vault")))
    print(f"Hybrid RSA + AES EHR vault demo\nWorking vault: {vault.backend.label}")

    rule("STEP 1 - Register two users (each gets an RSA-3072 key pair)")
    vault.register("alice", ALICE_PASS)
    vault.register("bob", BOB_PASS)
    print("Registered 'alice' and 'bob'. Each private key is stored ENCRYPTED,")
    print("wrapped by an Argon2id key derived from that user's passphrase.")

    rule("STEP 2 - Alice logs in and uploads a PDF health report")
    alice = vault.login("alice", ALICE_PASS)
    pdf = minimal_pdf()
    print(f"Original PDF: {len(pdf)} bytes, starts with {pdf[:8]!r}")
    sidecar = vault.upload(alice, "blood_panel.pdf", pdf)
    print(f"Encrypted and stored. file_id = {sidecar.file_id}")
    print(f"Scheme       = {sidecar.scheme}")
    print(f"SHA-256(orig)= {sidecar.sha256}")

    rule("STEP 3 - What is actually stored is unreadable")
    enc_path = f"docs/alice/{sidecar.file_id}.enc"
    ciphertext = vault.backend.get_bytes(enc_path)
    print(f"Stored ciphertext ({len(ciphertext)} bytes), first 32 bytes:")
    print("  " + hexdump(ciphertext))
    print(f"Contains the original PDF bytes? {pdf in ciphertext}")
    print(f"Starts with %PDF-? {ciphertext[:5] == b'%PDF-'}")
    print("\nSidecar metadata (no plaintext, no raw AES key):")
    print(f"  wrapped_key = {short(sidecar.wrapped_key)}   (AES key encrypted with RSA-OAEP)")
    print(f"  nonce       = {sidecar.nonce}")
    print(f"  tag         = {sidecar.tag}")

    rule("STEP 4 - Alice decrypts it back to the exact original")
    recovered = vault.view(alice, sidecar.file_id)
    print(f"Recovered {len(recovered)} bytes, starts with {recovered[:8]!r}")
    print(f"Byte-for-byte identical to the original? {recovered == pdf}")

    rule("STEP 5 - A different user (bob) CANNOT decrypt it")
    bob = vault.login("bob", BOB_PASS)
    try:
        # Bob fetches Alice's ciphertext + sidecar and tries with his own key.
        from ehr_crypto import decrypt_document

        decrypt_document(ciphertext, sidecar, bob.private_key)
        print("!! FAILURE: bob decrypted alice's file (should never happen)")
    except DecryptionError as exc:
        print(f"Blocked as expected -> DecryptionError:\n  {exc}")

    rule("STEP 6 - Tampering with the stored file is detected")
    vault.tamper("alice", sidecar.file_id)  # flips one byte of the ciphertext
    print("Flipped one byte of the stored ciphertext, then tried to view it:")
    try:
        vault.view(alice, sidecar.file_id)
        print("!! FAILURE: tampering went undetected")
    except TamperError as exc:
        print(f"Blocked as expected -> TamperError:\n  {exc}")

    rule("DONE - confidentiality, per-user access control, and integrity verified")
    print(f"(Throwaway vault left at: {workdir})")


if __name__ == "__main__":
    main()
