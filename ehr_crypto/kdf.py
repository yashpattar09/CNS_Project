"""Password-based key derivation for protecting the user's RSA private key.

The dedicated EHR passphrase is *never* stored. Instead we derive a 256-bit key
encryption key (KEK) from it with a slow, salted KDF, and use that KEK to
encrypt the private key at rest. Because the KDF is deliberately expensive and
salted, an attacker who steals the stored user record still cannot brute-force
the passphrase cheaply, and cannot precompute a rainbow table.

Default KDF: **Argon2id** (memory-hard, the modern OWASP recommendation).
Fallback KDF: **PBKDF2-HMAC-SHA256** (from `cryptography`, no extra dependency),
selectable so the demo runs even in a stripped-down environment.

We store the KDF name + parameters alongside the ciphertext so decryption always
knows how to reproduce the exact same KEK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

# --- Argon2id defaults (argon2-cffi) ---------------------------------------
# ~64 MiB, 3 passes, 4 lanes: sub-second on a laptop, painful to brute-force.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4

# --- PBKDF2 fallback --------------------------------------------------------
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 guidance for PBKDF2-HMAC-SHA256

KEK_LEN = 32  # 256-bit key for AES-256


@dataclass
class KdfParams:
    """Everything needed to reproduce a KEK, minus the secret passphrase."""

    algorithm: str  # "argon2id" | "pbkdf2-sha256"
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"algorithm": self.algorithm, "params": self.params}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "KdfParams":
        return cls(algorithm=d["algorithm"], params=dict(d.get("params", {})))


def default_params(algorithm: str = "argon2id") -> KdfParams:
    if algorithm == "argon2id":
        return KdfParams(
            "argon2id",
            {
                "time_cost": ARGON2_TIME_COST,
                "memory_cost": ARGON2_MEMORY_KIB,
                "parallelism": ARGON2_PARALLELISM,
            },
        )
    if algorithm == "pbkdf2-sha256":
        return KdfParams("pbkdf2-sha256", {"iterations": PBKDF2_ITERATIONS})
    raise ValueError(f"Unknown KDF algorithm: {algorithm}")


def derive_kek(passphrase: str, salt: bytes, kdf: KdfParams, *, length: int = KEK_LEN) -> bytes:
    """Derive a `length`-byte KEK from `passphrase` + `salt` using `kdf`."""
    secret = passphrase.encode("utf-8")

    if kdf.algorithm == "argon2id":
        # Imported lazily so the fallback path works without argon2-cffi installed.
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=int(kdf.params["time_cost"]),
            memory_cost=int(kdf.params["memory_cost"]),
            parallelism=int(kdf.params["parallelism"]),
            hash_len=length,
            type=Type.ID,
        )

    if kdf.algorithm == "pbkdf2-sha256":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=int(kdf.params["iterations"]),
        ).derive(secret)

    raise ValueError(f"Unknown KDF algorithm: {kdf.algorithm}")
