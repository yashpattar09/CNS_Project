"""Typed errors for the EHR crypto vault.

Keeping these distinct lets the UI (and the tests) tell the difference between
"you typed the wrong passphrase", "this file is not yours", and "this file was
tampered with" — each of which needs a different, clear message for the user.
"""


class EhrCryptoError(Exception):
    """Base class for every error raised by this package."""


class AuthError(EhrCryptoError):
    """Wrong passphrase, unknown user, or a user that already exists."""


class DecryptionError(EhrCryptoError):
    """The wrapped AES key could not be unwrapped with this private key.

    In practice this means the document belongs to a *different* user (their
    public key was used to wrap the key, so only their private key can unwrap it).
    """


class TamperError(EhrCryptoError):
    """AES-256-GCM authentication failed — the ciphertext or tag was altered."""


class IntegrityError(EhrCryptoError):
    """The decrypted bytes do not match the stored SHA-256 of the original."""


class StorageError(EhrCryptoError):
    """A storage backend (local filesystem or Supabase) could not complete an op."""
