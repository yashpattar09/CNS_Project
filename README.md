# Hybrid Cryptographic Encryption System Using RSA and AES
### A secure EHR (health-record) vault — Cryptography & Network Security mini-project

A user uploads a health-report PDF; the system stores it so that **only that user can
decrypt it**, and **any tampering is detected**. It combines symmetric and asymmetric
cryptography (a *hybrid cryptosystem*), password-based key protection, and integrity
verification, exposed through a professional **Streamlit** web app that deploys to
Streamlit Community Cloud.

A fully **standalone** project — the crypto engine is a dependency-free Python package you
can import, test, and demo on its own.

---

## 1. What it does

| Requirement | How it's met |
|---|---|
| Upload a PDF and store it securely | Per-file **AES-256-GCM** encryption |
| Only the owner can view it | AES key **wrapped with the user's RSA public key** (RSA-OAEP) |
| Separate authentication for the vault | A dedicated **EHR passphrase**, distinct from any app login |
| Automatic encryption | Encryption happens on upload; plaintext is never stored |
| Tamper detection | **AES-GCM auth tag** + an independent **SHA-256** integrity check |
| Store / view / delete | Full CRUD in the Streamlit UI |
| Secure transport | Supabase Storage and Streamlit Cloud are **HTTPS/TLS-only** |
| No custom crypto | Only `cryptography` + `argon2-cffi` (industry-standard) |

---

## 2. Architecture — the hybrid scheme

**Why hybrid?** RSA can only encrypt very small payloads and is slow; AES is fast and handles
any size but needs a shared key. The standard solution — used by TLS, PGP, S/MIME — is to
encrypt the *data* with a random AES key, then encrypt (*wrap*) that small AES key with RSA.
Only the private-key holder can unwrap it, giving public-key-grade access control at
symmetric-key speed.

```
REGISTER  (username + EHR passphrase)
  generate RSA-3072 key pair
     public key  ─────────────────────────────────► stored in the user record
     private key (PKCS#8 PEM)
        passphrase ─Argon2id─► KEK ─AES-256-GCM─► ENCRYPTED private key ─► stored in the user record
  (the passphrase itself is NEVER stored)

UPLOAD a file  (per-file hybrid encryption)
  plaintext ─SHA-256─► digest                                   # integrity fingerprint
  aes_key  = 32 random bytes (AES-256)   nonce = 12 random bytes # GCM
  ciphertext + tag = AES-256-GCM(aes_key, nonce, plaintext, aad = file_id)
  wrapped_key      = RSA-OAEP-SHA256(public_key, aes_key)
  STORE ONLY:  ciphertext(.enc)  +  sidecar.json{ wrapped_key, nonce, tag, sha256, aad, meta }
  NEVER stored: the plaintext, or the raw AES key

VIEW / DOWNLOAD
  passphrase ─Argon2id─► KEK ─► decrypt private key (kept only in session memory)
  aes_key   = RSA-OAEP.decrypt(private_key, wrapped_key)        # fails for any other user
  plaintext = AES-256-GCM.decrypt(ciphertext+tag, nonce, aad)   # fails if tampered (tag)
  assert SHA-256(plaintext) == stored digest                    # second integrity layer

DELETE  → remove the ciphertext and its sidecar
```

### Algorithms & why they were chosen

- **AES-256-GCM** (bulk data): authenticated encryption — one primitive gives both
  **confidentiality** and **integrity/authenticity**. NIST SP 800-38D standard. 96-bit random
  nonce, 128-bit tag.
- **RSA-3072 with OAEP(SHA-256)** (key wrapping): 3072-bit ≈ 128-bit security (NIST-recommended
  through 2030+). **OAEP** is the IND-CCA2-secure padding — never "textbook" RSA.
- **Argon2id** (password KDF): the winner of the Password Hashing Competition; memory-hard, so
  GPU/ASIC brute-forcing the passphrase is expensive. Salted per user. **PBKDF2-HMAC-SHA256**
  (600k iterations) is implemented as a selectable fallback.
- **SHA-256** (integrity): a stored fingerprint of the original, re-verified after every
  decryption — an explicit, demonstrable tamper check on top of the GCM tag.
- **AAD = file_id**: the file id is bound into GCM as additional authenticated data, so an
  attacker cannot swap one file's ciphertext under another's metadata.

### Security properties (the threat model)

- **Confidentiality at rest:** stored blobs are AES-256 ciphertext; private keys are Argon2-
  wrapped. Even full read access to the storage bucket reveals nothing without the passphrase.
- **Per-user access control by cryptography, not just paths:** a file encrypted for user A can
  only be opened with A's private key (`DecryptionError` otherwise).
- **Zero-knowledge server:** the passphrase is never persisted and the private key is decrypted
  only in the session's memory, so the server cannot read a user's documents on its own.
- **Tamper-evidence:** any change to ciphertext, tag, or metadata is caught (`TamperError`);
  a content/hash mismatch is caught independently (`IntegrityError`).
- **Trade-off (by design):** forget the passphrase ⇒ documents are **unrecoverable**. That is
  the correct property for true end-to-end encryption of medical records.

---

## 3. Project layout

```
ehr_crypto_app/
├── ehr_crypto/            # standalone crypto library (NO Streamlit dependency)
│   ├── kdf.py             # Argon2id / PBKDF2 key derivation
│   ├── keys.py            # RSA keygen + passphrase-protected private key
│   ├── hybrid.py          # encrypt_document / decrypt_document (the core scheme)
│   ├── models.py          # Sidecar + UserRecord (JSON records)
│   ├── storage.py         # LocalStorage (default) + SupabaseStorage backends
│   ├── vault.py           # register / login / upload / list / view / delete
│   └── exceptions.py      # AuthError, DecryptionError, TamperError, IntegrityError, …
├── app.py                 # Streamlit web app
├── demo.py                # CLI step-by-step console walkthrough
├── sample_pdf.py          # dependency-free sample-PDF generator
├── sample/sample_report.pdf
├── tests/                 # pytest: roundtrip, wrong-user, tamper
├── requirements.txt
├── .streamlit/secrets.toml.example
└── README.md
```

---

## 4. How to run

> Python 3.10+ (developed on 3.13). From inside the `ehr_crypto_app/` folder:

```bash
pip install -r requirements.txt
```

**Run the tests** (proves the three security properties):
```bash
pytest tests -v
```

**Run the CLI demo** (console walkthrough for the viva):
```bash
python demo.py
```
It registers two users, encrypts a PDF, shows the stored blob is unreadable, decrypts it back,
shows a second user *cannot* decrypt it, then tampers a byte and shows detection.

**Run the web app locally:**
```bash
streamlit run app.py
```
With no secrets configured it uses an offline local vault (`./vault_data`). Open the URL it
prints, create an account, upload a PDF (or click *Use sample health report*), then view,
verify, run the tamper demo, and delete.

---

## 5. Optional: store in Supabase (cloud backend)

This uses a **brand-new Storage bucket** — it does **not** touch any existing table, column,
RLS policy, or trigger in your Supabase project.

1. In the Supabase dashboard → **Storage** → **New bucket** → name it `ehr-documents`,
   keep it **Private**.
2. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill in your
   project `url`, a **service-role** `key`, and `bucket = "ehr-documents"`.
   - The service-role key is used **server-side only** (in Streamlit secrets) so the app can
     manage objects. It bypasses RLS, so **no storage policies are required**. Keep it secret.
   - Confidentiality never relies on this key: every uploaded blob is already AES-encrypted and
     every private key is passphrase-wrapped.
3. Restart the app — the sidebar will now read `Backend: Supabase bucket 'ehr-documents'`.
   Uploads/downloads travel over **HTTPS/TLS**.

Layout inside the bucket: `users/<username>.json`, `docs/<username>/<file_id>.enc`,
`docs/<username>/<file_id>.json`.

---

## 6. Deploy on Streamlit Community Cloud

1. Push this folder to a GitHub repo.
2. On [share.streamlit.io](https://share.streamlit.io) → **New app** → pick the repo/branch and
   set **Main file path** to `ehr_crypto_app/app.py`.
3. (Optional cloud storage) In the app's **Settings → Secrets**, paste the `[supabase]` block
   from `secrets.toml.example`. Without it, the app runs on an (ephemeral) local vault.
4. Deploy. Streamlit Cloud serves the app over **HTTPS**.

> Note: Streamlit Cloud's local disk is ephemeral (reset on restart). For persistent storage
> across restarts, configure the Supabase backend.

---

## 7. Viva quick-reference (Q & A)

- **Why hybrid instead of just RSA?** RSA can't encrypt large data and is slow; you encrypt the
  file with fast AES and only RSA-wrap the small AES key.
- **Why AES-GCM and not CBC?** GCM is *authenticated* — it detects tampering via its tag; CBC
  gives confidentiality only and needs a separate MAC.
- **Why OAEP?** Randomised, IND-CCA2-secure padding; plain/textbook RSA is deterministic and
  insecure.
- **Why Argon2id for the passphrase?** Memory-hard and salted → resists brute-force/rainbow
  tables far better than a plain hash; PBKDF2 is the fallback.
- **How is tampering detected?** Two ways: the AES-GCM authentication tag, and an independent
  SHA-256 of the original that's re-checked after decryption.
- **Where does decryption happen / who can read the file?** Only the logged-in user's session,
  after the passphrase decrypts their private key in memory. The server never stores the
  passphrase and cannot decrypt on its own.
- **How is transport secured?** TLS/HTTPS end-to-end (Supabase Storage and Streamlit Cloud).
- **What if the passphrase is lost?** The data is unrecoverable — the intended property of true
  end-to-end encryption.

## 8. Limitations (honest notes)
- Sidecar **metadata** (filename, size, date) is stored in the clear for listing; only the file
  contents and keys are encrypted. Encrypting metadata too is a straightforward extension.
- The demo/local backend keeps data on local disk; use the Supabase backend for real persistence.
- Rotating a lost passphrase (re-wrapping the private key) is not implemented, by design.
