# Secure EHR Vault — Hybrid Cryptographic Encryption System Using RSA and AES

A secure Electronic Health Record (EHR) vault. A user uploads a health-report PDF (or any
file); the system encrypts it so that **only that user can ever decrypt it**, and **any
tampering is detected**. It combines symmetric and asymmetric cryptography (a *hybrid
cryptosystem*), password-based key protection, and cryptographic integrity verification,
all behind a professional **Streamlit** web interface that can be deployed to the cloud.

The project is deliberately **standalone**: the cryptographic engine (`ehr_crypto/`) is a
dependency-free Python package you can import, unit-test, and demonstrate on its own,
independent of the web UI.

> **Cryptography & Network Security mini-project.** This README is written to double as the
> project documentation/report — it explains the concepts, the exact algorithms and parameters,
> the architecture, every workflow step by step, how to run and deploy it, the threat model,
> and a viva question bank.

---

## Table of contents

1. [What it does (at a glance)](#1-what-it-does-at-a-glance)
2. [Core security properties](#2-core-security-properties)
3. [Cryptography background (the concepts)](#3-cryptography-background-the-concepts)
4. [The algorithms used — in detail](#4-the-algorithms-used--in-detail)
5. [System architecture](#5-system-architecture)
6. [Data model — what is stored](#6-data-model--what-is-stored)
7. [How it works — every workflow, step by step](#7-how-it-works--every-workflow-step-by-step)
8. [Project structure (file by file)](#8-project-structure-file-by-file)
9. [Installation](#9-installation)
10. [How to use — the web app](#10-how-to-use--the-web-app)
11. [How to use — the CLI demo](#11-how-to-use--the-cli-demo)
12. [Running the tests](#12-running-the-tests)
13. [Storage backends (local & Supabase)](#13-storage-backends-local--supabase)
14. [Deploying to Streamlit Cloud](#14-deploying-to-streamlit-cloud)
15. [Transport security (TLS)](#15-transport-security-tls)
16. [Threat model — what it protects (and what it doesn't)](#16-threat-model--what-it-protects-and-what-it-doesnt)
17. [Limitations](#17-limitations)
18. [Viva / exam question bank](#18-viva--exam-question-bank)
19. [Glossary](#19-glossary)
20. [Standards & references](#20-standards--references)

---

## 1. What it does (at a glance)

| Requirement | How it is met |
|---|---|
| Upload a PDF/file and store it securely | Encrypted with a per-file **AES-256-GCM** key |
| Only the owner can view it | The AES key is **wrapped with the owner's RSA public key** (RSA-OAEP); only the owner's private key can unwrap it |
| Separate authentication for the vault | A dedicated **EHR passphrase**, independent of any other login |
| Automatic encryption | Encryption happens on upload; the plaintext is **never** written to storage |
| Tamper detection | **AES-GCM authentication tag** + an independent **SHA-256** check of the original |
| Store / view / delete | Full CRUD, plus a "show encrypted" and a live "tamper" demo in the UI |
| Secure transport | Supabase Storage and Streamlit Cloud are **HTTPS/TLS-only** |
| No custom cryptography | Only the standard libraries `cryptography` and `argon2-cffi` are used |

---

## 2. Core security properties

- **Confidentiality at rest.** Every stored file is AES-256 ciphertext. Every user's RSA private
  key is itself encrypted. Reading the raw storage reveals nothing useful.
- **Per-user access control enforced by mathematics, not just by file paths.** A file encrypted
  for user A can only be decrypted with A's private key. Another user's key fails
  (`DecryptionError`).
- **Zero-knowledge server.** The passphrase is **never stored**. The private key is decrypted
  only transiently, in the running session's memory. The server/operator cannot read a user's
  documents on their own.
- **Integrity / tamper-evidence.** Any modification of the ciphertext, the authentication tag,
  or the metadata is detected (`TamperError`); a content/hash mismatch is caught independently
  (`IntegrityError`).
- **Deliberate trade-off.** If the passphrase is forgotten, the data is **unrecoverable**. That
  is the correct and intended property for genuine end-to-end encryption of medical records.

---

## 3. Cryptography background (the concepts)

**Symmetric encryption** uses one shared secret key for both encryption and decryption (e.g.
AES). It is fast and handles data of any size, but it has a key-distribution problem: how do you
get the key to the right person securely?

**Asymmetric (public-key) encryption** uses a *key pair* — a **public key** (shareable, used to
encrypt) and a **private key** (secret, used to decrypt), e.g. RSA. It solves key distribution:
anyone can encrypt *to* you with your public key, but only you can decrypt with your private key.
The catch: RSA is slow and can only encrypt data smaller than its modulus (a 3072-bit RSA key can
encrypt only a few hundred bytes).

**Hybrid cryptography** combines the two to get the best of both — and is exactly what TLS, PGP
and S/MIME use:

1. Encrypt the (large) data with a fresh, random **symmetric** key (fast).
2. Encrypt that small symmetric key with the recipient's **public** key (secure distribution).
3. Store the encrypted data + the "wrapped" key together.

To decrypt, the recipient uses their private key to recover the symmetric key, then decrypts the
data. **This project implements that pattern for health records.**

A fourth ingredient is needed because a human passphrase is not a cryptographic key: a
**Key Derivation Function (KDF)** turns the passphrase into a strong key, slowly and with a salt,
so it resists brute-force and precomputation attacks.

---

## 4. The algorithms used — in detail

All primitives come from the well-established [`cryptography`](https://cryptography.io) library
(and [`argon2-cffi`](https://argon2-cffi.readthedocs.io) for Argon2). **No algorithm is
hand-rolled.**

### 4.1 AES-256-GCM — bulk data encryption
- **What:** Advanced Encryption Standard, 256-bit key, in **Galois/Counter Mode**. GCM is an
  *authenticated encryption with associated data* (AEAD) mode — it provides **confidentiality
  and integrity/authenticity in a single primitive**.
- **Parameters used:** 256-bit key (`os.urandom(32)`), **96-bit (12-byte) random nonce**,
  **128-bit (16-byte) authentication tag**. Additional Authenticated Data (**AAD**) = the file's
  `file_id`.
- **Why:** AES is the NIST-standard symmetric cipher (FIP 197). GCM (NIST SP 800-38D) means we do
  not need a separate MAC — the tag detects any change to the ciphertext. The AAD cryptographically
  binds each ciphertext to its own metadata record, so records cannot be swapped.
- **Nonce rule:** a fresh random nonce is generated for **every** encryption, so the same key is
  never reused with the same nonce (a GCM requirement).

### 4.2 RSA-3072 with OAEP(SHA-256) — key wrapping
- **What:** RSA public-key encryption with a **3072-bit modulus** and **OAEP** (Optimal
  Asymmetric Encryption Padding) using SHA-256 and MGF1.
- **Parameters used:** `key_size = 3072`, `public_exponent = 65537`; OAEP with
  `MGF1(SHA-256)`, hash `SHA-256`, `label = None`.
- **Why:** 3072-bit RSA gives roughly **128-bit security** (NIST SP 800-57, recommended through
  2030+). **OAEP** is a randomised, IND-CCA2-secure padding — unlike "textbook" RSA, which is
  deterministic and insecure. RSA is used **only to wrap the 32-byte AES key**, which fits easily
  and plays to RSA's strengths (secure key transport) while avoiding its weakness (speed/size).

### 4.3 Argon2id — passphrase key derivation (default)
- **What:** The winner of the Password Hashing Competition (2015); a **memory-hard** KDF.
- **Parameters used:** `time_cost = 3`, `memory_cost = 65536 KiB (64 MiB)`, `parallelism = 4`,
  output `32 bytes`, a fresh random **16-byte salt** per user.
- **Why:** Memory-hardness makes large-scale brute-forcing with GPUs/ASICs expensive. The salt
  defeats rainbow tables and makes two identical passphrases derive different keys. This derived
  key (a **Key Encryption Key, KEK**) protects the RSA private key at rest.

### 4.4 PBKDF2-HMAC-SHA256 — KDF fallback
- **What:** Password-Based Key Derivation Function 2, the classic iterated-HMAC KDF.
- **Parameters used:** `600,000 iterations`, SHA-256, 32-byte output (OWASP 2023 guidance).
- **Why:** A universally available alternative (built into `cryptography`) selectable if Argon2
  is unavailable. The chosen KDF + its parameters are stored with the record so decryption can
  reproduce the exact same key.

### 4.5 SHA-256 — integrity fingerprint
- **What:** A 256-bit cryptographic hash (FIPS 180-4).
- **How used:** On upload we store `SHA-256(original_bytes)`. On download, after decryption, we
  recompute it and compare. A mismatch raises `IntegrityError`.
- **Why:** An explicit, easy-to-demonstrate integrity layer on top of the GCM tag. (A hash alone
  is not encryption — it is used here purely as a fingerprint for verification.)

### 4.6 How they fit together
```
                passphrase ──Argon2id──► KEK (32 bytes)
                                           │  AES-256-GCM
   RSA private key (PKCS#8 PEM) ───────────┴────────────► encrypted private key (at rest)

   random AES-256 key ──encrypts──► the file (AES-256-GCM) ──► ciphertext + tag
           │
           └──wrapped by──► RSA-OAEP(public key) ──► wrapped_key (at rest)

   SHA-256(file) ─────────────────────────────────────────► digest (at rest, for integrity)
```

---

## 5. System architecture

Three layers, cleanly separated:

```
┌─────────────────────────────────────────────────────────────┐
│  app.py   —  Streamlit UI (register / login / upload /        │
│              view / show-encrypted / verify / tamper / delete)│
├─────────────────────────────────────────────────────────────┤
│  ehr_crypto/  —  the standalone crypto + vault engine         │
│     vault.py     orchestration + per-user scoping             │
│     hybrid.py    encrypt_document / decrypt_document          │
│     keys.py      RSA keygen + passphrase-protected private key │
│     kdf.py       Argon2id / PBKDF2 key derivation             │
│     models.py    UserRecord, Sidecar (JSON records)           │
│     storage.py   StorageBackend: LocalStorage / SupabaseStorage│
│     exceptions.py typed errors                                │
├─────────────────────────────────────────────────────────────┤
│  Storage   —  LocalStorage (./vault_data)  OR                 │
│               SupabaseStorage (a private bucket, over HTTPS)   │
└─────────────────────────────────────────────────────────────┘
```

- The **UI never touches cryptography directly** — it calls the `Vault` API.
- The **engine never touches the UI or the network directly** — it talks to an abstract
  `StorageBackend`, so the same code runs offline on disk or against the cloud.
- Decryption only ever happens inside the engine, driven by a `Session` that holds the
  **in-memory** private key for the logged-in user.

---

## 6. Data model — what is stored

Everything is stored as plain objects in a backend (files on disk, or objects in a bucket).
**Two kinds of JSON records exist, plus the ciphertext blob.** None of them ever contains the
plaintext or the raw AES key.

### 6.1 Object layout
```
users/<username>.json            # the user's account record
docs/<username>/<file_id>.enc    # the encrypted file (ciphertext only)
docs/<username>/<file_id>.json   # the "sidecar": crypto metadata for that file
```

### 6.2 `UserRecord` (`users/<username>.json`)
```json
{
  "username": "alice",
  "public_pem": "-----BEGIN PUBLIC KEY----- ...",
  "protected_private_key": {
    "kdf": { "algorithm": "argon2id", "params": { "time_cost": 3, "memory_cost": 65536, "parallelism": 4 } },
    "salt": "<base64 16-byte salt>",
    "nonce": "<base64 12-byte GCM nonce>",
    "ciphertext": "<base64: AES-256-GCM(KEK, private-key-PEM)>"
  },
  "rsa_bits": 3072,
  "created_at": "2026-..."
}
```
The private key is present **only in encrypted form**. The passphrase is not here (or anywhere).

### 6.3 `Sidecar` (`docs/<username>/<file_id>.json`)
```json
{
  "file_id": "ab12...ef",
  "filename": "blood_panel.pdf",
  "size": 1220,
  "created_at": "2026-...",
  "scheme": "RSA-3072-OAEP-SHA256 + AES-256-GCM",
  "wrapped_key": "<base64: RSA-OAEP(public_key, aes_key)>",
  "nonce": "<base64 12-byte GCM nonce>",
  "tag": "<base64 16-byte GCM auth tag>",
  "sha256": "<hex SHA-256 of the original file>",
  "aad": "ab12...ef",
  "owner": "alice"
}
```

---

## 7. How it works — every workflow, step by step

### 7.1 Register (`Vault.register`)
1. Validate the username (`^[A-Za-z0-9_.-]{3,32}$`) and require a passphrase of ≥ 8 characters.
2. Generate a fresh **RSA-3072** key pair.
3. Serialise the **public** key to PEM.
4. Protect the **private** key: generate a 16-byte salt, derive a 32-byte **KEK** from the
   passphrase with **Argon2id**, then AES-256-GCM-encrypt the private-key PEM under the KEK.
5. Write the `UserRecord`. **The passphrase is discarded** and never stored.

### 7.2 Login (`Vault.login`) → `Session`
1. Load the user's `UserRecord`.
2. Re-derive the KEK from the entered passphrase + the stored salt + stored KDF params.
3. AES-GCM-decrypt the private key. If the passphrase is wrong, the KEK is wrong and the GCM tag
   fails → raises **`AuthError`** ("Incorrect EHR passphrase"). This is how a wrong passphrase is
   detected **without ever storing the passphrase**.
4. Return a `Session` holding the decrypted private key **in memory only**.

### 7.3 Upload / encrypt (`Vault.upload` → `hybrid.encrypt_document`)
1. Compute `SHA-256(plaintext)` → the integrity digest.
2. Generate a random **256-bit AES key** and a random **96-bit nonce**.
3. **AES-256-GCM** encrypt the file with AAD = `file_id`, producing `ciphertext || tag`; the
   16-byte tag is split out and stored separately.
4. **RSA-OAEP** wrap the AES key with the user's public key → `wrapped_key`.
5. Write `docs/<user>/<file_id>.enc` (ciphertext) and `docs/<user>/<file_id>.json` (sidecar).
   The raw AES key and the plaintext are discarded.

### 7.4 View / decrypt (`Vault.view` → `hybrid.decrypt_document`)
1. Load the sidecar and the ciphertext.
2. **RSA-OAEP** unwrap `wrapped_key` with the session's **private key**. If the file belongs to
   another user, this fails → **`DecryptionError`**.
3. **AES-256-GCM** decrypt `ciphertext || tag` with the nonce and AAD. If anything was altered,
   the tag check fails → **`TamperError`**.
4. Recompute `SHA-256` and compare to the stored digest. Mismatch → **`IntegrityError`**.
5. Return the plaintext to the user (preview + download).

### 7.5 Verify only
Runs 7.4 but discards the plaintext — a quick "is this file intact and mine?" check.

### 7.6 Tamper demo (`Vault.tamper`)
Flips a single bit of the stored `.enc`. The next View then fails the GCM tag check, live-proving
tamper detection. (Teaching aid only.)

### 7.7 Delete (`Vault.delete`)
Removes both the `.enc` and the sidecar for that `file_id`.

### 7.8 End-to-end picture
```
UPLOAD                                  VIEW
file ─sha256─► digest                   load sidecar + ciphertext
aes_key,nonce (random)                  wrapped_key ─RSA.decrypt(priv)─► aes_key
AES-GCM(file) ─► ct + tag               AES-GCM.decrypt(ct+tag,nonce,aad) ─► file
aes_key ─RSA.encrypt(pub)─► wrapped     assert sha256(file)==digest
store ct + {wrapped,nonce,tag,sha256}   return file to the owner only
```

---

## 8. Project structure (file by file)

```
ehr_crypto_app/
├── ehr_crypto/              # standalone crypto library (no Streamlit dependency)
│   ├── __init__.py          # public exports
│   ├── exceptions.py        # AuthError, DecryptionError, TamperError, IntegrityError, StorageError
│   ├── kdf.py               # Argon2id (default) / PBKDF2 key derivation + params
│   ├── keys.py              # RSA keygen; protect/unlock the private key with the passphrase KEK
│   ├── hybrid.py            # encrypt_document / decrypt_document (the hybrid scheme)
│   ├── models.py            # UserRecord + Sidecar dataclasses (JSON (de)serialisation)
│   ├── storage.py           # StorageBackend ABC + LocalStorage + SupabaseStorage
│   └── vault.py             # register/login/upload/list/view/delete + tamper helper
├── app.py                   # Streamlit web application
├── demo.py                  # command-line, step-by-step console walkthrough
├── sample_pdf.py            # dependency-free sample-PDF generator
├── sample/sample_report.pdf # a small valid PDF for demos
├── tests/
│   ├── test_roundtrip.py    # encrypt→decrypt returns the original; stored blob is unreadable
│   ├── test_wrong_user.py   # a different user cannot decrypt; wrong passphrase cannot unlock
│   └── test_tamper.py       # altered ciphertext/tag/hash are all detected
├── conftest.py              # makes the package importable under pytest
├── requirements.txt
├── .streamlit/secrets.toml.example
├── .gitignore
└── README.md                # this document
```

---

## 9. Installation

**Prerequisite:** Python 3.10 or newer (developed and tested on 3.13). Check with
`python --version`.

From inside the `ehr_crypto_app/` folder:
```bash
pip install -r requirements.txt
```
This installs `streamlit`, `cryptography`, `argon2-cffi`, `supabase` (optional cloud backend),
and `pytest` (for the tests).

> **Windows note:** if the bare `streamlit` command is "not recognized", always launch it through
> Python: `python -m streamlit run app.py`. This avoids PATH issues entirely.

---

## 10. How to use — the web app

Launch it:
```bash
python -m streamlit run app.py
```
Then open the URL it prints (default **http://localhost:8501**).

**Step 1 — Create an account.** Open the **Create account** tab, choose a username and an **EHR
passphrase** (≥ 8 characters), and submit. This generates your RSA-3072 key pair. *Remember the
passphrase — it cannot be recovered.*

**Step 2 — Sign in.** On the **Sign in** tab, enter the same credentials and click **Unlock my
vault**. Your private key is decrypted into the session.

**Step 3 — Upload.** On the **Upload** tab, drop a PDF (or any file) and click **🔒 Encrypt &
store**, or click **Use sample health report** to try it instantly. You will see a hex preview
proving the stored bytes are unreadable.

**Step 4 — Manage documents.** On the **My documents** tab, expand a document to get five actions:

| Button | What it does |
|---|---|
| 👁 **View (decrypt)** | Decrypts in memory, shows an "Integrity verified ✓" badge, previews the PDF, and offers a download |
| 🔒 **Show encrypted** | Shows the raw ciphertext **as stored at rest** — a hex dump, a `.enc` download, and the sidecar JSON (wrapped key / nonce / tag / sha256) |
| ✅ **Verify only** | Confirms integrity + ownership without opening the file |
| ⚠️ **Tamper (demo)** | Corrupts one byte of the stored ciphertext to demonstrate detection |
| 🗑 **Delete** | Permanently removes the file (with confirmation) |

**Sidebar:** shows your username, the active storage backend, the cipher scheme, a **Log out**
button (which wipes the in-memory key), and a "How your data is protected" summary.

### Suggested demonstration flow (for a viva)
1. Upload the sample report.
2. Click **🔒 Show encrypted** → "this unreadable blob is what's actually stored."
3. Click **👁 View (decrypt)** → "with my passphrase it returns as the real PDF, integrity verified."
4. Click **⚠️ Tamper (demo)**, then **👁 View** again → "any alteration is detected immediately."

---

## 11. How to use — the CLI demo

For a no-UI, scriptable walkthrough (ideal to show the internals):
```bash
python demo.py
```
It uses a throwaway local vault and prints each step: register two users → Alice encrypts a PDF →
show the stored `.enc` is unreadable → Alice decrypts it back to the exact original → Bob (a
different user) is blocked (`DecryptionError`) → one byte is tampered and the read is blocked
(`TamperError`).

---

## 12. Running the tests

```bash
pytest tests -v
```
Eight tests cover the three security guarantees:

- **`test_roundtrip.py`** — encryption→decryption returns the exact original bytes; the stored
  ciphertext does not contain the plaintext and does not start with `%PDF`.
- **`test_wrong_user.py`** — a second user's private key cannot decrypt the first user's file
  (`DecryptionError`); a wrong passphrase cannot unlock a private key (`AuthError`).
- **`test_tamper.py`** — a flipped ciphertext byte and an altered tag both raise `TamperError`; a
  doctored SHA-256 raises `IntegrityError`.

---

## 13. Storage backends (local & Supabase)

The engine talks to an abstract `StorageBackend`, so the identical crypto runs against either.

### 13.1 Local vault (default)
With no Supabase secrets configured, files are stored under `./vault_data/` (override with the
`EHR_VAULT_DIR` environment variable). Zero configuration, fully offline — ideal for development
and the viva. Data persists on your machine between runs.

### 13.2 Supabase Storage (optional cloud)
This uses a **brand-new Storage bucket** and touches no database table, column, policy, or
trigger.

1. In the Supabase dashboard → **Storage → New bucket** → name it `ehr-documents`, keep it
   **Private**.
2. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill in your project
   `url`, a **service-role** `key`, and `bucket = "ehr-documents"`.
   - The service-role key is used **server-side only** (in Streamlit secrets), so the app can
     manage objects. It bypasses storage RLS, so **no policies are required**. Keep it secret.
   - Confidentiality never depends on this key: every stored blob is already AES-encrypted and
     every private key is passphrase-wrapped.
3. Restart the app — the sidebar will read `Backend: Supabase bucket 'ehr-documents'`. Uploads and
   downloads travel over **HTTPS/TLS**.

Bucket layout: `users/<username>.json`, `docs/<username>/<file_id>.enc`,
`docs/<username>/<file_id>.json`.

---

## 14. Deploying to Streamlit Cloud

1. Push this folder to a GitHub repository.
2. On [share.streamlit.io](https://share.streamlit.io) → **New app** → select the repo/branch and
   set **Main file path** to `ehr_crypto_app/app.py`.
3. (Optional cloud storage) In **Settings → Secrets**, paste the `[supabase]` block from
   `secrets.toml.example`. Without it the app runs on an (ephemeral) local vault.
4. Deploy. Streamlit Cloud serves the app over **HTTPS**.

> Streamlit Cloud's local disk is ephemeral (reset on restart). For persistence across restarts,
> configure the Supabase backend.

---

## 15. Transport security (TLS)

- **Supabase Storage** endpoints are HTTPS-only (TLS 1.2+); uploads/downloads are encrypted in
  transit.
- **Streamlit Community Cloud** serves apps over HTTPS.
- For a local run (`localhost`), traffic stays on your machine and is not exposed to a network.
- **Defence in depth:** even if transport were compromised, the payloads are already
  AES-encrypted ciphertext and RSA-wrapped keys — the attacker sees nothing useful.

---

## 16. Threat model — what it protects (and what it doesn't)

**Protects against:**
- An attacker who reads the storage (disk/bucket): sees only ciphertext + wrapped keys.
- A curious server operator: cannot decrypt without the user's passphrase (zero-knowledge).
- One user trying to read another user's files: blocked by RSA key ownership.
- Silent corruption or deliberate modification of stored files: detected on read.
- Passphrase brute-forcing from a stolen record: slowed massively by Argon2id + per-user salt.

**Does not (by design/scope) protect against:**
- A forgotten passphrase (data becomes unrecoverable — intended).
- Malware on the client while the user is logged in (the plaintext exists in memory during a view).
- Metadata confidentiality: filename, size and dates are stored in clear for listing (see below).
- Denial of service / an attacker who merely deletes ciphertext (integrity ≠ availability).

---

## 17. Limitations

- **Metadata is not encrypted.** The sidecar stores filename, size and timestamps in clear so the
  document list can be shown without decrypting. Encrypting metadata too is a straightforward
  extension (encrypt the sidecar's descriptive fields with the same per-file key).
- **No passphrase rotation / recovery.** Changing a forgotten passphrase (re-wrapping the private
  key) is intentionally not implemented.
- **Single-factor vault auth.** The vault is gated by the passphrase only. A second factor could
  be layered on in the UI.
- **Ephemeral cloud disk.** The local backend on Streamlit Cloud does not persist across
  restarts; use the Supabase backend for durability.

---

## 18. Viva / exam question bank

- **Q: Why a hybrid scheme instead of encrypting the whole file with RSA?**
  RSA can only encrypt data smaller than its key and is slow. You encrypt the file with fast AES
  and use RSA only to wrap the small AES key — getting public-key access control at symmetric
  speed.
- **Q: Why AES-GCM rather than AES-CBC?**
  GCM is authenticated (AEAD): its tag detects tampering. CBC gives confidentiality only and needs
  a separate MAC to detect modification.
- **Q: Why OAEP padding for RSA?**
  OAEP is randomised and IND-CCA2-secure. Plain/"textbook" RSA is deterministic and vulnerable to
  several attacks.
- **Q: Why 3072-bit RSA and 256-bit AES?**
  They are matched at roughly the 128-bit security level (NIST SP 800-57), a sensible modern
  baseline.
- **Q: Why Argon2id for the passphrase and not a plain hash?**
  Argon2id is memory-hard and salted, which makes brute-forcing and rainbow-table attacks
  dramatically harder than a fast hash like a bare SHA-256.
- **Q: What exactly is stored, and what is never stored?**
  Stored: ciphertext, the RSA-wrapped AES key, the nonce, the GCM tag, and a SHA-256 of the
  original. Never stored: the plaintext, the raw AES key, or the passphrase.
- **Q: How is "only the owner can read it" enforced?**
  The AES key is wrapped with the owner's RSA public key; only the owner's private key can unwrap
  it. The private key is itself locked by the owner's passphrase.
- **Q: How is tampering detected — in two independent ways?**
  (1) The AES-GCM authentication tag fails if the ciphertext/tag/AAD changed; (2) a stored SHA-256
  of the original is re-checked after decryption.
- **Q: What role does the nonce play and why is it random each time?**
  GCM requires a unique nonce per encryption under a given key; reusing a nonce breaks its
  security. We generate a fresh 96-bit random nonce every time.
- **Q: What does AAD (the file_id) achieve?**
  It binds a ciphertext to its own metadata record, so an attacker cannot swap one file's
  ciphertext under another file's sidecar.
- **Q: How is data secured in transit?**
  TLS/HTTPS end-to-end (Supabase Storage and Streamlit Cloud); the payloads are also already
  encrypted, giving defence in depth.
- **Q: What happens if the passphrase is lost?**
  The private key cannot be decrypted, so no documents can be opened — the correct property of
  true end-to-end encryption.

---

## 19. Glossary

- **AEAD** — Authenticated Encryption with Associated Data; provides secrecy + integrity (e.g. GCM).
- **AES** — Advanced Encryption Standard, the standard symmetric block cipher.
- **GCM** — Galois/Counter Mode; an AEAD mode producing a ciphertext + authentication tag.
- **Nonce** — a "number used once"; a per-message value that must not repeat under one key.
- **AAD** — Additional Authenticated Data; authenticated but not encrypted (here, the file_id).
- **RSA** — the classic public-key cryptosystem (encrypt with public, decrypt with private).
- **OAEP** — Optimal Asymmetric Encryption Padding; the secure padding scheme for RSA encryption.
- **KDF** — Key Derivation Function; turns a passphrase into a strong key (Argon2id / PBKDF2).
- **KEK** — Key Encryption Key; the key (from the KDF) used to encrypt another key (the RSA private key).
- **Salt** — random data added before hashing/KDF so equal inputs yield different outputs.
- **Key wrapping** — encrypting one key with another key (here, AES key wrapped by RSA public key).
- **Sidecar** — the JSON record stored next to a ciphertext holding its crypto metadata.
- **Zero-knowledge (server)** — the server cannot read user data because it lacks the secret.

---

## 20. Standards & references

- **AES:** NIST FIPS 197. **GCM:** NIST SP 800-38D.
- **RSA / OAEP:** PKCS #1 v2.2 (RFC 8017).
- **SHA-256:** NIST FIPS 180-4.
- **PBKDF2:** RFC 8018 (PKCS #5 v2.1). **Argon2:** RFC 9106 (Argon2id recommended).
- **Key-size guidance:** NIST SP 800-57 Part 1.
- **Libraries:** [`cryptography`](https://cryptography.io), [`argon2-cffi`](https://argon2-cffi.readthedocs.io),
  [`streamlit`](https://streamlit.io), [`supabase-py`](https://github.com/supabase/supabase-py).
