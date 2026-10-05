"""Secure EHR Vault — Streamlit front-end for the hybrid RSA + AES system.

A thin UI over `ehr_crypto`. All cryptography happens here on the server side;
the passphrase is used transiently and never stored, and the decrypted RSA
private key lives only in this browser session's `st.session_state`.

Run locally:   streamlit run app.py
Deploy:        Streamlit Community Cloud (see README + .streamlit/secrets.toml.example)
"""

from __future__ import annotations

import base64
import os
from datetime import datetime

import streamlit as st

from ehr_crypto import LocalStorage, SupabaseStorage, Vault
from ehr_crypto.exceptions import AuthError, EhrCryptoError, IntegrityError, TamperError
from ehr_crypto.models import SCHEME
from sample_pdf import minimal_pdf

APP_DIR = os.path.dirname(os.path.abspath(__file__))

st.set_page_config(page_title="Secure EHR Vault", page_icon="🔐", layout="wide")

st.markdown(
    """
    <style>
      .stApp { background: radial-gradient(1200px 600px at 20% -10%, #0b2a4a 0%, #041524 55%, #020c17 100%); }
      .block-container { padding-top: 2rem; }
      .ehr-badge { display:inline-block; padding:2px 10px; border-radius:999px;
                   font-size:12px; font-weight:700; letter-spacing:.3px; }
      .ehr-ok  { background:rgba(46,204,113,.15); color:#2ecc71; border:1px solid rgba(46,204,113,.4); }
      .ehr-bad { background:rgba(231,76,60,.15);  color:#e74c3c; border:1px solid rgba(231,76,60,.4); }
      .ehr-card{ background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.10);
                 border-radius:14px; padding:14px 16px; }
      code { color:#7fd1ff; }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- #
# Backend wiring
# --------------------------------------------------------------------------- #
@st.cache_resource(show_spinner=False)
def build_vault() -> Vault:
    """Supabase bucket if secrets are present, otherwise a local vault folder."""
    cfg = {}
    try:
        cfg = dict(st.secrets["supabase"])
    except Exception:  # noqa: BLE001 - no secrets configured -> local default
        cfg = {}

    url, key = cfg.get("url"), cfg.get("key")
    if url and key:
        bucket = cfg.get("bucket", "ehr-documents")
        return Vault(SupabaseStorage(url, key, bucket))

    root = os.environ.get("EHR_VAULT_DIR") or os.path.join(APP_DIR, "vault_data")
    return Vault(LocalStorage(root))


VAULT = build_vault()


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def human_size(n: int) -> str:
    size = float(n)
    if size < 1024:
        return f"{int(size)} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 ** 2:.1f} MB"


def fmt_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M")
    except Exception:  # noqa: BLE001
        return iso


def is_pdf(data: bytes) -> bool:
    return data[:5] == b"%PDF-"


def render_preview(data: bytes, filename: str) -> None:
    if is_pdf(data):
        b64 = base64.b64encode(data).decode("ascii")
        st.markdown(
            f'<iframe src="data:application/pdf;base64,{b64}" width="100%" '
            f'height="620" style="border:1px solid rgba(255,255,255,.15);border-radius:12px;">'
            f"</iframe>",
            unsafe_allow_html=True,
        )
        st.caption("If the inline preview is blocked by your browser, use Download below.")
    else:
        st.info("Decrypted successfully. This file type has no inline preview — download it below.")
    st.download_button(
        "⬇️ Download decrypted file",
        data=data,
        file_name=filename,
        mime="application/pdf" if is_pdf(data) else "application/octet-stream",
        key=f"dl_{filename}_{len(data)}",
    )


def logout() -> None:
    for k in ("session", "view_id", "confirm_delete", "flash"):
        st.session_state.pop(k, None)


# --------------------------------------------------------------------------- #
# Auth screen
# --------------------------------------------------------------------------- #
def auth_screen() -> None:
    st.title("🔐 Secure EHR Vault")
    st.caption(
        "Hybrid **RSA-3072 + AES-256-GCM** encryption for health records. "
        "Your documents are encrypted so that **only you** — with your EHR passphrase — can open them."
    )

    login_tab, register_tab = st.tabs(["Sign in", "Create account"])

    with login_tab:
        with st.form("login_form"):
            u = st.text_input("Username")
            p = st.text_input("EHR passphrase", type="password")
            submitted = st.form_submit_button("Unlock my vault", use_container_width=True)
        if submitted:
            try:
                st.session_state.session = VAULT.login(u.strip(), p)
                st.session_state.flash = ("success", f"Welcome back, {u.strip()}.")
                st.rerun()
            except AuthError as exc:
                st.error(str(exc))
            except EhrCryptoError as exc:
                st.error(f"Could not sign in: {exc}")

    with register_tab:
        st.markdown(
            "Your passphrase protects your private key and is **never stored**. "
            "If you forget it, your documents are unrecoverable — that's the point."
        )
        with st.form("register_form"):
            u = st.text_input("Choose a username", key="reg_u")
            p1 = st.text_input("Create an EHR passphrase (min 8 chars)", type="password", key="reg_p1")
            p2 = st.text_input("Confirm passphrase", type="password", key="reg_p2")
            submitted = st.form_submit_button("Create encrypted account", use_container_width=True)
        if submitted:
            if p1 != p2:
                st.error("Passphrases do not match.")
            else:
                try:
                    VAULT.register(u.strip(), p1)
                    st.success("Account created with a fresh RSA-3072 key pair. You can sign in now.")
                except AuthError as exc:
                    st.error(str(exc))


# --------------------------------------------------------------------------- #
# Vault screen (authenticated)
# --------------------------------------------------------------------------- #
def sidebar(session) -> None:
    with st.sidebar:
        st.markdown(f"### 👤 {session.username}")
        st.caption(f"Backend: **{VAULT.backend.label}**")
        st.caption(f"Scheme: `{SCHEME}`")
        st.divider()
        if st.button("Log out", use_container_width=True):
            logout()
            st.rerun()
        with st.expander("How your data is protected"):
            st.markdown(
                "- A random **AES-256** key encrypts each file (GCM mode → confidentiality **and** tamper-proofing).\n"
                "- That key is **wrapped with your RSA public key**; only your private key can unwrap it.\n"
                "- Your **private key** is itself encrypted with an **Argon2id** key derived from your passphrase.\n"
                "- A **SHA-256** of the original is stored and re-checked on every open.\n"
                "- Traffic to storage is over **HTTPS/TLS**."
            )


def upload_tab(session) -> None:
    st.subheader("Encrypt & store a document")
    st.write("Pick a file (PDFs get an inline preview; any file type is supported).")

    uploaded = st.file_uploader("Choose a file", type=None, key="uploader")
    col1, col2 = st.columns([1, 1])
    with col1:
        store = st.button("🔒 Encrypt & store", use_container_width=True, disabled=uploaded is None)
    with col2:
        use_sample = st.button("Use sample health report", use_container_width=True)

    data = name = None
    if use_sample:
        data, name = minimal_pdf(), "sample_report.pdf"
    elif store and uploaded is not None:
        data, name = uploaded.getvalue(), uploaded.name

    if data is not None:
        try:
            sidecar = VAULT.upload(session, name, data)
        except EhrCryptoError as exc:
            st.error(f"Encryption failed: {exc}")
            return

        st.success(f"“{name}” encrypted and stored ({human_size(sidecar.size)}).")
        stored = VAULT.backend.get_bytes(f"docs/{session.username}/{sidecar.file_id}.enc")
        with st.container():
            st.markdown('<div class="ehr-card">', unsafe_allow_html=True)
            st.markdown("**What was written to storage** (proof it's unreadable):")
            st.code(" ".join(f"{b:02x}" for b in stored[:48]) + " …", language="text")
            m1, m2, m3 = st.columns(3)
            m1.metric("Cipher", "AES-256-GCM")
            m2.metric("Key wrap", "RSA-OAEP")
            m3.metric("Ciphertext", human_size(len(stored)))
            st.caption(f"SHA-256 of original: `{sidecar.sha256}`")
            st.markdown("</div>", unsafe_allow_html=True)
        st.info("Open it any time from **My documents**.")


def documents_tab(session) -> None:
    st.subheader("My documents")
    docs = VAULT.list_documents(session.username)
    if not docs:
        st.info("No documents yet. Add one from the **Upload** tab.")
        return

    for d in docs:
        with st.expander(f"📄 {d.filename}  ·  {human_size(d.size)}  ·  {fmt_date(d.created_at)}"):
            st.caption(f"file_id `{d.file_id}` · SHA-256 `{d.sha256[:24]}…`")
            c1, c2, c3, c4 = st.columns(4)
            if c1.button("👁 View / verify", key=f"view_{d.file_id}", use_container_width=True):
                st.session_state.view_id = d.file_id
            if c2.button("✅ Verify only", key=f"verify_{d.file_id}", use_container_width=True):
                _verify_only(session, d)
            if c3.button("⚠️ Tamper (demo)", key=f"tamper_{d.file_id}", use_container_width=True):
                VAULT.tamper(session.username, d.file_id)
                st.session_state.flash = (
                    "warning",
                    f"Corrupted one byte of “{d.filename}”. Now click View to see detection.",
                )
                st.rerun()
            if c4.button("🗑 Delete", key=f"del_{d.file_id}", use_container_width=True):
                st.session_state.confirm_delete = d.file_id

    # Delete confirmation
    pending = st.session_state.get("confirm_delete")
    if pending:
        match = next((x for x in docs if x.file_id == pending), None)
        if match:
            st.warning(f"Delete “{match.filename}” permanently? This cannot be undone.")
            a, b = st.columns(2)
            if a.button("Yes, delete", type="primary"):
                VAULT.delete(session.username, pending)
                st.session_state.pop("confirm_delete", None)
                if st.session_state.get("view_id") == pending:
                    st.session_state.pop("view_id", None)
                st.rerun()
            if b.button("Cancel"):
                st.session_state.pop("confirm_delete", None)
                st.rerun()

    # View / integrity result
    view_id = st.session_state.get("view_id")
    if view_id:
        match = next((x for x in docs if x.file_id == view_id), None)
        if match:
            st.divider()
            st.markdown(f"### Viewing “{match.filename}”")
            try:
                plaintext = VAULT.view(session, view_id)
                st.markdown('<span class="ehr-badge ehr-ok">Integrity verified ✓</span>', unsafe_allow_html=True)
                render_preview(plaintext, match.filename)
            except (TamperError, IntegrityError) as exc:
                st.markdown('<span class="ehr-badge ehr-bad">Integrity FAILED ✗</span>', unsafe_allow_html=True)
                st.error(str(exc))
            except EhrCryptoError as exc:
                st.error(str(exc))


def _verify_only(session, d) -> None:
    try:
        VAULT.view(session, d.file_id)
        st.session_state.flash = ("success", f"“{d.filename}” — integrity verified ✓")
    except (TamperError, IntegrityError) as exc:
        st.session_state.flash = ("error", f"“{d.filename}” — {exc}")
    except EhrCryptoError as exc:
        st.session_state.flash = ("error", str(exc))
    st.rerun()


def vault_screen(session) -> None:
    sidebar(session)
    st.title("🔐 Secure EHR Vault")
    tab_docs, tab_upload = st.tabs(["My documents", "Upload"])
    with tab_docs:
        documents_tab(session)
    with tab_upload:
        upload_tab(session)


# --------------------------------------------------------------------------- #
# Router
# --------------------------------------------------------------------------- #
def main() -> None:
    flash = st.session_state.pop("flash", None)
    if flash:
        level, msg = flash
        getattr(st, level, st.info)(msg)

    session = st.session_state.get("session")
    if session is None:
        auth_screen()
    else:
        vault_screen(session)


main()
