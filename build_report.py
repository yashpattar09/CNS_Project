"""Generate the Mini Project report (.docx) for the Secure EHR Vault.

Follows the institute template: Times New Roman, 1.5 line spacing, margins
L=1.25" R=1" T/B=0.75", chapter/heading/sub-heading sizes, a cover page with the
college header + logo, Contents and List of Figures tables, and all chapters.

Run:  python build_report.py
Output:  Mini Project Report - Secure EHR Vault.docx
Also generates two diagram images (fig_architecture.png, fig_flow.png).
"""

from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

NAVY = "#0b2a4a"
STEEL = "#1f6feb"
GREY = "#e8eef5"


# --------------------------------------------------------------------------- #
# 1) Diagrams
# --------------------------------------------------------------------------- #
def _box(ax, x, y, w, h, text, fc, ec=NAVY, fs=10, tc="black"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                                linewidth=1.5, edgecolor=ec, facecolor=fc))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, wrap=True)


def _arrow(ax, x1, y1, x2, y2, label=""):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=16,
                                 linewidth=1.4, color=NAVY))
    if label:
        ax.text((x1 + x2) / 2 + 0.12, (y1 + y2) / 2, label, fontsize=8, style="italic", color=NAVY)


def make_architecture(path):
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ax.set_xlim(0, 10); ax.set_ylim(0, 9); ax.axis("off")
    _box(ax, 1, 7, 8, 1.4,
         "PRESENTATION LAYER  —  app.py (Streamlit Web UI)\n"
         "register · login · upload · view · show-encrypted · verify · tamper · delete",
         GREY, fs=9)
    _box(ax, 1, 3.7, 8, 2.6,
         "CRYPTOGRAPHIC ENGINE  —  ehr_crypto/\n\n"
         "vault.py  (orchestration, per-user scoping)\n"
         "hybrid.py  (AES-256-GCM  +  RSA-OAEP key wrap  +  SHA-256)\n"
         "keys.py (RSA-3072, private-key protection) · kdf.py (Argon2id/PBKDF2)\n"
         "models.py (UserRecord, Sidecar) · exceptions.py",
         "#dbe8fb", fs=9)
    _box(ax, 1, 0.6, 8, 1.6,
         "STORAGE LAYER  (abstract StorageBackend)\n"
         "LocalStorage  (./vault_data)        SupabaseStorage  (private bucket, HTTPS/TLS)",
         GREY, fs=9)
    _arrow(ax, 5, 7, 5, 6.3, "Vault API")
    _arrow(ax, 5, 3.7, 5, 2.2, "StorageBackend")
    fig.tight_layout()
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def make_flow(path):
    fig, ax = plt.subplots(figsize=(7.6, 5.2))
    ax.set_xlim(0, 12); ax.set_ylim(0, 11); ax.axis("off")
    ax.text(3, 10.5, "ENCRYPTION  (Upload)", ha="center", fontsize=11, fontweight="bold", color=NAVY)
    ax.text(9, 10.5, "DECRYPTION  (View)", ha="center", fontsize=11, fontweight="bold", color=NAVY)

    _box(ax, 0.6, 8.6, 4.8, 1.2, "Plaintext file (PDF)", GREY, fs=9)
    _box(ax, 0.6, 6.8, 4.8, 1.2, "Random AES-256 key + 96-bit nonce", "#dbe8fb", fs=9)
    _box(ax, 0.6, 5.0, 4.8, 1.2, "AES-256-GCM encrypt\n-> ciphertext + 128-bit tag", "#dbe8fb", fs=9)
    _box(ax, 0.6, 3.2, 4.8, 1.2, "RSA-OAEP wrap AES key\nwith user PUBLIC key", "#dbe8fb", fs=9)
    _box(ax, 0.6, 1.2, 4.8, 1.4, "STORE: ciphertext + sidecar\n{wrapped_key, nonce, tag, sha256}", GREY, fs=9)
    _arrow(ax, 3, 8.6, 3, 8.0); _arrow(ax, 3, 6.8, 3, 6.2)
    _arrow(ax, 3, 5.0, 3, 4.4); _arrow(ax, 3, 3.2, 3, 2.6)

    _box(ax, 6.6, 8.6, 4.8, 1.2, "Load ciphertext + sidecar", GREY, fs=9)
    _box(ax, 6.6, 6.8, 4.8, 1.2, "RSA-OAEP unwrap key with\nuser PRIVATE key", "#dbe8fb", fs=9)
    _box(ax, 6.6, 5.0, 4.8, 1.2, "AES-256-GCM decrypt\n(tag verified -> tamper check)", "#dbe8fb", fs=9)
    _box(ax, 6.6, 3.2, 4.8, 1.2, "Verify SHA-256 == stored\n(integrity check)", "#dbe8fb", fs=9)
    _box(ax, 6.6, 1.2, 4.8, 1.4, "Return plaintext\nto the owner only", GREY, fs=9)
    _arrow(ax, 9, 8.6, 9, 8.0); _arrow(ax, 9, 6.8, 9, 6.2)
    _arrow(ax, 9, 5.0, 9, 4.4); _arrow(ax, 9, 3.2, 9, 2.6)

    fig.tight_layout()
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)


# --------------------------------------------------------------------------- #
# 2) Document helpers
# --------------------------------------------------------------------------- #
FONT = "Times New Roman"


def set_default_font(doc):
    st = doc.styles["Normal"]
    st.font.name = FONT
    st.font.size = Pt(12)
    st._element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
    pf = st.paragraph_format
    pf.line_spacing = 1.5
    pf.space_after = Pt(6)


def set_margins(doc):
    for s in doc.sections:
        s.left_margin = Inches(1.25)
        s.right_margin = Inches(1.0)
        s.top_margin = Inches(0.75)
        s.bottom_margin = Inches(0.75)


def _runs(p, text, size=12, bold=False, italic=False, color=None):
    r = p.add_run(text)
    r.font.name = FONT
    r.font.size = Pt(size)
    r.bold = bold
    r.italic = italic
    if color:
        r.font.color.rgb = RGBColor.from_string(color)
    return r


def para(doc, text="", size=12, bold=False, italic=False, align=None, space_after=6, color=None):
    p = doc.add_paragraph()
    if align is not None:
        p.alignment = align
    p.paragraph_format.space_after = Pt(space_after)
    if text:
        _runs(p, text, size, bold, italic, color)
    return p


def body(doc, text, justify=True):
    p = para(doc, text, size=12,
             align=WD_ALIGN_PARAGRAPH.JUSTIFY if justify else WD_ALIGN_PARAGRAPH.LEFT)
    return p


def bullet(doc, text, bold_lead=None):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.line_spacing = 1.5
    if bold_lead:
        _runs(p, bold_lead, 12, bold=True)
        _runs(p, text, 12)
    else:
        _runs(p, text, 12)
    return p


def chapter(doc, num, title):
    doc.add_page_break()
    para(doc, f"CHAPTER {num}", size=12, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=2)
    para(doc, title, size=16, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=10)


def subheading(doc, text):
    para(doc, text, size=14, bold=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=6)


def figure(doc, img_path, number, caption, width=5.6):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(img_path, width=Inches(width))
    cap = para(doc, f"Figure {number}: {caption}", size=8, bold=True,
               align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)
    return cap


def screenshot_placeholder(doc, number, caption, line1, line2):
    # Two lines of explanation ABOVE the screenshot, as the template requires.
    body(doc, line1)
    body(doc, line2)
    ph = para(doc, f"[  Paste screenshot here: {caption}  ]", size=11, italic=True,
              align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2, color="888888")
    pPr = ph._p.get_or_add_pPr()
    pbdr = OxmlElement("w:pBdr")
    for edge in ("top", "left", "bottom", "right"):
        e = OxmlElement(f"w:{edge}")
        e.set(qn("w:val"), "dashed"); e.set(qn("w:sz"), "6")
        e.set(qn("w:space"), "8"); e.set(qn("w:color"), "999999")
        pbdr.append(e)
    pPr.append(pbdr)
    para(doc, f"Figure {number}: {caption}", size=8, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)


def add_footer_page_numbers(doc):
    footer = doc.sections[0].footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run()
    for t, kind in (("begin", "w:fldChar"), (None, "instr"), ("end", "w:fldChar")):
        if kind == "instr":
            el = OxmlElement("w:instrText"); el.set(qn("xml:space"), "preserve"); el.text = "PAGE"
        else:
            el = OxmlElement("w:fldChar"); el.set(qn("w:fldCharType"), t)
        run._r.append(el)


def three_col_table(doc, headers, rows):
    t = doc.add_table(rows=1, cols=3)
    t.style = "Table Grid"
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]
        c.paragraphs[0].clear()
        _runs(c.paragraphs[0], h, 12, bold=True)
    for r in rows:
        cells = t.add_row().cells
        for i, val in enumerate(r):
            cells[i].paragraphs[0].clear()
            _runs(cells[i].paragraphs[0], str(val), 11)
    return t


# --------------------------------------------------------------------------- #
# 3) Build the report
# --------------------------------------------------------------------------- #
def build():
    make_architecture("fig_architecture.png")
    make_flow("fig_flow.png")

    doc = Document()
    set_margins(doc)
    set_default_font(doc)
    add_footer_page_numbers(doc)

    PROJECT_TITLE = "Hybrid Cryptographic Encryption System Using RSA and AES"
    PROJECT_SUB = "A Secure Electronic Health Record (EHR) Vault"

    # ---- COVER PAGE ----
    try:
        p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run().add_picture("report_assets_logo.jpeg", width=Inches(1.3))
    except Exception:
        pass
    para(doc, "S. G. BALEKUNDRI INSTITUTE OF TECHNOLOGY", size=15, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)
    para(doc, "Shivabasavanagar, Belagavi - 590 010, Karnataka, India", size=11,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)
    para(doc, "An ISO 21001:2018 Certified Institution  |  Approved by AICTE, New Delhi  |  "
              "Affiliated to VTU, Belagavi", size=9, italic=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    para(doc, "Department of Computer Science and Business Systems", size=13, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=18)

    para(doc, "A Mini Project Report on", size=12, italic=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6)
    para(doc, f"“{PROJECT_TITLE}”", size=16, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    para(doc, PROJECT_SUB, size=13, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=16)

    para(doc, "Submitted in partial fulfillment of the requirements for the award of the degree of",
         size=11, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    para(doc, "Bachelor of Engineering", size=12, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)
    para(doc, "in", size=11, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)
    para(doc, "Computer Science and Business Systems", size=12, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=16)

    para(doc, "Submitted by", size=11, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    para(doc, "[ Student Name ]        [ USN ]", size=12, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=16)

    para(doc, "Under the guidance of", size=11, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    para(doc, "[ Guide Name ], [ Designation ]", size=12, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=16)
    para(doc, "Academic Year 20__ - 20__", size=12, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)

    # ---- CERTIFICATE ----
    doc.add_page_break()
    para(doc, "CERTIFICATE", size=16, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=12)
    body(doc,
         "This is to certify that the mini project entitled "
         f"“{PROJECT_TITLE} - {PROJECT_SUB}” is a bonafide work carried out by "
         "[ Student Name ] ([ USN ]) in partial fulfillment of the requirements for the award of "
         "the degree of Bachelor of Engineering in Computer Science and Business Systems of "
         "Visvesvaraya Technological University, Belagavi, during the academic year 20__ - 20__. "
         "It is certified that all corrections / suggestions indicated during the internal "
         "evaluation have been incorporated in the report. The mini project report has been "
         "approved as it satisfies the academic requirements in respect of the mini project work "
         "prescribed for the said degree.")
    para(doc, "", space_after=18)
    tbl = doc.add_table(rows=1, cols=3)
    for i, who in enumerate(["Signature of the Guide", "Signature of the Coordinator",
                             "Signature of the HOD"]):
        cell = tbl.rows[0].cells[i]
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        _runs(cell.paragraphs[0], "\n\n\n" + who, 11, bold=True)

    # ---- ABSTRACT ----
    doc.add_page_break()
    para(doc, "ABSTRACT", size=16, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)
    body(doc,
         "Electronic Health Records contain highly sensitive personal data that must remain "
         "confidential and tamper-proof. This project implements a Secure EHR Vault built on a "
         "hybrid cryptosystem that combines symmetric and asymmetric encryption. Each uploaded "
         "report is encrypted with a fresh AES-256-GCM key; that key is wrapped using the owner's "
         "RSA-3072 public key, so only the owner's passphrase-protected private key can recover "
         "it. A SHA-256 fingerprint and the AES-GCM authentication tag detect any tampering. The "
         "private key is secured with an Argon2id key derived from a dedicated passphrase that is "
         "never stored, making the server zero-knowledge. The system is delivered as a Streamlit "
         "web application with optional cloud storage over HTTPS.")

    # ---- TABLE OF CONTENTS ----
    doc.add_page_break()
    para(doc, "TABLE OF CONTENTS", size=16, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)
    toc_rows = [
        ["", "Abstract", ""],
        ["1", "Introduction", ""],
        ["", "   1.1 Overview", ""],
        ["", "   1.2 Aim and Objectives", ""],
        ["", "   1.3 Literature Survey", ""],
        ["2", "Existing System", ""],
        ["3", "Proposed System", ""],
        ["", "   3.1 System Architecture", ""],
        ["", "   3.2 Module Description", ""],
        ["", "   3.3 Hybrid Encryption Scheme", ""],
        ["4", "System Requirements Specification", ""],
        ["5", "Implementation", ""],
        ["6", "Applications", ""],
        ["7", "Conclusion and Future Scope", ""],
        ["8", "Bibliography", ""],
    ]
    three_col_table(doc, ["Sl. No.", "Content", "Page No."], toc_rows)

    # ---- LIST OF FIGURES ----
    doc.add_page_break()
    para(doc, "LIST OF FIGURES", size=16, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)
    lof_rows = [
        ["3.1", "System Architecture of the Secure EHR Vault", ""],
        ["3.2", "Hybrid RSA + AES Encryption and Decryption Data Flow", ""],
        ["5.1", "Account Registration / Login", ""],
        ["5.2", "Upload and Encrypt a Document", ""],
        ["5.3", "Encrypted-at-rest (ciphertext) View", ""],
        ["5.4", "Decrypted View with Integrity Verified", ""],
        ["5.5", "Tamper Detection", ""],
        ["5.6", "Command-line Demonstration Output", ""],
    ]
    three_col_table(doc, ["Fig. No.", "Figure Name", "Page No."], lof_rows)

    # ===================== CHAPTER 1 : INTRODUCTION =====================
    chapter(doc, 1, "INTRODUCTION")
    subheading(doc, "1.1 Overview")
    body(doc,
         "Healthcare is rapidly moving from paper files to digital Electronic Health Records "
         "(EHRs). While digitisation improves access and continuity of care, it also concentrates "
         "sensitive data - diagnoses, lab reports, prescriptions - in systems that can be breached, "
         "copied, or silently altered. Regulations and patient trust both demand that such records "
         "stay confidential and that any modification be detectable.")
    body(doc,
         "A common but weak approach is to store documents in a database or file server and rely "
         "on access control or on encryption whose keys are held by the service provider. In such "
         "designs, the provider (or anyone who compromises it) can read every record. This project "
         "takes a stronger, cryptographically enforced approach: documents are encrypted on the "
         "server before storage, but in a way that only the owning user - holding a secret "
         "passphrase - can ever decrypt, so even the operator cannot read them.")
    body(doc,
         "The solution uses a hybrid cryptosystem. Symmetric encryption (AES-256-GCM) provides "
         "fast, authenticated encryption of the file contents, while asymmetric encryption "
         "(RSA-3072 with OAEP padding) is used to protect (wrap) the symmetric key so that only "
         "the intended user can unlock it. This mirrors the design of widely used secure protocols "
         "such as TLS and PGP. Integrity is guaranteed by the AES-GCM authentication tag and an "
         "additional SHA-256 fingerprint of the original file.")

    subheading(doc, "1.2 Aim and Objectives")
    body(doc, "Aim: To design and implement a secure EHR storage system in which health-report "
              "documents are automatically encrypted using a hybrid of RSA and AES, are accessible "
              "only to their owner, and are protected against tampering.")
    bullet(doc, "Encrypt every uploaded document with a unique AES-256-GCM key.", "Confidentiality: ")
    bullet(doc, "Wrap the AES key with the user's RSA public key so only the owner can decrypt.",
           "Access control: ")
    bullet(doc, "Protect the RSA private key with an Argon2id key derived from a dedicated, "
                "never-stored passphrase (zero-knowledge server).", "Key management: ")
    bullet(doc, "Detect any modification using the AES-GCM tag and a stored SHA-256 hash.",
           "Integrity: ")
    bullet(doc, "Provide a professional web interface to upload, view, verify and delete records, "
                "and transmit data over HTTPS/TLS.", "Usability & transport: ")

    subheading(doc, "1.3 Literature Survey")
    body(doc,
         "[1] W. Diffie and M. Hellman, “New Directions in Cryptography” (1976), introduced "
         "public-key cryptography and the idea of using separate keys for encryption and "
         "decryption. This project applies that principle through RSA key pairs so that encryption "
         "(with a public key) and decryption (with a private key) are cleanly separated per user.")
    body(doc,
         "[2] R. Rivest, A. Shamir and L. Adleman, “A Method for Obtaining Digital Signatures "
         "and Public-Key Cryptosystems” (1978), defined the RSA algorithm. We use RSA-3072 with "
         "OAEP padding to securely wrap the per-file AES key, which is RSA's ideal role (secure "
         "transport of a small secret) rather than bulk encryption.")
    body(doc,
         "[3] M. Dworkin, NIST SP 800-38D, “Recommendation for Block Cipher Modes of Operation: "
         "Galois/Counter Mode (GCM)” (2007), specifies authenticated encryption with AES. We adopt "
         "AES-256-GCM so that confidentiality and integrity are provided together, removing the need "
         "for a separate message authentication code.")
    body(doc,
         "[4] A. Biryukov, D. Dinu and D. Khovratovich, “Argon2: New Generation of Memory-Hard "
         "Functions for Password Hashing” (2016), presents the Argon2 KDF. We use Argon2id to turn "
         "the user's passphrase into the key that protects their RSA private key, resisting "
         "brute-force and GPU attacks far better than a simple hash.")

    # ===================== CHAPTER 2 : EXISTING SYSTEM =====================
    chapter(doc, 2, "EXISTING SYSTEM")
    body(doc,
         "In many existing health-record systems, documents are stored either in plaintext or with "
         "server-side encryption where the service provider holds and manages the keys. Access is "
         "typically guarded by a single account login shared with the rest of the application.")
    subheading(doc, "2.1 Limitations of the Existing System")
    bullet(doc, "The provider (or an attacker who compromises the server/database) can read every "
                "stored record, because the decryption keys live on the server.")
    bullet(doc, "A single application login protects the records; if those credentials leak, the "
                "documents are exposed.")
    bullet(doc, "Plaintext or provider-encrypted storage offers no cryptographic guarantee that a "
                "stored file has not been silently modified.")
    bullet(doc, "There is usually no per-document key, so compromise of one key can expose many "
                "or all files.")
    bullet(doc, "Confidentiality depends on trusting the operator rather than on mathematics.")

    # ===================== CHAPTER 3 : PROPOSED SYSTEM =====================
    chapter(doc, 3, "PROPOSED SYSTEM")
    body(doc,
         "The proposed Secure EHR Vault encrypts every document on the server before storage using "
         "a hybrid scheme, and arranges keys so that only the owning user can decrypt. The design "
         "is zero-knowledge: the passphrase that ultimately unlocks a user's data is never stored, "
         "so the operator cannot read user documents even if they wanted to.")

    subheading(doc, "3.1 System Architecture")
    body(doc, "The system is organised into three clearly separated layers - a Streamlit "
              "presentation layer, a standalone cryptographic engine, and a pluggable storage "
              "layer - as shown in Figure 3.1.")
    figure(doc, "fig_architecture.png", "3.1", "System Architecture of the Secure EHR Vault")

    subheading(doc, "3.2 Module Description")
    bullet(doc, "The Streamlit web interface. It handles registration, login, upload, viewing, "
                "the encrypted-at-rest view, integrity verification, the tamper demo and deletion. "
                "It never performs cryptography itself - it calls the vault engine.", "app.py: ")
    bullet(doc, "The high-level orchestrator. It implements register, login, upload, list, view "
                "and delete, and scopes every object to its owning user.", "vault.py: ")
    bullet(doc, "The hybrid encryption core: encrypt_document and decrypt_document, implementing "
                "AES-256-GCM encryption, RSA-OAEP key wrapping and SHA-256 integrity.", "hybrid.py: ")
    bullet(doc, "RSA-3072 key-pair generation and protection of the private key using a "
                "passphrase-derived key.", "keys.py: ")
    bullet(doc, "Key derivation from the passphrase using Argon2id (default) or PBKDF2.", "kdf.py: ")
    bullet(doc, "The UserRecord and Sidecar data records that are persisted as JSON.", "models.py: ")
    bullet(doc, "Storage abstraction with a local-disk backend and a Supabase cloud backend.",
           "storage.py: ")

    subheading(doc, "3.3 Hybrid Encryption Scheme")
    body(doc, "Figure 3.2 shows the end-to-end data flow. On upload, the file is encrypted with a "
              "random AES key which is then wrapped with the user's RSA public key; on view, the "
              "private key unwraps the AES key, the file is decrypted, and integrity is verified.")
    figure(doc, "fig_flow.png", "3.2", "Hybrid RSA + AES Encryption and Decryption Data Flow", width=6.0)
    body(doc, "Only the ciphertext and a small metadata record (the wrapped AES key, the nonce, "
              "the authentication tag and the SHA-256 fingerprint) are stored. The plaintext file "
              "and the raw AES key are never written to storage.")

    # ===================== CHAPTER 4 : SRS =====================
    chapter(doc, 4, "SYSTEM REQUIREMENTS SPECIFICATION")
    subheading(doc, "4.1 Hardware Requirements")
    bullet(doc, "Processor: Dual-core 2.0 GHz or higher (x86-64).")
    bullet(doc, "RAM: 4 GB minimum (8 GB recommended; Argon2id uses 64 MiB per derivation).")
    bullet(doc, "Storage: 500 MB free for the environment and encrypted vault.")
    bullet(doc, "A standard laptop/desktop; internet connection required only for the optional "
                "cloud (Supabase) backend and for deployment.")
    subheading(doc, "4.2 Software Requirements")
    bullet(doc, "Operating System: Windows 10/11, Linux or macOS.")
    bullet(doc, "Python 3.10 or newer (developed and tested on Python 3.13).")
    bullet(doc, "Libraries: streamlit, cryptography, argon2-cffi, supabase (optional), pytest.")
    bullet(doc, "A modern web browser (Chrome, Edge, Firefox).")
    bullet(doc, "Optional: a Supabase account with a private Storage bucket for cloud persistence.")

    # ===================== CHAPTER 5 : IMPLEMENTATION =====================
    chapter(doc, 5, "IMPLEMENTATION")
    body(doc,
         "The cryptographic engine is implemented in pure Python using the cryptography and "
         "argon2-cffi libraries; no cryptographic primitive is hand-written. The engine exposes a "
         "Vault class used by a Streamlit application. The following screenshots show the working "
         "system. (Each screenshot is preceded by a two-line explanation, as required.)")

    subheading(doc, "5.1 Registration and Login")
    screenshot_placeholder(doc, "5.1", "Account Registration / Login",
        "The user creates an account with a username and a dedicated EHR passphrase; this generates "
        "an RSA-3072 key pair whose private key is encrypted with an Argon2id-derived key.",
        "On login, the passphrase re-derives that key and decrypts the private key into memory for "
        "the session only; a wrong passphrase fails the authentication-tag check and is rejected.")

    subheading(doc, "5.2 Uploading and Encrypting a Document")
    screenshot_placeholder(doc, "5.2", "Upload and Encrypt a Document",
        "The user selects a PDF health report and clicks Encrypt & store; a fresh AES-256-GCM key "
        "encrypts the file and is then wrapped with the user's RSA public key.",
        "The interface confirms storage and shows a preview of the raw encrypted bytes, proving the "
        "stored content is unreadable ciphertext.")

    subheading(doc, "5.3 Encrypted-at-rest View")
    screenshot_placeholder(doc, "5.3", "Encrypted-at-rest (ciphertext) View",
        "The Show-encrypted option displays exactly what is written to storage: a hex dump of the "
        "ciphertext together with the sidecar metadata (wrapped key, nonce, tag, SHA-256).",
        "The bytes do not begin with %PDF and contain no readable text, demonstrating that an "
        "attacker with storage access cannot read the document.")

    subheading(doc, "5.4 Viewing (Decryption) with Integrity Check")
    screenshot_placeholder(doc, "5.4", "Decrypted View with Integrity Verified",
        "When the owner clicks View, the private key unwraps the AES key, the file is decrypted and "
        "its SHA-256 is re-verified against the stored value.",
        "An Integrity verified badge is shown and the original PDF is rendered and made available "
        "for download, confirming a correct round-trip.")

    subheading(doc, "5.5 Tamper Detection")
    screenshot_placeholder(doc, "5.5", "Tamper Detection",
        "The Tamper demo corrupts a single byte of the stored ciphertext to simulate an attack on "
        "the storage medium.",
        "The next View attempt fails the AES-GCM authentication check and the system clearly reports "
        "an integrity failure instead of returning corrupted data.")

    subheading(doc, "5.6 Command-line Demonstration and Testing")
    screenshot_placeholder(doc, "5.6", "Command-line Demonstration Output",
        "A standalone console demo (demo.py) registers two users, encrypts a report, shows the "
        "unreadable ciphertext, decrypts it back, and proves another user cannot decrypt it.",
        "An automated test suite (pytest) verifies the encrypt-decrypt round trip, wrong-user "
        "rejection and tamper detection - all eight tests pass.")

    # ===================== CHAPTER 6 : APPLICATIONS =====================
    chapter(doc, 6, "APPLICATIONS")
    bullet(doc, "Secure storage of patient health records, lab reports and prescriptions in "
                "hospitals and clinics.")
    bullet(doc, "Personal medical document vaults where individuals keep their own reports "
                "private.")
    bullet(doc, "Telemedicine platforms that must store and exchange confidential documents.")
    bullet(doc, "Insurance and legal document archives requiring confidentiality and tamper "
                "evidence.")
    bullet(doc, "Any application needing per-user, zero-knowledge encrypted file storage with "
                "integrity guarantees.")

    # ===================== CHAPTER 7 : CONCLUSION & FUTURE SCOPE =====================
    chapter(doc, 7, "CONCLUSION AND FUTURE SCOPE")
    subheading(doc, "7.1 Conclusion")
    body(doc,
         "The project successfully implements a Secure EHR Vault using a hybrid RSA and AES "
         "cryptosystem. Documents are automatically encrypted with per-file AES-256-GCM keys that "
         "are wrapped using each user's RSA-3072 public key, ensuring that only the owner can "
         "decrypt them. The owner's private key is protected by an Argon2id key derived from a "
         "passphrase that is never stored, so the server remains zero-knowledge. The AES-GCM "
         "authentication tag together with a stored SHA-256 fingerprint guarantees that any "
         "tampering is detected. Delivered as a Streamlit web application with HTTPS transport and "
         "an optional cloud backend, the system meets its goals of confidentiality, per-user access "
         "control and integrity.")
    subheading(doc, "7.2 Future Scope")
    bullet(doc, "Encrypt document metadata (filename, size, dates) in addition to contents.")
    bullet(doc, "Add secure sharing by re-wrapping a file's AES key with a doctor's public key.")
    bullet(doc, "Introduce multi-factor authentication and an optional key-recovery/escrow scheme.")
    bullet(doc, "Maintain a tamper-evident audit log of all access and modification events.")
    bullet(doc, "Provide a mobile client and integrate with hospital information systems.")

    # ===================== CHAPTER 8 : BIBLIOGRAPHY =====================
    chapter(doc, 8, "BIBLIOGRAPHY")
    refs = [
        "W. Diffie and M. E. Hellman, “New Directions in Cryptography,” IEEE Transactions on "
        "Information Theory, vol. 22, no. 6, pp. 644-654, 1976.",
        "R. L. Rivest, A. Shamir and L. Adleman, “A Method for Obtaining Digital Signatures and "
        "Public-Key Cryptosystems,” Communications of the ACM, vol. 21, no. 2, pp. 120-126, 1978.",
        "M. Dworkin, “Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode "
        "(GCM) and GMAC,” NIST Special Publication 800-38D, 2007.",
        "A. Biryukov, D. Dinu and D. Khovratovich, “Argon2: New Generation of Memory-Hard "
        "Functions for Password Hashing,” IEEE European Symposium on Security and Privacy, 2016.",
        "National Institute of Standards and Technology, “Advanced Encryption Standard (AES),” "
        "FIPS Publication 197, 2001.",
        "K. Moriarty, B. Kaliski, J. Jonsson and A. Rusch, “PKCS #1: RSA Cryptography "
        "Specifications Version 2.2,” RFC 8017, 2016.",
        "Python Cryptographic Authority, “cryptography library documentation,” cryptography.io.",
        "Streamlit Inc., “Streamlit documentation,” streamlit.io.",
    ]
    for i, r in enumerate(refs, start=1):
        p = doc.add_paragraph()
        p.paragraph_format.line_spacing = 1.5
        _runs(p, f"[{i}] ", 12, bold=True)
        _runs(p, r, 12)

    out = "Mini Project Report - Secure EHR Vault.docx"
    doc.save(out)
    print("Saved:", out)


if __name__ == "__main__":
    build()
