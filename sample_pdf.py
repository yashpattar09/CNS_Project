"""Generate a tiny, valid PDF with no third-party dependency.

Used to produce `sample/sample_report.pdf` for the demo and to let the Streamlit
app offer a "load sample report" button. Hand-building a minimal PDF keeps the
project's runtime dependencies limited to the crypto stack.
"""

from __future__ import annotations

import os
from typing import List, Optional


def _esc(text: str) -> bytes:
    return (
        text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    ).encode("latin-1", "replace")


def minimal_pdf(title: str = "Confidential Health Report", lines: Optional[List[str]] = None) -> bytes:
    """Return the bytes of a one-page PDF containing `title` and `lines`."""
    if lines is None:
        lines = [
            "Patient: Jane Doe            MRN: 0042-LL",
            "Test: Complete Blood Count (CBC)",
            "",
            "Haemoglobin ....... 13.6 g/dL   (12.0-15.5)",
            "WBC ............... 6.8 x10^9/L  (4.0-11.0)",
            "Platelets ......... 250 x10^9/L  (150-400)",
            "",
            "This document is encrypted at rest with AES-256-GCM;",
            "the file key is wrapped with the patient's RSA public key.",
        ]

    ops = [b"BT /F1 18 Tf 72 720 Td (%s) Tj ET" % _esc(title)]
    y = 690
    for line in lines:
        ops.append(b"BT /F1 12 Tf 72 %d Td (%s) Tj ET" % (y, _esc(line)))
        y -= 20
    content = b"\n".join(ops)

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"

    xref_pos = len(out)
    count = len(objects) + 1
    out += b"xref\n0 %d\n" % count
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (count, xref_pos)
    return bytes(out)


def write_sample(path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(minimal_pdf())
    return path


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(here, "sample", "sample_report.pdf")
    write_sample(target)
    print(f"Wrote {target} ({os.path.getsize(target)} bytes)")
