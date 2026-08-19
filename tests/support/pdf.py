"""Shared helper: build a minimal valid PDF carrying a single line of text.

Kept pure-Python so the audit tests don't pull in reportlab / fpdf2 as dev
deps just for a pypdf roundtrip."""

from __future__ import annotations


def minimal_pdf_with_text(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content_stream = f"BT\n/F1 12 Tf\n50 750 Td\n({escaped}) Tj\nET\n".encode("ascii")
    objects: list[bytes] = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Count 1/Kids[3 0 R]>>",
        b"<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
        (f"<</Length {len(content_stream)}>>\nstream\n".encode("ascii") + content_stream + b"endstream"),
        b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
    ]
    buf = bytearray(b"%PDF-1.4\n")
    xref_offsets: list[int] = []
    for idx, obj in enumerate(objects, start=1):
        xref_offsets.append(len(buf))
        buf += f"{idx} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"
    xref_start = len(buf)
    buf += b"xref\n0 " + str(len(objects) + 1).encode("ascii") + b"\n"
    buf += b"0000000000 65535 f \n"
    for offset in xref_offsets:
        buf += f"{offset:010d} 00000 n \n".encode("ascii")
    buf += b"trailer\n<</Size " + str(len(objects) + 1).encode("ascii") + b"/Root 1 0 R>>\n"
    buf += b"startxref\n" + str(xref_start).encode("ascii") + b"\n%%EOF\n"
    return bytes(buf)
