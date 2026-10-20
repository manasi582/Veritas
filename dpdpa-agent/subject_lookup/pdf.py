"""
A small PDF writer for text records: A4, Courier (so line widths are exact), no dependencies, and the same bytes
for the same input, so a record's PDF can be hashed. Text outside Latin-1 is replaced by '?'.
"""
from __future__ import annotations

import textwrap
from typing import List, Tuple

PAGE_W, PAGE_H, MARGIN = 595, 842, 50
LINE_H = {"n": 12, "h": 17, "t": 22}
SIZE = {"n": 9, "h": 11, "t": 15}
CHARS = {"n": 90, "h": 70, "t": 48}       # Courier is 0.6 em wide: (595 - 100) / (size * 0.6)
FONT = {"n": "/F1", "h": "/F2", "t": "/F2"}


def _esc(text: str) -> bytes:
    raw = text.encode("cp1252", errors="replace")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def render(title: str, lines: List[Tuple[str, str]]) -> bytes:
    """`lines` are (style, text) with style 't' title, 'h' heading, 'n' normal, 'b' blank."""
    pages: List[List[Tuple[str, str]]] = [[]]
    y = PAGE_H - MARGIN
    items = [("t", title)] + list(lines)
    for style, text in items:
        if style == "b":
            y -= LINE_H["n"]
            if y < MARGIN:
                pages.append([]); y = PAGE_H - MARGIN
            continue
        for part in (textwrap.wrap(text, CHARS[style], break_long_words=True, replace_whitespace=False) or [""]):
            if y - LINE_H[style] < MARGIN:
                pages.append([]); y = PAGE_H - MARGIN
            pages[-1].append((style, part, y))
            y -= LINE_H[style]
    objs: List[bytes] = []

    def add(b: bytes) -> int:
        objs.append(b)
        return len(objs)

    add(b"<< /Type /Catalog /Pages 2 0 R >>")          # 1
    add(b"")                                            # 2 (filled below)
    add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")        # 3
    add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>")   # 4
    page_ids = []
    for page in pages:
        out = [b"BT"]
        for style, text, ypos in page:
            out.append(b"%s %d Tf 1 0 0 1 %d %d Tm (" % (FONT[style].encode(), SIZE[style], MARGIN, ypos) + _esc(text) + b") Tj")
        out.append(b"ET")
        stream = b"\n".join(out)
        cid = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        page_ids.append(add(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>"
                            % (PAGE_W, PAGE_H, cid)))
    objs[1] = b"<< /Type /Pages /Count %d /Kids [%s] >>" % (len(page_ids), b" ".join(b"%d 0 R" % i for i in page_ids))
    info = add(b"<< /Title (" + _esc(title) + b") /Producer (Veritas) >>")
    body = b"%PDF-1.4\n"
    offsets = []
    for i, o in enumerate(objs, start=1):
        offsets.append(len(body))
        body += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(body)
    body += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        body += b"%010d 00000 n \n" % off
    body += b"trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, info, xref)
    return body
