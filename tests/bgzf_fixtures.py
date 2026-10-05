"""Helpers for building BGZF archives and indexes in tests."""

from __future__ import annotations

import struct
import zlib

EOF_MEMBER = bytes.fromhex("1f8b08040000000000ff0600424302001b0003000000000000000000")


def bgzf_block(payload: bytes, level: int = 6) -> bytes:
    """Return one valid BGZF member containing ``payload``."""
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    deflated = compressor.compress(payload) + compressor.flush()
    # XFL convention used by bgzip: 2 for max compression, 4 for fastest.
    xfl = 2 if level == 9 else 4 if level == 1 else 0
    header = struct.pack(
        "<BBBBIBB",
        0x1F,
        0x8B,
        8,  # CM = deflate
        4,  # FLG = FEXTRA
        0,  # MTIME
        xfl,
        0xFF,  # OS = unknown
    )
    extra = b"BC" + struct.pack("<H", 2) + b"\x00\x00"  # BC subfield + BSIZE placeholder
    body = header + struct.pack("<H", len(extra)) + extra + deflated
    member = body + struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload))
    bsize = len(member) - 1
    # Patch BSIZE in place: header 10 + XLEN 2 + "BC" 2 + slen 2 = offset 16.
    member = member[:16] + struct.pack("<H", bsize) + member[18:]
    return member


def build_archive(payloads: list[bytes], *, eof: bool = True) -> bytes:
    out = b"".join(bgzf_block(p) for p in payloads)
    if eof:
        out += EOF_MEMBER
    return out


def build_index(archive: bytes, payloads: list[bytes]) -> bytes:
    """Build the canonical companion index for a generated archive."""
    offsets: list[tuple[int, int]] = []
    comp = 0
    uncomp = 0
    for payload in payloads:
        member = bgzf_block(payload)
        if comp != 0:  # first data block has no index entry
            offsets.append((comp, uncomp))
        comp += len(member)
        uncomp += len(payload)
    return struct.pack("<Q", len(offsets)) + b"".join(
        struct.pack("<QQ", c, u) for c, u in offsets
    )


def encode_multipart(fields: dict[str, tuple[str, bytes]]) -> tuple[bytes, str]:
    """Encode ``{field_name: (filename, content)}`` as multipart/form-data."""
    boundary = "----bgzf-audit-test-boundary"
    chunks: list[bytes] = []
    for name, (filename, content) in fields.items():
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        )
        chunks.append(b"Content-Type: application/octet-stream\r\n\r\n")
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"
