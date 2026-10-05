"""BGZF (Blocked GNU Zip Format) validation and index auditing.

A BGZF archive is a concatenation of gzip members.  Every member is a
complete gzip block carrying one ``BC`` extra subfield that declares the
total member size minus one (``BSIZE``).  Deflate data lives in its own
zlib "raw" stream per member, which makes every block independently
seekable.  A valid archive ends with exactly one canonical 28-byte empty
member (the BGZF EOF sentinel) and has no trailing bytes.

The companion index is a little-endian unsigned 64-bit structure::

    uint64 count
    (uint64 compressed_start, uint64 uncompressed_start) * count

with one entry for every data block except the first, recording the
block's compressed-file offset and the cumulative decompressed offset at
which its payload begins.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass

# Limits imposed by the platform.
MAX_ARCHIVE_SIZE = 8 * 1024 * 1024  # 8 MiB compressed archive
MAX_DATA_BLOCKS = 4096

# Canonical BGZF EOF member: an empty block produced by every conformant
# writer (htslib, bgzip, ...).
EOF_MEMBER = bytes.fromhex(
    "1f8b08040000000000ff0600424302001b0003000000000000000000"
)

GZIP_ID1 = 0x1F
GZIP_ID2 = 0x8B
CM_DEFLATE = 8
FLG_FEXTRA = 4


class AuditError(Exception):
    """Validation failure carrying a stable code and a compressed offset.

    ``offset`` is the first locatable byte position in the compressed
    archive involved in the failure (or ``None`` when the problem cannot
    be pinned to a particular byte, e.g. a malformed index header).
    """

    def __init__(self, code: str, message: str, offset: int | None = None):
        super().__init__(message)
        self.code = code
        self.offset = offset


@dataclass(frozen=True)
class AuditResult:
    data_blocks: int
    uncompressed_length: int
    sha256: str  # hex digest of the concatenated decompressed payload


def _fail(code: str, message: str, offset: int) -> "AuditError":
    return AuditError(code, message, offset)


def _parse_bgzf_member(data: bytes, start: int) -> tuple[int, bytes, int]:
    """Parse one BGZF member beginning at ``start``.

    Returns ``(member_end, payload, declared_isize)``.  Raises
    :class:`AuditError` on any inconsistency.
    """
    total = len(data)

    # --- Fixed gzip header (10 bytes) ---
    # Check magic first: a short garbage fragment points at byte 0 as a
    # bad member start, not as a truncated header.
    if start + 2 > total:
        raise _fail(
            "TRUNCATED_HEADER",
            "incomplete gzip header: need at least the 2-byte magic",
            start,
        )
    if data[start] != GZIP_ID1 or data[start + 1] != GZIP_ID2:
        raise _fail("BAD_MAGIC", "not a gzip member (missing 1f 8b magic)", start)
    if start + 10 > total:
        raise _fail(
            "TRUNCATED_HEADER",
            "incomplete gzip header: need 10 bytes",
            start,
        )
    cm, flg = data[start + 2], data[start + 3]
    if cm != CM_DEFLATE:
        raise _fail("BAD_COMPRESSION_METHOD", f"unsupported compression method {cm}", start)
    if not (flg & FLG_FEXTRA):
        raise _fail("MISSING_BC_FIELD", "gzip member has no FEXTRA fields", start)

    # --- FEXTRA: XLEN + subfields ---
    if start + 12 > total:
        raise _fail("TRUNCATED_HEADER", "incomplete FEXTRA length field", start)
    (xlen,) = struct.unpack_from("<H", data, start + 10)
    extra_start = start + 12
    extra_end = extra_start + xlen
    if extra_end > total:
        raise _fail("TRUNCATED_HEADER", "FEXTRA payload runs past end of archive", start)

    bsize: int | None = None
    p = extra_start
    while p + 4 <= extra_end:
        si1, si2 = data[p], data[p + 1]
        (slen,) = struct.unpack_from("<H", data, p + 2)
        field_data = p + 4
        field_end = field_data + slen
        if field_end > extra_end:
            raise _fail(
                "BAD_EXTRA_FIELD",
                "extra subfield length exceeds XLEN",
                p,
            )
        if si1 == ord("B") and si2 == ord("C"):
            if bsize is not None:
                raise _fail("DUPLICATE_BC_FIELD", "member contains more than one BC subfield", p)
            if slen != 2:
                raise _fail(
                    "BAD_BC_FIELD",
                    f"BC subfield must be 2 bytes, got {slen}",
                    p,
                )
            (bsize,) = struct.unpack_from("<H", data, field_data)
        p = field_end
    if p != extra_end:
        raise _fail("BAD_EXTRA_FIELD", "trailing bytes inside FEXTRA payload", p)
    if bsize is None:
        raise _fail("MISSING_BC_FIELD", "member has no BC (block size) subfield", start)

    # BSIZE is "total BGZF block size - 1".
    declared_member_size = bsize + 1
    member_end = start + declared_member_size
    if declared_member_size < 28:
        # Smallest legal member is the 28-byte empty EOF block.
        raise _fail(
            "BAD_BLOCK_SIZE",
            f"declared block size {declared_member_size} is below minimum 28",
            start,
        )
    if member_end > total:
        raise _fail(
            "BLOCK_SIZE_OVERRUN",
            f"declared block size {declared_member_size} runs past end of archive",
            start,
        )

    # Header flags other than FEXTRA (text/name/comment/hcrc) would mean the
    # header layout is no longer the fixed BGZF layout; reject them.
    allowed_flg = FLG_FEXTRA
    if flg & ~allowed_flg:
        raise _fail("UNSUPPORTED_HEADER_FLAGS", "BGZF members may only set FEXTRA", start)

    # --- Deflate stream and gzip trailer ---
    deflate_start = extra_end
    trailer = member_end - 8
    if trailer < deflate_start:
        raise _fail("BAD_BLOCK_SIZE", "declared block too short for deflate stream and trailer", start)

    decompressor = zlib.decompressobj(wbits=-15)  # raw deflate, no zlib/gzip wrapper
    try:
        payload = decompressor.decompress(data[deflate_start:trailer])
        payload += decompressor.flush()
    except zlib.error as exc:
        raise _fail("BAD_DEFLATE", f"deflate error: {exc}", deflate_start) from exc

    if not decompressor.eof:
        # The deflate stream did not terminate within the bytes the block
        # size allows: declared size / deflate boundary mismatch.
        raise _fail(
            "DEFLATE_NOT_TERMINATED",
            "deflate stream is not terminated within declared block",
            deflate_start,
        )
    # Unconsumed bytes between the end of the deflate stream and the trailer
    # are not permitted inside one member.
    if decompressor.unused_data:
        boundary = trailer - len(decompressor.unused_data)
        raise _fail(
            "DEFLATE_BOUNDARY_MISMATCH",
            "extra bytes found between deflate end and gzip trailer",
            boundary,
        )

    crc_stored, isize_stored = struct.unpack_from("<II", data, trailer)
    crc_actual = zlib.crc32(payload) & 0xFFFFFFFF
    if crc_stored != crc_actual:
        raise _fail(
            "CRC32_MISMATCH",
            f"stored CRC32 {crc_stored:08x} does not match payload {crc_actual:08x}",
            trailer,
        )
    isize_actual = len(payload) & 0xFFFFFFFF
    if isize_stored != isize_actual:
        raise _fail(
            "ISIZE_MISMATCH",
            f"stored ISIZE {isize_stored} does not match payload length {isize_actual}",
            trailer + 4,
        )

    return member_end, payload, isize_stored


def _validate_archive(archive: bytes) -> list[tuple[int, int, bytes]]:
    """Validate every structural aspect of an archive that does not need an
    index: size limits, member headers/Deflate/CRC32/ISIZE, the EOF layout
    and the data-block count.

    Returns ``(start, end, payload)`` for each data block (every member
    except the terminal EOF sentinel).  Raises :class:`AuditError` on the
    first problem, positioned at the first locatable compressed offset.
    """
    if len(archive) > MAX_ARCHIVE_SIZE:
        raise AuditError(
            "ARCHIVE_TOO_LARGE",
            f"archive is {len(archive)} bytes, limit is {MAX_ARCHIVE_SIZE}",
            None,
        )
    if not archive:
        raise AuditError("EMPTY_ARCHIVE", "archive is empty", 0)

    # Parse every member first, recording payloads and offsets.  Member,
    # Deflate, CRC32 and ISIZE validation all happens here.
    members: list[tuple[int, int, bytes]] = []  # (start, end, payload)
    pos = 0
    while pos < len(archive):
        end, payload, _isize = _parse_bgzf_member(archive, pos)
        members.append((pos, end, payload))
        pos = end

    # The final member must be exactly the canonical EOF sentinel.
    eof_start, eof_end, eof_payload = members[-1]
    if eof_payload or archive[eof_start:eof_end] != EOF_MEMBER:
        raise _fail(
            "MISSING_EOF_MEMBER",
            "last member is not the canonical 28-byte BGZF EOF block",
            eof_start,
        )

    data_members = members[:-1]
    if not data_members:
        raise _fail(
            "NO_DATA_BLOCKS",
            "archive contains only the EOF member and no data blocks",
            0,
        )
    # Exactly one standard EOF member is allowed: the final one.  An EOF
    # sentinel anywhere in the data region means the archive does not end
    # with exactly one.
    for start, _end, payload in data_members:
        if not payload and archive[start : start + len(EOF_MEMBER)] == EOF_MEMBER:
            raise _fail(
                "UNEXPECTED_EOF_MEMBER",
                "canonical EOF member appears before the end of the archive",
                start,
            )
    if len(data_members) > MAX_DATA_BLOCKS:
        raise _fail(
            "TOO_MANY_BLOCKS",
            f"archive has {len(data_members)} data blocks, limit is {MAX_DATA_BLOCKS}",
            data_members[MAX_DATA_BLOCKS][0],
        )

    return data_members


def _summarize(data_members: list[tuple[int, int, bytes]]) -> AuditResult:
    """Concatenate the verified payloads into the audit summary."""
    digest = hashlib.sha256()
    total = 0
    for _start, _end, payload in data_members:
        digest.update(payload)
        total += len(payload)
    return AuditResult(
        data_blocks=len(data_members),
        uncompressed_length=total,
        sha256=digest.hexdigest(),
    )


def audit(archive: bytes, index: bytes) -> AuditResult:
    """Validate a BGZF archive together with its companion block index.

    Raises :class:`AuditError` on the first problem, positioned at the
    first locatable compressed offset.
    """
    data_members = _validate_archive(archive)
    _audit_index(index, data_members)
    return _summarize(data_members)


def reindex(archive: bytes) -> tuple[bytes, AuditResult]:
    """Rebuild the companion block index for a trusted, valid archive.

    Every member, the EOF sentinel, every Deflate stream, CRC32 and ISIZE
    are verified before a single index byte is produced, so a failure can
    never surface alongside a partial index.  Returns the little-endian
    index body and the :class:`AuditResult` summary; a single-data-block
    archive yields a legal index whose only content is an eight-byte zero
    count.
    """
    data_members = _validate_archive(archive)
    result = _summarize(data_members)

    entries = [struct.pack("<Q", len(data_members) - 1)]
    cumulative = len(data_members[0][2])
    for start, _end, payload in data_members[1:]:
        entries.append(struct.pack("<QQ", start, cumulative))
        cumulative += len(payload)
    return b"".join(entries), result


def _audit_index(index: bytes, data_members: list[tuple[int, int, bytes]]) -> None:
    """Check the little-endian offset-pair index against the data blocks."""
    expected = len(data_members) - 1
    header_size = 8
    entry_size = 16
    min_size = header_size + expected * entry_size

    if len(index) < header_size:
        raise AuditError(
            "INDEX_TRUNCATED",
            "index is shorter than its 8-byte count header",
            None,
        )
    (count,) = struct.unpack_from("<Q", index, 0)
    if count != expected:
        raise AuditError(
            "INDEX_COUNT_MISMATCH",
            f"index declares {count} entries, archive has {expected} non-first data blocks",
            None,
        )
    if len(index) != min_size:
        raise AuditError(
            "INDEX_SIZE_MISMATCH",
            f"index for {count} entries must be {min_size} bytes, got {len(index)}",
            None,
        )

    # Cumulative decompressed start of block k = sum of payload lengths of
    # blocks 0..k-1.  The first entry (block 1) starts after block 0.
    cumulative = len(data_members[0][2])
    for i, (comp_off, uncomp_off) in enumerate(
        struct.iter_unpack("<QQ", index[header_size:])
    ):
        member_index = i + 1  # index entries correspond to blocks 1..n-1
        start, _end, payload = data_members[member_index]

        if comp_off != start:
            raise AuditError(
                "INDEX_COMPRESSED_OFFSET_MISMATCH",
                (
                    f"index entry {i}: compressed offset {comp_off} does not "
                    f"match block start {start}"
                ),
                start,
            )
        if uncomp_off != cumulative:
            raise AuditError(
                "INDEX_UNCOMPRESSED_OFFSET_MISMATCH",
                (
                    f"index entry {i}: uncompressed offset {uncomp_off} does not "
                    f"match cumulative payload start {cumulative}"
                ),
                start,
            )
        cumulative += len(payload)
