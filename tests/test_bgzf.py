"""Unit tests for BGZF + index validation."""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.bgzf import (  # noqa: E402
    EOF_MEMBER,
    MAX_ARCHIVE_SIZE,
    MAX_DATA_BLOCKS,
    AuditError,
    audit,
)
from tests.bgzf_fixtures import bgzf_block, build_archive, build_index  # noqa: E402


class ValidArchiveTests(unittest.TestCase):
    def test_single_block(self):
        payloads = [b"hello bgzf"]
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        result = audit(archive, index)
        self.assertEqual(result.data_blocks, 1)
        self.assertEqual(result.uncompressed_length, 10)
        self.assertEqual(result.sha256, hashlib.sha256(b"".join(payloads)).hexdigest())

    def test_many_blocks_offsets_and_digest(self):
        payloads = [b"x" * (i + 1) for i in range(50)]
        payloads[7] = b"chunk-eight"
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        result = audit(archive, index)
        stream = b"".join(payloads)
        self.assertEqual(result.data_blocks, 50)
        self.assertEqual(result.uncompressed_length, len(stream))
        self.assertEqual(result.sha256, hashlib.sha256(stream).hexdigest())

    def test_empty_payload_block_is_data(self):
        # An empty data block is byte-identical to the EOF sentinel only when
        # it carries the canonical XFL/OS bytes; a non-canonical empty block
        # (XFL=4, as written at compression level 1) is ordinary data.
        empty_block = bgzf_block(b"", level=1)
        second = bgzf_block(b"after")
        archive = empty_block + second + EOF_MEMBER
        index = struct.pack("<Q", 1) + struct.pack("<QQ", len(empty_block), 0)
        result = audit(archive, index)
        self.assertEqual(result.data_blocks, 2)
        self.assertEqual(result.uncompressed_length, 5)

    def test_incompressible_data(self):
        payloads = [os.urandom(5000)]
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        result = audit(archive, index)
        self.assertEqual(result.data_blocks, 1)
        self.assertEqual(result.sha256, hashlib.sha256(payloads[0]).hexdigest())


class ArchiveFailureTests(unittest.TestCase):
    def setUp(self):
        self.payloads = [b"aaaa", b"bbbb", b"cccc"]
        self.archive = build_archive(self.payloads)
        self.good_index = build_index(self.archive, self.payloads)

    def expect(self, archive, index, code, offset=None):
        with self.assertRaises(AuditError) as ctx:
            audit(archive, index)
        self.assertEqual(ctx.exception.code, code)
        if offset is not None:
            self.assertEqual(ctx.exception.offset, offset)
        return ctx.exception

    def test_empty_archive(self):
        self.expect(b"", self.good_index, "EMPTY_ARCHIVE", 0)

    def test_bad_magic(self):
        broken = b"XX" + self.archive[2:]
        self.expect(broken, self.good_index, "BAD_MAGIC", 0)

    def test_truncated_header(self):
        self.expect(self.archive[:5], self.good_index, "TRUNCATED_HEADER", 0)

    def test_missing_bc_field(self):
        # Rebuild a plain gzip member (no FEXTRA) for the first payload.
        co = zlib.compressobj(6, zlib.DEFLATED, 31)
        plain = co.compress(b"aaaa") + co.flush()
        broken = plain + self.archive[len(bgzf_block(b"aaaa")) :]
        self.expect(broken, self.good_index, "MISSING_BC_FIELD", 0)

    def test_duplicate_bc_field(self):
        first = bgzf_block(b"aaaa")
        # Insert a second BC subfield into FEXTRA and adjust XLEN + BSIZE.
        xlen = struct.unpack_from("<H", first, 10)[0]
        bc = first[12 : 12 + xlen]
        new_extra = bc + bc
        new_block = first[:10] + struct.pack("<H", len(new_extra)) + new_extra + first[12 + xlen :]
        new_block = new_block[:16] + struct.pack("<H", len(new_block) - 1) + new_block[18:]
        broken = new_block + self.archive[len(first) :]
        # Offset of the duplicated subfield: 12 header + first extra length.
        self.expect(broken, self.good_index, "DUPLICATE_BC_FIELD", 12 + xlen)

    def test_declared_block_size_short(self):
        broken = bytearray(self.archive)
        # Block 0 BSIZE at offset 16; shrink by 1.
        bsize = struct.unpack_from("<H", broken, 16)[0]
        struct.pack_into("<H", broken, 16, bsize - 1)
        # Either the deflate boundary or trailer check must fail at the block.
        with self.assertRaises(AuditError) as ctx:
            audit(bytes(broken), self.good_index)
        self.assertIn(ctx.exception.code, {"DEFLATE_NOT_TERMINATED", "BAD_BLOCK_SIZE", "CRC32_MISMATCH"})
        self.assertEqual(ctx.exception.offset, 18)  # deflate starts right after the 18-byte header

    def test_declared_block_size_long_consumes_next_block(self):
        broken = bytearray(self.archive)
        bsize = struct.unpack_from("<H", broken, 16)[0]
        struct.pack_into("<H", broken, 16, bsize + 1)
        with self.assertRaises(AuditError) as ctx:
            audit(bytes(broken), self.good_index)
        self.assertEqual(ctx.exception.code, "DEFLATE_BOUNDARY_MISMATCH")

    def test_crc_mismatch_points_at_trailer(self):
        broken = bytearray(self.archive)
        block0_len = len(bgzf_block(b"aaaa"))
        struct.pack_into("<I", broken, block0_len - 8, 0xDEADBEEF)
        self.expect(bytes(broken), self.good_index, "CRC32_MISMATCH", block0_len - 8)

    def test_isize_mismatch_points_at_isize_field(self):
        broken = bytearray(self.archive)
        block0_len = len(bgzf_block(b"aaaa"))
        struct.pack_into("<I", broken, block0_len - 4, 99)
        self.expect(bytes(broken), self.good_index, "ISIZE_MISMATCH", block0_len - 4)

    def test_bad_deflate_byte(self):
        block0 = bytearray(bgzf_block(b"aaaa"))
        # Flip a byte in the deflate stream (the fixed BGZF header is
        # 18 bytes for a 6-byte BC extra).
        block0[18] ^= 0xFF
        broken = bytes(block0) + self.archive[len(block0) :]
        with self.assertRaises(AuditError) as ctx:
            audit(broken, self.good_index)
        self.assertIn(ctx.exception.code, {"BAD_DEFLATE", "DEFLATE_NOT_TERMINATED", "CRC32_MISMATCH"})

    def test_missing_eof_member(self):
        broken = self.archive[: -len(EOF_MEMBER)]
        self.expect(broken, self.good_index, "MISSING_EOF_MEMBER")

    def test_trailing_bytes_after_eof(self):
        # A single trailing byte cannot begin a member: rejected as a
        # truncated header positioned exactly at the first extra byte.
        broken = self.archive + b"\x00"
        self.expect(broken, self.good_index, "TRUNCATED_HEADER", len(self.archive))

    def test_trailing_member_after_eof(self):
        # At least a full header's worth of non-gzip bytes after the EOF is
        # a bad-magic failure positioned at the first extra byte.
        broken = self.archive + b"\x00" * 10
        self.expect(broken, self.good_index, "BAD_MAGIC", len(self.archive))

    def test_nonstandard_eof_member(self):
        # A valid empty member that is not the canonical byte sequence
        # (different OS byte) must not count as the standard EOF.
        payload = b""
        co = zlib.compressobj(6, zlib.DEFLATED, -15)
        deflated = co.compress(payload) + co.flush()
        header = bytearray(struct.pack("<BBBBIBB", 0x1F, 0x8B, 8, 4, 0, 0, 0x03))
        extra = b"BC" + struct.pack("<H", 2) + b"\x00\x00"
        block = bytes(header) + struct.pack("<H", len(extra)) + extra + deflated
        block += struct.pack("<II", 0, 0)
        block = block[:16] + struct.pack("<H", len(block) - 1) + block[18:]
        data = build_archive([b"x"])
        data = data[: -len(EOF_MEMBER)] + block
        self.expect(data, build_index(data, [b"x"]), "MISSING_EOF_MEMBER")

    def test_eof_member_inside_data_region(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = build_archive(payloads)
        injected = bgzf_block(b"aaaa") + EOF_MEMBER + bgzf_block(b"bbbb") + EOF_MEMBER
        self.expect(injected, build_index(archive, payloads), "UNEXPECTED_EOF_MEMBER")

    def test_too_many_blocks(self):
        payloads = [b"x"] * (MAX_DATA_BLOCKS + 1)
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        with self.assertRaises(AuditError) as ctx:
            audit(archive, index)
        self.assertEqual(ctx.exception.code, "TOO_MANY_BLOCKS")
        self.assertEqual(ctx.exception.offset, len(b"".join(bgzf_block(b"x") for _ in range(MAX_DATA_BLOCKS))))

    def test_archive_too_large(self):
        # The size guard runs before parsing: an 8 MiB+ blob is rejected
        # regardless of whether a single BGZF member could encode it.
        blob = os.urandom(MAX_ARCHIVE_SIZE + 10)
        self.expect(blob, struct.pack("<Q", 0), "ARCHIVE_TOO_LARGE")


class IndexFailureTests(unittest.TestCase):
    def setUp(self):
        self.payloads = [b"aaaa", b"bbbb", b"cccc"]
        self.archive = build_archive(self.payloads)

    def expect(self, index, code):
        with self.assertRaises(AuditError) as ctx:
            audit(self.archive, index)
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception

    def test_truncated_index_header(self):
        self.expect(b"\x01\x02", "INDEX_TRUNCATED")

    def test_count_mismatch(self):
        good = build_index(self.archive, self.payloads)
        # Claim 9 entries while keeping the two real ones.
        self.expect(struct.pack("<Q", 9) + good[8:], "INDEX_COUNT_MISMATCH")

    def test_extra_index_bytes(self):
        good = build_index(self.archive, self.payloads)
        self.expect(good + b"\x00" * 16, "INDEX_SIZE_MISMATCH")

    def test_index_too_short(self):
        good = build_index(self.archive, self.payloads)
        self.expect(good[:-8], "INDEX_SIZE_MISMATCH")

    def test_compressed_offset_drift(self):
        good = bytearray(build_index(self.archive, self.payloads))
        # First pair's compressed offset is at byte 8; shift by one.
        struct.pack_into("<Q", good, 8, 1)
        with self.assertRaises(AuditError) as ctx:
            audit(self.archive, bytes(good))
        self.assertEqual(ctx.exception.code, "INDEX_COMPRESSED_OFFSET_MISMATCH")
        block1_start = len(bgzf_block(b"aaaa"))
        self.assertEqual(ctx.exception.offset, block1_start)

    def test_uncompressed_offset_drift(self):
        good = bytearray(build_index(self.archive, self.payloads))
        struct.pack_into("<Q", good, 16, 3)  # should be 4
        with self.assertRaises(AuditError) as ctx:
            audit(self.archive, bytes(good))
        self.assertEqual(ctx.exception.code, "INDEX_UNCOMPRESSED_OFFSET_MISMATCH")
        self.assertEqual(ctx.exception.offset, len(bgzf_block(b"aaaa")))

    def test_single_block_needs_empty_index(self):
        payloads = [b"only"]
        archive = build_archive(payloads)
        # count == 0, no entries
        result = audit(archive, struct.pack("<Q", 0))
        self.assertEqual(result.data_blocks, 1)
        # Nonzero count for one block is invalid
        self.expect(struct.pack("<Q", 1) + b"\x00" * 16, "INDEX_COUNT_MISMATCH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
