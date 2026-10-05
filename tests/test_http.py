"""End-to-end HTTP tests against a real server socket."""

from __future__ import annotations

import http.client
import json
import os
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.server import create_server  # noqa: E402
from tests.bgzf_fixtures import bgzf_block, build_archive, build_index, encode_multipart  # noqa: E402


class HttpServerTestBase(unittest.TestCase):
    def setUp(self):
        self.server = create_server(host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def post_audit(self, fields, content_type=None, raw_body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        if raw_body is not None:
            conn.request("POST", "/api/bgzf/audit", body=raw_body, headers={"Content-Type": content_type})
        else:
            body, ct = encode_multipart(fields)
            conn.request(
                "POST",
                "/api/bgzf/audit",
                body=body,
                headers={"Content-Type": ct, "Content-Length": str(len(body))},
            )
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else None

    def post_reindex(self, fields):
        body, ct = encode_multipart(fields)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/api/bgzf/reindex",
            body=body,
            headers={"Content-Type": ct, "Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        data = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, headers, data

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data)


class AuditEndpointTests(HttpServerTestBase):
    def test_healthz(self):
        status, body = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_valid_archive_ok(self):
        payloads = [b"block-zero", b"block-one", b"block-two"]
        archive = build_archive(payloads)
        index = build_index(archive, payloads)
        status, body = self.post_audit(
            {"archive": ("a.bgz", archive), "index": ("a.gzi", index)}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data_blocks"], 3)
        self.assertEqual(body["uncompressed_length"], sum(map(len, payloads)))

    def test_crc_corruption_returns_422_with_offset(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = bytearray(build_archive(payloads))
        block0_len = len(bgzf_block(b"aaaa"))
        struct.pack_into("<I", archive, block0_len - 8, 0x0BADF00D)
        index = build_index(bytes(archive), payloads)
        status, body = self.post_audit(
            {"archive": ("a.bgz", bytes(archive)), "index": ("a.gzi", index)}
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "CRC32_MISMATCH")
        self.assertEqual(body["error"]["offset"], block0_len - 8)

    def test_block_size_drift_returns_422_with_offset(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = bytearray(build_archive(payloads))
        struct.pack_into("<H", archive, 16, struct.unpack_from("<H", archive, 16)[0] - 1)
        index = build_index(bytes(archive), payloads)
        status, body = self.post_audit(
            {"archive": ("a.bgz", bytes(archive)), "index": ("a.gzi", index)}
        )
        self.assertEqual(status, 422)
        self.assertIn(
            body["error"]["code"],
            {"DEFLATE_NOT_TERMINATED", "BAD_BLOCK_SIZE", "CRC32_MISMATCH"},
        )
        self.assertIsNotNone(body["error"]["offset"])

    def test_index_drift_returns_422(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = build_archive(payloads)
        index = bytearray(build_index(archive, payloads))
        struct.pack_into("<Q", index, 8, 0)  # compressed offset of block 1 wrong
        status, body = self.post_audit(
            {"archive": ("a.bgz", archive), "index": ("a.gzi", bytes(index))}
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "INDEX_COMPRESSED_OFFSET_MISMATCH")
        self.assertEqual(body["error"]["offset"], len(bgzf_block(b"aaaa")))

    def test_missing_part(self):
        payloads = [b"aaaa"]
        archive = build_archive(payloads)
        status, body = self.post_audit({"archive": ("a.bgz", archive)})
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "MISSING_PART")

    def test_wrong_content_type(self):
        status, body = self.post_audit(
            {}, content_type="application/json", raw_body=b"{}"
        )
        self.assertEqual(status, 415)
        self.assertEqual(body["error"]["code"], "UNSUPPORTED_MEDIA_TYPE")

    def test_not_found(self):
        status, body = self.get("/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "NOT_FOUND")

    def test_error_shape_is_stable(self):
        # Garbage archive must not leak a partial result; exactly one error
        # object with code/message/offset is returned.
        body_bytes, ct = encode_multipart(
            {"archive": ("a.bgz", b"garbage"), "index": ("a.gzi", struct.pack("<Q", 0))}
        )
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/bgzf/audit", body=body_bytes, headers={"Content-Type": ct})
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 422)
        self.assertEqual(set(payload.keys()), {"error"})
        self.assertEqual(set(payload["error"].keys()), {"code", "message", "offset"})
        self.assertEqual(payload["error"]["code"], "BAD_MAGIC")
        self.assertEqual(payload["error"]["offset"], 0)


class ReindexEndpointTests(HttpServerTestBase):
    def test_rebuilds_index_then_round_trips_through_audit(self):
        import hashlib

        from app.bgzf import audit

        payloads = [b"reindex-zero", b"reindex-one", b"reindex-two"]
        archive = build_archive(payloads)
        status, headers, data = self.post_reindex(
            {"archive": ("a.bgz", archive)}
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/octet-stream")
        expected_index = build_index(archive, payloads)
        self.assertEqual(data, expected_index)
        self.assertEqual(headers["content-length"], str(len(expected_index)))
        self.assertEqual(headers["x-bgzf-block-count"], "3")
        self.assertEqual(
            headers["x-bgzf-uncompressed-length"], str(sum(map(len, payloads)))
        )
        stream = b"".join(payloads)
        self.assertEqual(headers["x-bgzf-sha256"], hashlib.sha256(stream).hexdigest())

        # The rebuilt index is immediately usable by the audit endpoint.
        status2, body2 = self.post_audit(
            {"archive": ("a.bgz", archive), "index": ("a.gzi", data)}
        )
        self.assertEqual(status2, 200, body2)
        self.assertEqual(body2["data_blocks"], 3)
        self.assertEqual(body2["sha256"], headers["x-bgzf-sha256"])
        self.assertEqual(audit(archive, data).sha256, headers["x-bgzf-sha256"])

    def test_single_block_yields_zero_count_index(self):
        archive = build_archive([b"solo"])
        status, headers, data = self.post_reindex(
            {"archive": ("a.bgz", archive)}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, struct.pack("<Q", 0))
        self.assertEqual(headers["x-bgzf-block-count"], "1")
        self.assertEqual(headers["x-bgzf-uncompressed-length"], "4")
        status2, body2 = self.post_audit(
            {"archive": ("a.bgz", archive), "index": ("a.gzi", data)}
        )
        self.assertEqual(status2, 200, body2)

    def test_corrupt_archive_rejected_without_partial_index(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = bytearray(build_archive(payloads))
        first_len = len(bgzf_block(b"aaaa"))
        struct.pack_into("<I", archive, first_len - 8, 0xDEADBEEF)
        status, headers, data = self.post_reindex(
            {"archive": ("a.bgz", bytes(archive))}
        )
        self.assertEqual(status, 422)
        self.assertEqual(headers["content-type"], "application/json")
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], "CRC32_MISMATCH")
        self.assertEqual(body["error"]["offset"], first_len - 8)
        # No index framing may leak into a JSON error body.
        self.assertNotIn("x-bgzf-block-count", headers)

    def test_garbage_archive_rejected_with_stable_offset(self):
        status, headers, data = self.post_reindex(
            {"archive": ("a.bgz", b"garbage")}
        )
        self.assertEqual(status, 422)
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], "BAD_MAGIC")
        self.assertEqual(body["error"]["offset"], 0)
        self.assertNotIn("x-bgzf-block-count", headers)

    def test_missing_archive_part(self):
        status, _headers, data = self.post_reindex(
            {"other": ("a.gzi", struct.pack("<Q", 0))}
        )
        self.assertEqual(status, 422)
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], "MISSING_PART")

    def test_wrong_content_type(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/api/bgzf/reindex",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        body = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 415)
        self.assertEqual(body["error"]["code"], "UNSUPPORTED_MEDIA_TYPE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
