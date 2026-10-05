"""End-to-end HTTP tests against a real server socket."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.bgzf import EOF_MEMBER  # noqa: E402
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

    def post_reindex(self, fields=None, raw_body=None, content_type=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        if raw_body is not None:
            conn.request("POST", "/api/bgzf/reindex", body=raw_body, headers={"Content-Type": content_type})
        else:
            body, ct = encode_multipart(fields or {})
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
        return resp.status, data, headers

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
    def test_single_block_returns_zero_count_index(self):
        archive = build_archive([b"only"])
        status, data, headers = self.post_reindex({"archive": ("a.bgz", archive)})
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/octet-stream")
        self.assertEqual(int(headers["content-length"]), 8)
        self.assertEqual(data, struct.pack("<Q", 0))
        self.assertEqual(int(headers["x-bgzf-data-blocks"]), 1)
        self.assertEqual(int(headers["x-bgzf-uncompressed-length"]), 4)
        # Digest matches the decompressed payload and is echoed as a header.
        expected_sha = hashlib.sha256(b"only").hexdigest()
        self.assertEqual(headers["x-bgzf-sha256"], expected_sha)

    def test_rebuilds_index_and_metadata_headers(self):
        payloads = [b"block-zero", b"block-one", b"block-two"]
        archive = build_archive(payloads)
        status, data, headers = self.post_reindex({"archive": ("a.bgz", archive)})
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/octet-stream")
        self.assertEqual(data, build_index(archive, payloads))
        self.assertEqual(int(headers["x-bgzf-data-blocks"]), 3)
        self.assertEqual(int(headers["x-bgzf-uncompressed-length"]), sum(map(len, payloads)))
        expected_sha = hashlib.sha256(b"".join(payloads)).hexdigest()
        self.assertEqual(headers["x-bgzf-sha256"], expected_sha)
        self.assertEqual(int(headers["content-length"]), len(data))

    def test_audit_accepts_rebuilt_index_round_trip(self):
        # Reindex, then send the rebuilt index back through /audit.
        payloads = [b"round", b"trip"]
        archive = build_archive(payloads)
        _status, rebuilt, _headers = self.post_reindex({"archive": ("a.bgz", archive)})
        status, body = self.post_audit(
            {"archive": ("a.bgz", archive), "index": ("a.gzi", rebuilt)}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data_blocks"], 2)

    def test_corrupt_archive_returns_422_no_index_body(self):
        payloads = [b"aaaa", b"bbbb"]
        archive = bytearray(build_archive(payloads))
        block0_len = len(bgzf_block(b"aaaa"))
        struct.pack_into("<I", archive, block0_len - 8, 0x0BADF00D)
        status, data, headers = self.post_reindex({"archive": ("a.bgz", bytes(archive))})
        self.assertEqual(status, 422)
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], "CRC32_MISMATCH")
        self.assertEqual(body["error"]["offset"], block0_len - 8)
        # A rejected rebuild must not smuggle any index bytes: the error
        # is JSON, and its shape is the stable one.
        self.assertNotIn("application/octet-stream", headers.get("content-type", ""))
        self.assertEqual(set(body["error"].keys()), {"code", "message", "offset"})

    def test_bad_magic_archive_rejected(self):
        status, data, _headers = self.post_reindex(
            {"archive": ("a.bgz", b"garbage")}
        )
        self.assertEqual(status, 422)
        body = json.loads(data)
        self.assertEqual(body["error"]["code"], "BAD_MAGIC")
        self.assertEqual(body["error"]["offset"], 0)

    def test_missing_eof_rejected(self):
        archive = build_archive([b"aaaa"])[: -len(EOF_MEMBER)]
        status, data, _headers = self.post_reindex({"archive": ("a.bgz", archive)})
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "MISSING_EOF_MEMBER")

    def test_missing_part(self):
        status, data, _headers = self.post_reindex(
            fields={},
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(data)["error"]["code"], "MISSING_PART")

    def test_wrong_content_type(self):
        status, data, _headers = self.post_reindex(
            raw_body=b"{}", content_type="application/json"
        )
        self.assertEqual(status, 415)
        self.assertEqual(json.loads(data)["error"]["code"], "UNSUPPORTED_MEDIA_TYPE")

    def test_unknown_post_path_404(self):
        body, ct = encode_multipart({"archive": ("a.bgz", build_archive([b"x"]))})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/bgzf/nope", body=body, headers={"Content-Type": ct})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
