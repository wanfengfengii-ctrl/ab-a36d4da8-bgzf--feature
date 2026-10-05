"""HTTP frontend for the BGZF archive audit service.

Exposes:

* ``POST /api/bgzf/audit``   -- multipart/form-data with ``archive`` and
  ``index`` file parts.
* ``POST /api/bgzf/reindex`` -- multipart/form-data with a single
  ``archive`` part; returns a rebuilt little-endian index body.
* ``GET  /healthz``          -- liveness probe for the container health
  check.

Only the Python standard library is required.
"""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .bgzf import MAX_ARCHIVE_SIZE, AuditError, audit, reindex

# The index for 4096 blocks is ~64 KiB; allow generous multipart framing
# overhead on top of the 8 MiB archive limit.
MAX_REQUEST_SIZE = MAX_ARCHIVE_SIZE + 256 * 1024

AUDIT_PATH = "/api/bgzf/audit"
REINDEX_PATH = "/api/bgzf/reindex"


class MultipartError(Exception):
    """The multipart/form-data request body itself is malformed."""


def parse_multipart(body: bytes, content_type: str) -> dict[str, bytes]:
    """Extract form parts keyed by their form-field name.

    Only the parts this API needs (``archive`` and ``index``) are kept.
    Raises :class:`MultipartError` on structural problems.
    """
    boundary: bytes | None = None
    for param in content_type.split(";")[1:]:
        param = param.strip()
        if param.startswith("boundary="):
            value = param[len("boundary=") :]
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            boundary = value.encode("latin-1")
    if boundary is None or not boundary:
        raise MultipartError("missing multipart boundary")
    delimiter = b"--" + boundary

    parts: dict[str, bytes] = {}
    pos = body.find(delimiter)
    if pos != 0:
        raise MultipartError("body does not start with the multipart boundary")
    pos += len(delimiter)

    while True:
        if body[pos : pos + 2] == b"--":
            # Closing delimiter: nothing but transport padding may follow.
            tail = body[pos + 2 :]
            if tail and tail != b"\r\n":
                raise MultipartError("unexpected bytes after closing boundary")
            break
        if body[pos : pos + 2] != b"\r\n":
            raise MultipartError("malformed boundary line")
        pos += 2

        header_end = body.find(b"\r\n\r\n", pos)
        if header_end == -1:
            raise MultipartError("part header is not terminated")
        header_block = body[pos:header_end]
        content_start = header_end + 4

        next_delim = body.find(b"\r\n" + delimiter, content_start)
        if next_delim == -1:
            raise MultipartError("part body is not terminated by a boundary")

        name: str | None = None
        filename: str | None = None
        for line in header_block.split(b"\r\n"):
            if line.lower().startswith(b"content-disposition:"):
                for token in line.decode("latin-1").split(";")[1:]:
                    token = token.strip()
                    if token.startswith("name="):
                        name = token[5:].strip('"')
                    elif token.startswith("filename="):
                        filename = token[9:].strip('"')

        if name is not None:
            parts[name] = body[content_start:next_delim]
            parts[f"{name}__filename"] = filename.encode("utf-8") if filename else b""

        pos = next_delim + 2 + len(delimiter)

    return parts


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "BgzfAudit/1.0"

    def _write_json(self, status: int, payload: dict) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - http.server hook
        if self.path.split("?", 1)[0] == "/healthz":
            self._write_json(HTTPStatus.OK, {"status": "ok"})
        else:
            self._write_json(
                HTTPStatus.NOT_FOUND,
                {"error": {"code": "NOT_FOUND", "message": "unknown path", "offset": None}},
            )

    def do_POST(self) -> None:  # noqa: N802 - http.server hook
        path = self.path.split("?", 1)[0]
        if path == AUDIT_PATH:
            self._handle_audit()
        elif path == REINDEX_PATH:
            self._handle_reindex()
        else:
            self._write_json(
                HTTPStatus.NOT_FOUND,
                {"error": {"code": "NOT_FOUND", "message": "unknown path", "offset": None}},
            )

    def _read_parts(self, required: tuple[str, ...]) -> dict[str, bytes] | None:
        """Read and parse a multipart request body, or send an error.

        Returns the parsed parts, or ``None`` after writing the error
        response when the transport or multipart framing is invalid or a
        required part is missing.
        """
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            self._write_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {
                    "error": {
                        "code": "UNSUPPORTED_MEDIA_TYPE",
                        "message": "expected multipart/form-data",
                        "offset": None,
                    }
                },
            )
            return None

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0:
            self._write_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"error": {"code": "BAD_CONTENT_LENGTH", "message": "invalid Content-Length", "offset": None}},
            )
            return None
        if length > MAX_REQUEST_SIZE:
            # Drain a modestly oversized body so the uploader still reads
            # the 413 cleanly; refuse to tie up a thread draining a body
            # that claims to be far larger.
            if length <= 2 * MAX_REQUEST_SIZE:
                self._drain_best_effort(length)
            self._write_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "error": {
                        "code": "REQUEST_TOO_LARGE",
                        "message": f"request exceeds {MAX_REQUEST_SIZE} bytes",
                        "offset": None,
                    }
                },
            )
            return None

        body = self._read_exactly(length)
        if body is None:
            self._write_json(
                HTTPStatus.BAD_REQUEST,
                {"error": {"code": "TRUNCATED_REQUEST", "message": "request body shorter than Content-Length", "offset": None}},
            )
            return None

        try:
            parts = parse_multipart(body, content_type)
        except MultipartError as exc:
            self._write_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"error": {"code": "MALFORMED_MULTIPART", "message": str(exc), "offset": None}},
            )
            return None

        missing = [name for name in required if name not in parts]
        if missing:
            self._write_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {
                    "error": {
                        "code": "MISSING_PART",
                        "message": f"missing multipart part: {', '.join(missing)}",
                        "offset": None,
                    }
                },
            )
            return None
        return parts

    def _write_audit_error(self, exc: AuditError) -> None:
        # Size is a transport-level rejection; everything else is a
        # semantic 422 with a stable, locatable error code.
        status = (
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            if exc.code == "ARCHIVE_TOO_LARGE"
            else HTTPStatus.UNPROCESSABLE_ENTITY
        )
        self._write_json(
            status,
            {
                "error": {
                    "code": exc.code,
                    "message": str(exc),
                    "offset": exc.offset,
                }
            },
        )

    def _handle_audit(self) -> None:
        parts = self._read_parts(("archive", "index"))
        if parts is None:
            return

        try:
            result = audit(parts["archive"], parts["index"])
        except AuditError as exc:
            self._write_audit_error(exc)
            return

        self._write_json(
            HTTPStatus.OK,
            {
                "data_blocks": result.data_blocks,
                "uncompressed_length": result.uncompressed_length,
                "sha256": result.sha256,
            },
        )

    def _handle_reindex(self) -> None:
        parts = self._read_parts(("archive",))
        if parts is None:
            return

        # reindex verifies every member, EOF, Deflate stream, CRC32 and
        # ISIZE before it returns a single index byte, so a failure here
        # carries the same stable code / offset as the audit endpoint and
        # is never accompanied by a partial index body.
        try:
            index, result = reindex(parts["archive"])
        except AuditError as exc:
            self._write_audit_error(exc)
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(index)))
        self.send_header("X-BGZF-Data-Blocks", str(result.data_blocks))
        self.send_header("X-BGZF-Uncompressed-Length", str(result.uncompressed_length))
        self.send_header("X-BGZF-SHA256", result.sha256)
        self.end_headers()
        self.wfile.write(index)

    def _drain_best_effort(self, length: int) -> None:
        """Discard up to ``length`` request bytes without storing them."""
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 64 * 1024))
            if not chunk:
                return
            remaining -= len(chunk)

    def _read_exactly(self, length: int) -> bytes | None:
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 64 * 1024))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def log_message(self, fmt: str, *args) -> None:  # noqa: A002
        # Keep container logs focused on audit outcomes; errors still surface.
        if os.environ.get("BGZF_AUDIT_LOG") == "1":
            super().log_message(fmt, *args)


def create_server(host: str = "0.0.0.0", port: int | None = None) -> ThreadingHTTPServer:
    if port is None:
        port = int(os.environ.get("PORT", "8080"))
    return ThreadingHTTPServer((host, port), AuditHandler)


def main() -> None:
    server = create_server()
    host, port = server.server_address[:2]
    print(f"bgzf-audit listening on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
