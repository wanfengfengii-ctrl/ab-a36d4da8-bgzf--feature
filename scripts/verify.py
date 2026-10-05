#!/usr/bin/env python3
"""One-off verification job run by the ``verify`` Compose service.

It waits for the application health endpoint, then:

1. runs a build check (byte-compilation of every module);
2. runs the unittest suite (code + HTTP-level tests);
3. submits four smoke samples to ``POST /api/bgzf/audit``:
   a valid archive, a CRC32-corrupted member, a declared block-size
   drift, and an index offset mismatch.

Exits 0 only when every stage passes; exits 1 with a readable report
otherwise, so Compose marks the one-off service as failed.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.bgzf_fixtures import bgzf_block, build_archive, build_index, encode_multipart  # noqa: E402

APP_URL = os.environ.get("APP_URL", "http://app:8080").rstrip("/")


def wait_for_healthy(timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{APP_URL}/healthz", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            last_error = exc
        time.sleep(1)
    print(f"[verify] service did not become healthy: {last_error}", file=sys.stderr)
    return False


def run_build_check() -> bool:
    print("[verify] build check: compileall ...", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", "app", "tests", "scripts"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stdout + proc.stderr, file=sys.stderr)
    return proc.returncode == 0


def run_unit_tests() -> bool:
    print("[verify] running test suite ...", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        capture_output=True,
        text=True,
    )
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
    return proc.returncode == 0


def post_audit(archive: bytes, index: bytes) -> tuple[int, dict]:
    body, content_type = encode_multipart(
        {"archive": ("sample.bgz", archive), "index": ("sample.gzi", index)}
    )
    req = urllib.request.Request(
        f"{APP_URL}/api/bgzf/audit",
        data=body,
        headers={"Content-Type": content_type, "Content-Length": str(len(body))},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


SMOKES: list[tuple[str, Callable[[], str]]] = []


def smoke(name: str):
    def register(fn):
        SMOKES.append((name, fn))
        return fn

    return register


@smoke("valid archive")
def smoke_valid():
    payloads = [b"alpha-block", b"beta-block!", b"gamma-block?"]
    archive = build_archive(payloads)
    index = build_index(archive, payloads)
    status, body = post_audit(archive, index)
    assert status == 200, f"expected 200, got {status}: {body}"
    assert body["data_blocks"] == 3
    assert body["uncompressed_length"] == sum(map(len, payloads))
    assert len(body["sha256"]) == 64
    return f"{body['data_blocks']} blocks, {body['uncompressed_length']} bytes, sha256={body['sha256'][:12]}..."


@smoke("CRC32 corruption")
def smoke_crc():
    payloads = [b"crc-me", b"untouched"]
    archive = bytearray(build_archive(payloads))
    first_len = len(bgzf_block(payloads[0]))
    struct.pack_into("<I", archive, first_len - 8, 0xDEADBEEF)
    index = build_index(bytes(archive), payloads)
    status, body = post_audit(bytes(archive), index)
    assert status == 422, f"expected 422, got {status}: {body}"
    assert body["error"]["code"] == "CRC32_MISMATCH"
    assert body["error"]["offset"] == first_len - 8
    return f"422 {body['error']['code']} at offset {body['error']['offset']}"


@smoke("declared block-size drift")
def smoke_block_size():
    payloads = [b"size-me", b"untouched"]
    archive = bytearray(build_archive(payloads))
    declared = struct.unpack_from("<H", archive, 16)[0]
    struct.pack_into("<H", archive, 16, declared - 1)
    index = build_index(bytes(archive), payloads)
    status, body = post_audit(bytes(archive), index)
    assert status == 422, f"expected 422, got {status}: {body}"
    assert body["error"]["offset"] is not None
    assert body["error"]["code"] in {
        "DEFLATE_NOT_TERMINATED",
        "BAD_BLOCK_SIZE",
        "CRC32_MISMATCH",
    }
    return f"422 {body['error']['code']} at offset {body['error']['offset']}"


@smoke("index offset mismatch")
def smoke_index_drift():
    payloads = [b"index-zero", b"index-one"]
    archive = build_archive(payloads)
    index = bytearray(build_index(archive, payloads))
    struct.pack_into("<Q", index, 8, 0)  # compressed start of block 1
    status, body = post_audit(archive, bytes(index))
    assert status == 422, f"expected 422, got {status}: {body}"
    assert body["error"]["code"] == "INDEX_COMPRESSED_OFFSET_MISMATCH"
    assert body["error"]["offset"] == len(bgzf_block(payloads[0]))
    return f"422 {body['error']['code']} at offset {body['error']['offset']}"


def run_smokes() -> bool:
    print("[verify] submitting smoke samples ...", flush=True)
    ok = True
    for name, fn in SMOKES:
        try:
            detail = fn()
        except AssertionError as exc:
            ok = False
            print(f"  FAIL {name}: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - report any transport error
            ok = False
            print(f"  ERROR {name}: {exc!r}", file=sys.stderr)
        else:
            print(f"  ok   {name}: {detail}")
    return ok


def main() -> int:
    stages = [
        wait_for_healthy(),
        run_build_check(),
        run_unit_tests(),
        run_smokes(),
    ]
    if all(stages):
        print("[verify] ALL CHECKS PASSED", flush=True)
        return 0
    print("[verify] VERIFICATION FAILED", file=sys.stderr, flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
