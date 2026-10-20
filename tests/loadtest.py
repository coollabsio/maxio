#!/usr/bin/env python3
"""Reproducible MaxIO load test.

Starts a local server (unless MAXIO_LOAD_URL is set), then measures:

- many small PUTs and GETs
- one multipart upload
- concurrent mixed reads and writes
- listing the bucket those objects landed in

Prints throughput, latency percentiles, and the server's peak RSS.

    SKIP_FRONTEND=1 cargo build
    python3 tests/loadtest.py

Environment:
    MAXIO_BIN                 binary to launch (default ./target/debug/maxio)
    MAXIO_LOAD_URL            use an already running server
    MAXIO_LOAD_SMALL          small-object count (default 200)
    MAXIO_LOAD_CONCURRENCY    worker threads (default 16)
    MAXIO_LOAD_MULTIPART_MB   multipart object size in MiB (default 32)
    MAXIO_LOAD_PART_MB        multipart part size in MiB (default 8)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

ACCESS_KEY = "maxioadmin"
SECRET_KEY = "maxioadmin"
REGION = "us-east-1"
SMALL = int(os.environ.get("MAXIO_LOAD_SMALL", "200"))
CONCURRENCY = int(os.environ.get("MAXIO_LOAD_CONCURRENCY", "16"))
MULTIPART_MB = int(os.environ.get("MAXIO_LOAD_MULTIPART_MB", "32"))
PART_MB = int(os.environ.get("MAXIO_LOAD_PART_MB", "8"))
BUCKET = "loadtest"


def sign(method: str, url: str, headers: dict[str, str], body: bytes) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    parsed = urllib.parse.urlsplit(url)
    signed = {k.lower(): v.strip() for k, v in headers.items()}
    signed["host"] = parsed.netloc
    signed["x-amz-date"] = amz_date
    signed["x-amz-content-sha256"] = payload_hash
    canonical_headers = "".join(f"{k}:{signed[k]}\n" for k in sorted(signed))
    signed_headers = ";".join(sorted(signed))
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    canonical_query = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in sorted(query)
    )
    canonical_uri = urllib.parse.quote(parsed.path, safe="/%")
    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    scope = f"{datestamp}/{REGION}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )

    def mac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing = mac(mac(mac(mac(("AWS4" + SECRET_KEY).encode(), datestamp), REGION), "s3"), "aws4_request")
    signature = hmac.new(signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    signed["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return signed


def request(method: str, url: str, body: bytes = b"", extra: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes, float]:
    headers = sign(method, url, extra or {}, body)
    req = urllib.request.Request(url, data=body if method != "GET" else None, method=method)
    for key, value in headers.items():
        req.add_header(key, value)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = resp.read()
            elapsed = time.perf_counter() - started
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, payload, elapsed
    except urllib.error.HTTPError as err:
        payload = err.read()
        elapsed = time.perf_counter() - started
        return err.code, {k.lower(): v for k, v in err.headers.items()}, payload, elapsed


def percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return ordered[index]


def fmt_ms(samples: list[float]) -> str:
    return (
        f"p50={percentile(samples, 50) * 1000:.1f}ms "
        f"p95={percentile(samples, 95) * 1000:.1f}ms "
        f"p99={percentile(samples, 99) * 1000:.1f}ms"
    )


class RssSampler:
    def __init__(self, pid: int):
        self.pid = pid
        self.peak_kb = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> int:
        self._stop.set()
        self._thread.join(timeout=2)
        return self.peak_kb

    def _run(self) -> None:
        path = f"/proc/{self.pid}/status"
        while not self._stop.is_set():
            try:
                with open(path, encoding="utf-8") as handle:
                    for line in handle:
                        if line.startswith("VmRSS:"):
                            kb = int(line.split()[1])
                            self.peak_kb = max(self.peak_kb, kb)
                            break
            except OSError:
                return
            self._stop.wait(0.2)


def run_pool(work) -> list[float]:
    samples: list[float] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        for status, elapsed in pool.map(work, range(SMALL)):
            if status != 200:
                errors.append(str(status))
            samples.append(elapsed)
    if errors:
        raise SystemExit(f"load test saw non-200 responses: {errors[:5]}")
    return samples


def main() -> None:
    base = os.environ.get("MAXIO_LOAD_URL", "").rstrip("/")
    proc = None
    data_dir = None
    rss = None
    binary = os.environ.get("MAXIO_BIN", "./target/debug/maxio")
    if not base:
        data_dir = tempfile.mkdtemp(prefix="maxio-load-")
        proc = subprocess.Popen(
            [
                binary,
                "--data-dir",
                data_dir,
                "--address",
                "127.0.0.1",
                "--port",
                "0",
                "--allow-insecure-dev",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert proc.stdout is not None
        deadline = time.time() + 20
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                raise SystemExit("server exited before printing its listen address")
            if "listening on" in line:
                port = line.rsplit(":", 1)[-1].strip()
                base = f"http://127.0.0.1:{port}"
                break
        else:
            raise SystemExit("timed out waiting for the server")
        rss = RssSampler(proc.pid)
        rss.start()

    try:
        status, _, body, _ = request("PUT", f"{base}/{BUCKET}")
        if status not in (200, 409):
            raise SystemExit(f"create bucket failed: {status} {body[:200]!r}")

        payload = b"x" * 4096

        def put_small(i: int):
            status, _, _, elapsed = request("PUT", f"{base}/{BUCKET}/small/{i}", payload)
            return status, elapsed

        def get_small(i: int):
            status, _, data, elapsed = request("GET", f"{base}/{BUCKET}/small/{i}")
            if status == 200 and data != payload:
                status = 500
            return status, elapsed

        started = time.perf_counter()
        put_samples = run_pool(put_small)
        put_secs = time.perf_counter() - started
        started = time.perf_counter()
        get_samples = run_pool(get_small)
        get_secs = time.perf_counter() - started

        total = MULTIPART_MB * 1024 * 1024
        part_size = PART_MB * 1024 * 1024
        status, _, body, _ = request("POST", f"{base}/{BUCKET}/multi.bin?uploads")
        if status != 200:
            raise SystemExit(f"create multipart failed: {status} {body[:300]!r}")
        root = ET.fromstring(body)
        upload_id = root.findtext("UploadId")
        if not upload_id:
            raise SystemExit(f"no upload id in {body[:300]!r}")
        etags: list[str] = []
        mp_started = time.perf_counter()
        offset = 0
        number = 1
        while offset < total:
            chunk = b"m" * min(part_size, total - offset)
            status, headers, resp_body, _ = request(
                "PUT",
                f"{base}/{BUCKET}/multi.bin?partNumber={number}&uploadId={urllib.parse.quote(upload_id, safe='')}",
                chunk,
            )
            if status != 200:
                raise SystemExit(f"upload part {number} failed: {status} {resp_body[:200]!r}")
            etag = headers.get("etag", "")
            etags.append(etag if etag.startswith('"') else f'"{etag}"')
            offset += len(chunk)
            number += 1
        parts = len(etags)
        complete = "<CompleteMultipartUpload>" + "".join(
            f"<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
            for n, etag in enumerate(etags, start=1)
        ) + "</CompleteMultipartUpload>"
        status, _, body, _ = request(
            "POST",
            f"{base}/{BUCKET}/multi.bin?uploadId={urllib.parse.quote(upload_id, safe='')}",
            complete.encode(),
            {"content-type": "application/xml"},
        )
        mp_secs = time.perf_counter() - mp_started
        if status != 200:
            raise SystemExit(f"complete multipart failed: {status} {body[:300]!r}")
        mp_bytes = total

        def mixed(i: int):
            if i % 2 == 0:
                return put_small(i)
            return get_small(i % max(SMALL, 1))

        started = time.perf_counter()
        mixed_samples = run_pool(mixed)
        mixed_secs = time.perf_counter() - started

        listed = 0
        token = None
        list_started = time.perf_counter()
        while True:
            list_url = f"{base}/{BUCKET}?list-type=2&max-keys=1000"
            if token:
                list_url += "&continuation-token=" + urllib.parse.quote(token, safe="")
            status, _, body, _ = request("GET", list_url)
            if status != 200:
                raise SystemExit(f"list failed: {status} {body[:200]!r}")
            listed += body.count(b"<Key>")
            root = ET.fromstring(body)
            if (root.findtext("IsTruncated") or "").lower() != "true":
                break
            token = root.findtext("NextContinuationToken")
            if not token:
                break
        list_elapsed = time.perf_counter() - list_started

        print(f"small PUT  n={SMALL} concurrency={CONCURRENCY} {SMALL / put_secs:.1f} obj/s  {fmt_ms(put_samples)}")
        print(f"small GET  n={SMALL} concurrency={CONCURRENCY} {SMALL / get_secs:.1f} obj/s  {fmt_ms(get_samples)}")
        print(
            f"multipart  {MULTIPART_MB}MiB in {parts} part(s)  "
            f"{mp_bytes / mp_secs / (1024 * 1024):.1f} MiB/s  {mp_secs * 1000:.0f}ms"
        )
        print(
            f"mixed      n={SMALL} concurrency={CONCURRENCY} "
            f"{SMALL / mixed_secs:.1f} op/s  {fmt_ms(mixed_samples)}"
        )
        print(f"list       {listed} keys in {list_elapsed * 1000:.1f}ms")
        if rss is not None:
            peak = rss.stop()
            print(f"memory     peak RSS {peak / 1024:.1f} MiB")
        else:
            print("memory     skipped (external server)")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        if data_dir is not None:
            subprocess.run(["rm", "-rf", data_dir], check=False)


if __name__ == "__main__":
    main()
