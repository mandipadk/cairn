#!/usr/bin/env python3
"""Put one file into an S3-compatible bucket with nothing but the standard
library and curl, so a backup can leave the machine without installing a
client. Signature Version 4, path-style addressing; works against
Cloudflare R2 (region "auto"), MinIO, and S3 itself.

    S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com \
    S3_BUCKET=ambolt-backups S3_ACCESS_KEY_ID=... S3_SECRET_ACCESS_KEY=... \
    scripts/upload-s3.py backups/ambolt-20260907-031500.tar.gz [key]

The key defaults to the file's name. Retention is the bucket's business:
give it a lifecycle rule rather than teaching this script to delete.
"""
import datetime
import hashlib
import hmac
import os
import subprocess
import sys
import urllib.parse


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    path = sys.argv[1]
    key = sys.argv[2] if len(sys.argv) == 3 else os.path.basename(path)
    try:
        endpoint = os.environ["S3_ENDPOINT"].rstrip("/")
        bucket = os.environ["S3_BUCKET"]
        access = os.environ["S3_ACCESS_KEY_ID"]
        secret = os.environ["S3_SECRET_ACCESS_KEY"]
    except KeyError as missing:
        sys.exit(f"set {missing.args[0]}")
    region = os.environ.get("S3_REGION", "auto")

    host = urllib.parse.urlparse(endpoint).netloc
    canonical_uri = "/" + urllib.parse.quote(bucket, safe="") + "/" + urllib.parse.quote(key, safe="/")
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    payload_hash = sha256_file(path)

    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join(["PUT", canonical_uri, "", canonical_headers, signed_headers, payload_hash])
    scope = f"{day}/{region}/s3/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    signing_key = sign(sign(sign(sign(("AWS4" + secret).encode(), day), region), "s3"), "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    result = subprocess.run(
        [
            "curl", "-sS", "-f", "-o", "/dev/null", "-w", "%{http_code}",
            "-X", "PUT", "--data-binary", "@" + path,
            "-H", f"Host: {host}",
            "-H", f"x-amz-date: {amz_date}",
            "-H", f"x-amz-content-sha256: {payload_hash}",
            "-H", f"Authorization: {authorization}",
            endpoint + canonical_uri,
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.exit(f"upload failed: {result.stderr.strip() or result.stdout.strip()}")
    print(f"uploaded {os.path.basename(path)} to {bucket}/{key} ({result.stdout.strip()})")


if __name__ == "__main__":
    main()
