#!/usr/bin/env bash
set -euo pipefail

IMG="corrupt:latest"
OCI_DIR="./oci"

rm -rf "$OCI_DIR"
docker build -t "$IMG" ./image
skopeo copy --format oci "docker-daemon:$IMG" "oci:$OCI_DIR:latest"
