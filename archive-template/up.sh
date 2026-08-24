#!/bin/sh
set -eu

cd "$(dirname "$0")"

docker load -i images.tar

for d in */; do
    [ -f "$d/docker-compose.yml" ] || continue
    echo ">>> ${d%/}"
    ( cd "$d" && docker compose up -d --build )
done
