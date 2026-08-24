#!/bin/sh
# Build the service binaries for Alpine/musl inside a throwaway Alpine
# container, then drop them next to the runtime Dockerfile.
#
# Two binaries come out of `make`: db_server + svm. Both are x86-64 (the JIT
# emits & executes x86-64). Run from anywhere; paths are relative to this script.
set -e
cd "$(dirname "$0")"
docker run --rm -v "$(pwd):/host" -w /host alpine:3.24.1 \
    sh -c "apk add --no-cache gcc make musl-dev linux-headers && make"
cp ./svm ./db_server ../../services/possibly_maybe/
echo "binaries updated: services/possibly_maybe/{svm,db_server}"
