#!/bin/sh

docker run --rm -v $(pwd):/host -w /host alpine:3.24.1 sh -c "apk add --no-cache gcc make musl-dev && make build"
cp ./battlebots ../../services/battlebots/battlebots
