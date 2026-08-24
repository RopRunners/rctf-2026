#!/bin/sh
# Rebuild svm_ref, the trusted reference the checker runs locally (SVM_LOCAL_DB).
#
# Two things this has to get right, and the old version got both wrong.
#
# LIBC. svm_ref runs inside the ForcAD celery worker, which is built FROM
# python:3.12 - Debian, glibc. The same source also builds the binary that ships
# inside the service, which runs on Alpine and must be musl. Build svm_ref on
# Alpine and it comes out musl-linked; the celery container then has no
# /lib/ld-musl-x86_64.so.1, the kernel returns ENOENT on exec, and Python
# reports `FileNotFoundError: '/checkers/possibly_maybe/svm_ref'` for a file
# that is plainly there, 0755, in the container. Every team, every round, scored
# as MUMBLE "checker error". So the build happens inside the checker's own base
# image rather than on whatever the operator happens to run.
#
# SCOPE. This writes svm_ref and nothing else. The old version ran
# `make -C internal/possibly_maybe svm`, which overwrites
# internal/possibly_maybe/svm - a *tracked* file, and the service's binary,
# which is supposed to be musl. Fixing the checker would have quietly broken the
# service. The source is mounted read-only here so that cannot happen again.
set -e

here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../../internal/possibly_maybe" && pwd)

# Must match the celery image's base (rctf-forcad/docker_config/celery/Dockerfile).
image=${REF_IMAGE:-python:3.12}

command -v docker >/dev/null || {
    echo "docker is required: svm_ref must be built against the same libc as the" >&2
    echo "celery worker, not against this machine's." >&2
    exit 1
}

echo "building svm_ref in $image (source mounted read-only)"
docker run --rm \
    -v "$src:/src:ro" \
    -v "$here:/out" \
    -e OUT_UID="$(id -u)" \
    -e OUT_GID="$(id -g)" \
    "$image" sh -ec '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends build-essential >/dev/null
        # Copied out of the read-only mount: make writes its objects beside the
        # sources, and those sources are what the service is built from.
        cp -a /src /build
        # `make clean` first, and it is load-bearing. The tree ships a prebuilt
        # svm - the musl one, for the service - and cp -a preserves timestamps,
        # so make finds a target newer than its sources, prints "svm is up to
        # date", builds nothing, and this copies the musl binary back out as if
        # it had been rebuilt.
        make -C /build clean
        make -C /build svm
        cp /build/svm /out/svm_ref
        chmod 0755 /out/svm_ref
        chown "$OUT_UID:$OUT_GID" /out/svm_ref
    '

# The failure this exists to prevent is silent at build time and only shows up
# as every team scoring MUMBLE, so it is worth asserting rather than assuming.
if grep -aq 'ld-musl' "$here/svm_ref"; then
    echo "svm_ref is still musl-linked - it will not run in the celery worker" >&2
    exit 1
fi
# No interpreter string at all means a static binary, which is fine and in fact
# the more robust thing to ship - it stops caring what libc the celery image
# has. Only musl is a failure; absence of a glibc marker is not.
if grep -aq 'ld-linux-x86-64' "$here/svm_ref"; then
    echo "linked against glibc, dynamic"
else
    echo "no interpreter - statically linked"
fi

echo "reference updated: $here/svm_ref"
echo "ship it with:  ./upload-checkers.sh possibly_maybe"
