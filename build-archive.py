#!/usr/bin/env python3
"""Build the encrypted services archive teams download.

    ./build-archive.py                      # every service
    ./build-archive.py pipeline xingyuan    # a subset
    ./build-archive.py --format 7z          # .7z instead of GnuPG
    ./build-archive.py --no-encrypt         # leave the tarball in the open, for testing

What comes out is one file - services.tar.gz.gpg or services.7z - plus its
SHA-256. Upload it through the rctf-back admin panel (RUNBOOK 5), verify you can
open it, then make it available.

WHY NOT A PLAIN ENCRYPTED .ZIP

It was considered and it is the wrong container here, for three reasons that
compound.

`zip -e`, which is what "password-protect a zip" normally means, is ZipCrypto -
the 1990 PKWARE cipher, broken by a known-plaintext attack. This archive is
almost entirely known plaintext: `docker save` writes predictable tar headers
and the compose files are on GitHub.

The strong alternative, WinZip AES-256, is real AES-256-CTR with HMAC-SHA1, but
its KDF is PBKDF2-HMAC-SHA1 at **1000 iterations** - against GnuPG's S2K count
of 65011712 here. That gap only stops mattering if the passphrase is random,
which is the argument for a random passphrase, not for the format.

And whichever of the two you pick, **a zip never encrypts its own metadata.**
The central directory is plaintext by design, so `unzip -l` on the encrypted
archive prints every path, size and timestamp without a password. For this event
that is each service's language, framework and file layout, days before the
embargo lifts. Info-ZIP's `unzip` also cannot read AES zips at all (method 99),
so an AES zip would require teams to install 7-Zip anyway - at which point .7z,
which *can* encrypt its headers with -mhe=on, is strictly better.

So: GnuPG by default, `--format 7z` if you want something teams can open with a
GUI. Both encrypt the file listing.

WHY THE IMAGES TRAVEL IN THE ARCHIVE

Every vulnbox egresses through one public address and Docker Hub allows 100
anonymous pulls per IP per 6 hours. Sixty teams running `docker compose up` at
T-0 is one address asking for several hundred pulls inside a minute; the ones
who lose that race get 429 and no service, which scores as DOWN through no fault
of theirs. So the images ship pre-pulled and the boxes never talk to a registry.

WHY THE COMPOSE FILES GET REWRITTEN

This is the part that is not obvious, and it is why a naive `docker save` bundle
does not work.

`docker save` does not preserve a digest reference. Pull nginx@sha256:b5a9…,
save it, load it on another machine, and you get an *untagged* image: RepoTags
and RepoDigests are both empty, because the registry manifest that the digest
names is not part of what `save` writes (moby#22011, docker/cli#5933). A compose
file that says `image: nginx@sha256:b5a9…` then finds nothing locally and goes
to the registry anyway - which is the exact stampede this archive exists to
avoid, except now it also looks like the bundle is working.

So each image is pulled here by its pinned digest, retagged to a local name
derived from its image ID, and the shipped copy of the compose file and the
Dockerfiles reference that tag instead. The pinning still does its job - it
pins what *this* script pulls - and images.lock records
`original-ref -> local-tag -> image-id` so the substitution is auditable and
up.sh can verify what it loaded.

The image ID is a content hash over the image config, which chains to the layer
hashes, so checking it after load is as strong as checking the digest would have
been. It is not the same number as the registry digest and never will be: that
one is a hash of the compressed manifest, which is not shipped.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent
SERVICES_PATH = BASE_DIR / "services"
TEMPLATE_PATH = BASE_DIR / "archive-template"
OUT_DIR = BASE_DIR / "dist"

# Stage aliases (`FROM x AS build`) and later `FROM build` are internal to the
# build, not images to fetch. Tracked per Dockerfile.
FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I | re.M)


def sh(*cmd, capture=False):
    r = subprocess.run(cmd, check=True, text=True,
                       stdout=subprocess.PIPE if capture else None)
    return (r.stdout or "").strip()


def service_names(only):
    names = sorted(p.name for p in SERVICES_PATH.iterdir() if p.is_dir())
    if not only:
        return names
    missing = set(only) - set(names)
    if missing:
        sys.exit(f"no such service: {', '.join(sorted(missing))}")
    return [n for n in names if n in only]


def refs_in_service(svc):
    """Every image this service needs from a registry, in file order.

    Two sources, and both matter: `image:` in the compose file, and `FROM` in
    every Dockerfile it builds. Miss the second and the base images are absent
    at `docker compose build` time, which is the same stampede one step later.
    """
    root = SERVICES_PATH / svc
    found = []

    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    for spec in (compose.get("services") or {}).values():
        if isinstance(spec, dict) and spec.get("image"):
            found.append((str(spec["image"]), root / "docker-compose.yml"))

    for dockerfile in sorted(root.rglob("Dockerfile*")):
        stages = set()
        for ref, alias in FROM_RE.findall(dockerfile.read_text()):
            if ref.lower() not in stages:
                found.append((ref, dockerfile))
            if alias:
                stages.add(alias.lower())
    return found


def local_tag(ref, image_id):
    """A deterministic local name. Content-derived, so rebuilding is stable.

    `rctf/<name>:<12 hex of the image id>`. The repository part is only there to
    keep the tag readable in `docker images`; the id is what identifies it.
    """
    name = ref.split("@", 1)[0].split(":", 1)[0].rsplit("/", 1)[-1]
    name = re.sub(r"[^a-z0-9._-]", "-", name.lower())
    return f"rctf/{name}:{image_id.removeprefix('sha256:')[:12]}"


def find_7z():
    for name in ("7zz", "7z", "7za"):
        if shutil.which(name):
            return name
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("services", nargs="*")
    ap.add_argument("--format", choices=("gpg", "7z"), default="gpg",
                    help="gpg: tar.gz encrypted with GnuPG AES-256 (default). "
                         "7z: a .7z with AES-256 and encrypted headers. "
                         "Plain .zip is deliberately not offered - see the note below")
    ap.add_argument("--platform", default="linux/amd64",
                    help="architecture to pull. The vulnboxes are linux/amd64; "
                         "change this only if that changes")
    ap.add_argument("--no-encrypt", action="store_true",
                    help="stop at the tarball; for testing only")
    ap.add_argument("--passphrase-file",
                    help="read the passphrase from this file instead of prompting. "
                         "Never pass it on the command line - argv is world-readable in ps(1)")
    args = ap.parse_args()

    # Checked before docker does any work: discovering that the encryption tool
    # is missing after pulling a couple of gigabytes is a slow way to learn it.
    sevenzip = None
    if not args.no_encrypt:
        if args.format == "gpg" and not shutil.which("gpg"):
            sys.exit("gpg is not installed")
        if args.format == "7z":
            sevenzip = find_7z()
            if not sevenzip:
                sys.exit("7z is not installed (apk add p7zip / apt install p7zip-full)")
            if args.passphrase_file:
                # 7z has no way to read a password from a file or stdin, so the
                # only non-interactive form is -p<pass> on the command line -
                # where every other user on the box can read it out of ps(1).
                # Prompting is the one safe option, so that is the only one.
                sys.exit("--passphrase-file cannot be used with --format 7z: 7z only "
                         "takes a password on argv, which leaks it to ps(1). "
                         "Run without it and 7z will prompt.")

    for tool in ("docker", "tar"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is not installed")

    names = service_names(args.services)
    print(f"services: {' '.join(names)}\n")

    # --- resolve and pull -------------------------------------------------
    #
    # One entry per distinct ref. dedcleaner is shared by three services, so
    # this is also what keeps it out of the bundle three times.
    resolved = {}
    unpinned = []
    for svc in names:
        for ref, where in refs_in_service(svc):
            if ref in resolved:
                continue
            if "@sha256:" not in ref:
                unpinned.append((ref, where.relative_to(BASE_DIR)))
            print(f"  pull {ref}")
            # --platform, always: the vulnboxes are linux/amd64, and without
            # this the organiser's own architecture decides what ships. Build
            # the archive on an arm64 laptop and every team gets arm64 images
            # that die with "exec format error" at T-0.
            sh("docker", "pull", "--quiet", "--platform", args.platform, ref)
            image_id = sh("docker", "image", "inspect", "--format", "{{.Id}}", ref,
                          capture=True)
            # The layer diffIDs, which are what up.sh verifies against.
            #
            # NOT the image ID: that is only stable across two daemons using the
            # same image store. The classic graphdriver store identifies an
            # image by its config digest, the containerd store (the default for
            # fresh installs since Engine v29) by its manifest/index digest, so
            # the same image legitimately reports two different IDs on the
            # workstation and on a vulnbox - and every image looks corrupt.
            # diffIDs come from the image config either way and are hashes of
            # the uncompressed layers, so they survive save/load and the switch.
            diff_ids = json.loads(sh(
                "docker", "image", "inspect",
                "--format", "{{json .RootFS.Layers}}", ref, capture=True))
            resolved[ref] = {"id": image_id, "diff_ids": diff_ids,
                             "tag": local_tag(ref, image_id)}
            sh("docker", "tag", ref, resolved[ref]["tag"])

    if unpinned:
        # Not fatal - it still builds - but the archive's contents then depend
        # on the day it was built, and two organisers get different bytes.
        print("\n  WARNING: not digest-pinned, so what shipped depends on when "
              "this ran:", file=sys.stderr)
        for ref, where in unpinned:
            print(f"    {ref}  ({where})", file=sys.stderr)
            print(f"      currently {resolved[ref]['id']}", file=sys.stderr)
        print(file=sys.stderr)

    staging = Path(tempfile.mkdtemp(prefix="rctf-archive-"))
    try:
        # --- copy and rewrite ---------------------------------------------
        for svc in names:
            dst = staging / svc
            shutil.copytree(SERVICES_PATH / svc, dst,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            for path in list(dst.rglob("docker-compose.yml")) + list(dst.rglob("Dockerfile*")):
                text = original = path.read_text()
                # Longest first: `nginx@sha256:x` contains `nginx`, and
                # replacing the short one first would corrupt the long one.
                for ref in sorted(resolved, key=len, reverse=True):
                    text = text.replace(ref, resolved[ref]["tag"])
                if text != original:
                    path.write_text(text)

        # --- save --------------------------------------------------------
        #
        # One call, not one per image: `docker save` writes each layer once
        # across everything it is given, and three of these services share a
        # base.
        images_tar = staging / "images.tar"
        print(f"\n  saving {len(resolved)} images")
        sh("docker", "save", "-o", str(images_tar), *(v["tag"] for v in resolved.values()))

        (staging / "images.lock").write_text(json.dumps(
            {ref: resolved[ref] for ref in sorted(resolved)}, indent=2) + "\n")

        # Required, not best-effort. These used to be copied only `if
        # src.exists()`, so renaming one in archive-template/ shipped an archive
        # without it and said nothing - teams would have got the services and no
        # instructions for them.
        for item in ("up.sh", "README"):
            src = TEMPLATE_PATH / item
            if not src.exists():
                sys.exit(f"{src} is missing - archive-template/ must hold up.sh and README")
            shutil.copy2(src, staging / item)
            os.chmod(staging / item, 0o755 if item.endswith(".sh") else 0o644)

        # --- pack --------------------------------------------------------
        OUT_DIR.mkdir(exist_ok=True)

        if args.format == "7z" and not args.no_encrypt:
            # One step: 7z compresses, encrypts and contains. -mhe=on encrypts
            # the headers, so the file listing needs the password too - which is
            # the whole reason this is .7z and not .zip. A zip's central
            # directory is never encrypted, so `unzip -l` on an encrypted zip
            # prints the entire tree, and here that is every service's language
            # and layout, days before the password drops.
            out = OUT_DIR / "services.7z"
            out.unlink(missing_ok=True)
            print("  compressing and encrypting (7z will prompt for the password)")
            subprocess.run([sevenzip, "a", "-t7z", "-m0=lzma2", "-mx=6",
                            "-mhe=on", "-p", str(out),
                            *(str(p) for p in sorted(staging.iterdir()))],
                           check=True)
        else:
            tarball = OUT_DIR / "services.tar.gz"
            print("  packing")
            # gzip, not zstd: the vulnboxes are Alpine, where tar is busybox and
            # busybox tar has no --zstd. gzip is the format both ends already have.
            with tarfile.open(tarball, "w:gz") as tf:
                for entry in sorted(staging.iterdir()):
                    tf.add(entry, arcname=entry.name)
            out = tarball

        if args.format == "gpg" and not args.no_encrypt:
            out = OUT_DIR / "services.tar.gz.gpg"
            out.unlink(missing_ok=True)
            cmd = ["gpg", "--symmetric",
                   "--cipher-algo", "AES256",
                   "--s2k-mode", "3", "--s2k-digest-algo", "SHA512",
                   "--s2k-count", "65011712",
                   "--output", str(out)]
            if args.passphrase_file:
                # --batch only with a passphrase to hand: with it and no
                # source, gpg fails outright rather than asking.
                cmd = cmd[:1] + ["--batch", "--yes", "--pinentry-mode", "loopback",
                                 "--passphrase-file", args.passphrase_file] + cmd[1:]
            print("  encrypting")
            subprocess.run(cmd + [str(tarball)], check=True)
            tarball.unlink()

        digest = hashlib.sha256(out.read_bytes()).hexdigest()
        size_mb = out.stat().st_size / 1024 / 1024
        print(f"\n{out}  ({size_mb:.0f} MB)")
        print(f"sha256  {digest}")
        print("\nPublish the sha256 beside the download. It is the only thing "
              "teams can check before the password drops.")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    main()
