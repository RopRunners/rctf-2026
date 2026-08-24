import json
import logging
import os
import random
import ssl
import sys
import time
import urllib.parse

import requests
from checklib import *
import requests.adapters as adapters

logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

PORT = 6000
IMAGE_IDS = list(range(1, 7))
REPO = "pipeline/app"
TAG = "latest"

# Anchored to this file, not to the working directory. ForcAD runs a checker as
# a subprocess from the celery worker's cwd (/app/services), where a path
# relative to the repo root resolves to nothing - the tree is bind-mounted at
# /checkers/. check.py runs them from the repo root, so the relative form works
# there and only there: locally every action passes, and in the game the certs
# are missing and every put MUMBLEs "Image not found" for every team at once.
_HERE = os.path.dirname(os.path.abspath(__file__))

CA_TEAMS = os.path.join(_HERE, "certs/ca/teams/ca.pem")
CHECKER_CLIENT_CERT = os.path.join(_HERE, "certs/checker/client.pem")
CHECKER_CLIENT_KEY = os.path.join(_HERE, "certs/checker/client.key")

CHECK_BUDGET_SECONDS = 12
DEPLOY_WAIT_SECONDS = 10
DEPLOY_POLL_INTERVAL = 0.5
HTTP_TIMEOUT = 8

TRANSIENT_STATUSES = (502, 503, 504)
TRANSIENT_ATTEMPTS = 4
TRANSIENT_BACKOFF = 0.4
TRANSIENT_WINDOW = 3

MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)

MIRROR_PROBE_URL = "https://www.google.com/generate_204"
MIRROR_PROBE_EXPECT = 204
MIRROR_PROBE_RETRIES = 1

IMAGES_DIR = os.path.join(_HERE, "images")


def get_tag_by_id(image_id) -> str:
    return f"v{image_id}"


def get_build_by_id(image_id) -> str:
    return get_tag_by_id(image_id)


def get_image_local_name_by_id(image_id) -> str:
    return f"app:{get_tag_by_id(image_id)}"


def get_all_image_names():
    return list(map(get_image_local_name_by_id, IMAGE_IDS))


def get_layout_path(image_id) -> str:
    return f"{IMAGES_DIR}/{get_tag_by_id(image_id)}"


def read_manifest_descriptor(layout_path: str):
    with open(os.path.join(layout_path, "index.json"), "r") as f:
        index = json.load(f)
    return next(
        (
            m
            for m in index["manifests"]
            if "application/vnd.oci.image.manifest" in m.get("mediaType", "")
        ),
        index["manifests"][0],
    )


_DIGEST_BUILDS = None


def digest_builds():
    global _DIGEST_BUILDS
    if _DIGEST_BUILDS is None:
        mapping = {}
        for image_id in IMAGE_IDS:
            layout_path = get_layout_path(image_id)
            if not os.path.exists(layout_path):
                continue
            desc = read_manifest_descriptor(layout_path)
            mapping[desc["digest"]] = get_build_by_id(image_id)
        _DIGEST_BUILDS = mapping
    return _DIGEST_BUILDS


def select_image_id(current_build):
    ids = list(IMAGE_IDS)
    if current_build is not None:
        candidates = [i for i in ids if get_build_by_id(i) != current_build]
        if candidates:
            ids = candidates
    chosen = random.choice(ids)
    logger.debug(f"Selected image_id: {chosen} (current_build was: {current_build})")
    return chosen


class NoHostnameAdapter(adapters.HTTPAdapter):
    def __init__(self, ca_file, **kwargs):
        self.ca_file = ca_file
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_file)
        ctx.check_hostname = False
        pool_kwargs["ssl_context"] = ctx
        pool_kwargs["assert_hostname"] = False
        return super().init_poolmanager(
            connections, maxsize, block=block, **pool_kwargs
        )


class MTLSNoHostnameAdapter(adapters.HTTPAdapter):
    def __init__(self, ca_file, client_cert, client_key, **kwargs):
        self.ca_file = ca_file
        self.client_cert = client_cert
        self.client_key = client_key
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_file)
        ctx.check_hostname = False
        ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        pool_kwargs["ssl_context"] = ctx
        pool_kwargs["assert_hostname"] = False
        return super().init_poolmanager(
            connections, maxsize, block=block, **pool_kwargs
        )


_WEB_SESSION = None
_REGISTRY_SESSION = None


def _ensure_web_session():
    global _WEB_SESSION
    if _WEB_SESSION is None:
        logger.debug("Initializing web session")
        session = get_initialized_session()
        session.verify = CA_TEAMS
        session.mount("https://", NoHostnameAdapter(ca_file=CA_TEAMS))
        _WEB_SESSION = session
    return _WEB_SESSION


def _ensure_registry_session():
    global _REGISTRY_SESSION
    if _REGISTRY_SESSION is None:
        logger.debug("Initializing registry mTLS session")
        session = get_initialized_session()
        session.verify = CA_TEAMS
        session.mount(
            "https://",
            MTLSNoHostnameAdapter(
                ca_file=CA_TEAMS,
                client_cert=CHECKER_CLIENT_CERT,
                client_key=CHECKER_CLIENT_KEY,
            ),
        )
        _REGISTRY_SESSION = session
    return _REGISTRY_SESSION


class CheckMachine:
    def __init__(self, checker: BaseChecker):
        self.c = checker
        self.port = PORT

    def _base(self) -> str:
        return f"https://{self.c.host}:{self.port}"

    def _request(self, method, path, fatal=True, **kw):
        url = f"{self._base()}{path}"
        s = _ensure_web_session()
        kw.setdefault("timeout", HTTP_TIMEOUT)
        logger.debug(f"{method} {url}")

        last_error = None
        give_up_at = time.monotonic() + TRANSIENT_WINDOW
        for attempt in range(TRANSIENT_ATTEMPTS if fatal else 1):
            if attempt:
                if time.monotonic() >= give_up_at:
                    break
                time.sleep(TRANSIENT_BACKOFF)
            try:
                r = s.request(method, url, **kw)
            except requests.exceptions.Timeout:
                last_error = f"{method} {path} timed out"
                logger.warning(last_error)
                if fatal:
                    self.c.cquit(Status.DOWN, "Timeout", last_error)
                break
            except requests.exceptions.RequestException as e:
                last_error = f"{method} {path} failed: {e}"
                logger.warning(f"{last_error} (attempt {attempt + 1})")
                continue

            logger.debug(f"{method} {url} -> {r.status_code}")
            if r.status_code not in TRANSIENT_STATUSES:
                return r
            last_error = f"{method} {path} -> HTTP {r.status_code}"
            logger.warning(f"{last_error} (attempt {attempt + 1})")

        if not fatal:
            return None
        logger.error(f"{method} {url} failed: {last_error}")
        self.c.cquit(Status.DOWN, "Connection error", last_error)

    def _post(self, path, **kw):
        return self._request("POST", path, **kw)

    def _get(self, path, **kw):
        return self._request("GET", path, **kw)

    # health --------------------
    def get_healthz_build(self):
        r = self._get("/healthz", fatal=False)
        if r is None or r.status_code != 200:
            logger.warning(f"Healthz unavailable: {r if r is None else r.status_code}")
            return None
        try:
            build = r.json().get("build")
        except ValueError:
            logger.warning("Healthz returned non-JSON")
            return None
        logger.debug(f"Healthz build: {build}")
        return build

    def wait_for_deploy(self, expected_build: str, pushed_digest: str, deadline: float):
        targets = {expected_build}
        superseded = False
        build = None
        tag_digest = pushed_digest

        while True:
            build = self.get_healthz_build()
            if build == expected_build:
                logger.info(f"Build {expected_build} is up and running")
                return True, ""

            current_digest = self.tag_digest()
            if current_digest is not None and current_digest != pushed_digest:
                if not superseded:
                    logger.info(f"Push {pushed_digest} superseded by {current_digest}")
                superseded = True
                tag_digest = current_digest
                other_build = digest_builds().get(current_digest)
                if other_build is not None:
                    targets.add(other_build)

            if superseded and build in targets:
                logger.info(f"Pipeline tracking concurrent push, build={build}")
                return True, ""

            if time.monotonic() >= deadline:
                break
            time.sleep(DEPLOY_POLL_INTERVAL)

        if superseded:
            detail = (
                f"deployed build={build} matches none of the images pushed during "
                f"the check window ({sorted(targets)}), tag now at {tag_digest}"
            )
        else:
            detail = (
                f"watchtower did not surface build={expected_build} on /healthz, "
                f"deployed build={build}"
            )
        logger.warning(detail)
        return False, detail

    # flag store/retrieve --------------------
    def store_flag(self, flag: str):
        logger.debug("Storing flag")
        r = self._post("/store", json={"data": flag})
        if r.status_code != 200:
            logger.error(f"Store failed: HTTP {r.status_code}")
            self.c.cquit(
                Status.MUMBLE, "Store failed", f"POST /store -> HTTP {r.status_code}"
            )
        try:
            j = r.json()
            aid, tok = j["id"], j["token"]
            logger.debug(f"Flag stored successfully, id={aid}")
            return aid, tok
        except (ValueError, KeyError) as e:
            logger.error(f"Bad store response: {e}")
            self.c.cquit(Status.MUMBLE, "Bad store response", f"{e}: {r.text[:120]!r}")

    def retrieve_flag(self, art_id: str, token: str, expected_flag: str):
        logger.debug(f"Retrieving flag for id={art_id}")
        r = self._get("/retrieve", params={"id": art_id, "token": token})

        if r.status_code in (403, 404):
            logger.error(f"Flag not found: HTTP {r.status_code}")
            self.c.cquit(
                Status.CORRUPT,
                "Flag not found",
                f"GET /retrieve -> HTTP {r.status_code}",
            )
        if r.status_code != 200:
            logger.error(f"Retrieve failed: HTTP {r.status_code}")
            self.c.cquit(
                Status.MUMBLE,
                "Retrieve failed",
                f"GET /retrieve -> HTTP {r.status_code}",
            )
        try:
            got = r.json().get("data")
        except ValueError:
            logger.error("Bad retrieve response: non-json")
            self.c.cquit(
                Status.MUMBLE, "Bad retrieve response", f"non-json: {r.text[:120]!r}"
            )

        if got != expected_flag:
            logger.error("Flag mismatch: stored != retrieved")
            self.c.cquit(Status.CORRUPT, "Flag mismatch", "stored != retrieved")
        logger.debug("Flag retrieved successfully")

    # functional coverage --------------------
    def functional_check(self):
        logger.info("Starting functional check")
        def mumble(what, detail):
            logger.error(f"Functionality broken: {what} -> {detail}")
            self.c.cquit(Status.MUMBLE, f"Functionality broken: {what}", detail)

        r = self._get("/healthz")
        if r.status_code != 200:
            mumble("healthz", f"HTTP {r.status_code}")
        try:
            hj = r.json()
        except ValueError:
            mumble("healthz response", f"non-json: {r.text[:120]!r}")
        if not hj.get("build"):
            mumble("healthz build", "missing build field")

        nonce = rnd_string(24)
        r = self._post("/store", json={"data": nonce})
        if r.status_code != 200:
            mumble("store(data)", f"HTTP {r.status_code}")
        try:
            j = r.json()
            aid, tok = j["id"], j["token"]
        except (ValueError, KeyError) as e:
            mumble("store(data) response", f"{e}: {r.text[:120]!r}")
        if not aid or not tok:
            mumble("store(data) creds", f"empty id/token: {j!r}")

        r = self._get("/retrieve", params={"id": aid, "token": tok})
        if r.status_code != 200:
            mumble("retrieve", f"HTTP {r.status_code}")
        try:
            got = r.json().get("data")
        except ValueError:
            got = None
        if got != nonce:
            mumble("retrieve integrity", "stored value != retrieved")

        r = self._get("/retrieve", params={"id": aid, "token": rnd_string(32)})
        if r.status_code == 200:
            mumble("token enforcement", "wrong token returned 200")
        elif r.status_code != 403:
            mumble(
                "token enforcement status",
                f"wrong token -> HTTP {r.status_code}, want 403",
            )

        r = self._get(
            "/retrieve", params={"id": rnd_string(32), "token": rnd_string(32)}
        )
        if r.status_code != 404:
            mumble("unknown id", f"-> HTTP {r.status_code}, want 404")

        r = self._get("/retrieve", params={"id": aid})
        if r.status_code != 400:
            mumble(
                "retrieve validation",
                f"missing token -> HTTP {r.status_code}, want 400",
            )

        r = self._post("/store", json={})
        if r.status_code != 400:
            mumble("store validation", f"empty store -> HTTP {r.status_code}, want 400")

        r = self._get("/store")
        if r.status_code != 405:
            mumble("store method", f"GET /store -> HTTP {r.status_code}, want 405")

        r = self._post("/mr", json={"method": "GET"})
        if r.status_code != 400:
            mumble("mirror validation", f"no url -> HTTP {r.status_code}, want 400")

        r = self._get("/metrics")
        if r.status_code != 200:
            mumble("metrics", f"GET /metrics -> HTTP {r.status_code}, want 200")
        for series in ("pipeline_build_info", "pipeline_artifacts_stored"):
            if series not in r.text:
                mumble("metrics format", f"prometheus exposition missing {series}")

        logger.info("Functional check passed")

    def mirror_check(self):
        logger.info("Starting mirror check")
        last_detail = ""
        for attempt in range(MIRROR_PROBE_RETRIES + 1):
            logger.debug(f"Mirror probe attempt {attempt + 1}")
            payload = {"method": "GET", "url": MIRROR_PROBE_URL}
            r = self._post("/mr", json=payload)

            if r.status_code == 403:
                logger.error("Mirror allow-list broken: probe host rejected")
                self.c.cquit(
                    Status.MUMBLE,
                    "Mirror allow-list broken",
                    "probe host rejected by /mr allow-list",
                )
            if r.status_code != 200:
                logger.error(f"Mirror endpoint broken: HTTP {r.status_code}")
                self.c.cquit(
                    Status.MUMBLE,
                    "Mirror endpoint broken",
                    f"POST /mr -> HTTP {r.status_code}",
                )
            try:
                j = r.json()
                up_status = j["status"]
            except (ValueError, KeyError) as e:
                logger.error(f"Bad mirror response: {e}")
                self.c.cquit(
                    Status.MUMBLE, "Bad mirror response", f"{e}: {r.text[:120]!r}"
                )

            if up_status == MIRROR_PROBE_EXPECT:
                logger.info("Mirror check passed")
                return

            last_detail = (
                f"mirror upstream returned {up_status}, want {MIRROR_PROBE_EXPECT}"
            )
            logger.warning(last_detail)

        logger.error("Mirror functionality degraded")
        self.c.cquit(Status.MUMBLE, "Mirror functionality degraded", last_detail)

    # Registry --------------------
    def tag_digest(self):
        url = f"{self._base()}/v2/{REPO}/manifests/{TAG}"
        s = _ensure_registry_session()
        try:
            r = s.head(
                url, headers={"Accept": MANIFEST_ACCEPT}, timeout=HTTP_TIMEOUT
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"HEAD {url} failed: {e}")
            return None
        if r.status_code != 200:
            logger.warning(f"HEAD {url} -> {r.status_code}")
            return None
        return r.headers.get("Docker-Content-Digest")

    def push_image(self, image_id=None) -> str:
        if image_id is None:
            image_id = select_image_id(None)
            logger.info(f"Selected random image_id for push: {image_id}")
        return self._push_image_with_id(image_id)

    def _push_image_with_id(self, image_id) -> str:
        tag = get_tag_by_id(image_id)
        layout_path = get_layout_path(image_id)
        logger.info(f"Pushing image {image_id} (tag: {tag}) from {layout_path}")

        if not os.path.exists(layout_path):
            logger.error(f"Image not found at {layout_path}")
            self.c.cquit(
                Status.MUMBLE,
                "Image not found",
                f"Pre-baked image at {layout_path} does not exist",
            )

        pusher = OCIPusher(
            host=self.c.host,
            port=self.port,
            repo=REPO,
            session=_ensure_registry_session(),
        )

        try:
            digest = pusher.push_oci_layout(layout_path=layout_path, tag=TAG)
            logger.info(f"Image {image_id} pushed successfully, digest={digest}")
            return digest
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            logger.error(f"Registry unreachable: {e}")
            self.c.cquit(Status.DOWN, "Connection error", f"registry unreachable: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Registry push error: {e}")
            self.c.cquit(
                Status.MUMBLE,
                "Registry push error",
                f"Failed to push image: {e}",
            )


class OCIPusher:
    def __init__(self, host: str, port: int, repo: str, session):
        self.host = host
        self.port = port
        self.repo = repo
        self.base_url = f"https://{host}:{port}/v2/{repo}"
        self.session = session
        logger.debug(f"OCIPusher initialized for {self.base_url}")

    def _get_absolute_location(self, location: str) -> str:
        if location.startswith("http"):
            return location
        parsed_base = urllib.parse.urlparse(self.base_url)
        if location.startswith("/"):
            return f"{parsed_base.scheme}://{parsed_base.netloc}{location}"
        return f"{parsed_base.scheme}://{parsed_base.netloc}/{parsed_base.path.rsplit('/', 1)[0]}/{location}"

    def push_blob(self, digest: str, file_path: str):
        logger.debug(f"Pushing blob {digest} from {file_path}")
        r = self.session.post(
            f"{self.base_url}/blobs/uploads/", timeout=HTTP_TIMEOUT
        )
        r.raise_for_status()

        location = self._get_absolute_location(r.headers["Location"])
        with open(file_path, "rb") as f:
            r = self.session.put(
                f"{location}?digest={digest}",
                data=f,
                headers={"Content-Type": "application/octet-stream"},
                timeout=HTTP_TIMEOUT,
            )
        r.raise_for_status()
        logger.debug(f"Blob {digest} pushed successfully")

    def push_oci_layout(self, layout_path: str, tag: str) -> str:
        logger.info(f"Pushing OCI layout from {layout_path} with tag {tag}")
        manifest_desc = read_manifest_descriptor(layout_path)
        manifest_digest = manifest_desc["digest"]
        manifest_media_type = manifest_desc.get(
            "mediaType", "application/vnd.oci.image.manifest.v1+json"
        )

        manifest_hash = manifest_digest.split(":")[1]
        manifest_path = os.path.join(layout_path, "blobs", "sha256", manifest_hash)

        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        config_digest = manifest["config"]["digest"]
        config_hash = config_digest.split(":")[1]
        config_path = os.path.join(layout_path, "blobs", "sha256", config_hash)
        if os.path.exists(config_path):
            self.push_blob(config_digest, config_path)

        for layer in manifest.get("layers", []):
            layer_digest = layer["digest"]
            layer_hash = layer_digest.split(":")[1]
            layer_path = os.path.join(layout_path, "blobs", "sha256", layer_hash)
            if os.path.exists(layer_path):
                self.push_blob(layer_digest, layer_path)

        with open(manifest_path, "rb") as f:
            manifest_bytes = f.read()

        r = self.session.put(
            f"{self.base_url}/manifests/{tag}",
            data=manifest_bytes,
            headers={"Content-Type": manifest_media_type},
            timeout=HTTP_TIMEOUT,
        )
        r.raise_for_status()
        logger.debug("Manifest pushed successfully")
        return manifest_digest
