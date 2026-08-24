"""Run a guest program on the trusted, checker-owned reference `svm`.

Uses SVM_LOCAL_DB=1 so the reference is self-contained -- it maps its own
zeroed 128-byte DB row and heap, needing no db_server.  Output (heap dump on
stdout, `[runner] ...` on stderr) is merged, matching the remote's socat
`2>&1` surface so a single parser handles both sides.
"""

import os
import subprocess

REF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "svm_ref")


def run_reference(program: str, timeout: float = 5.0) -> bytes:
    env = dict(os.environ)
    env["SVM_LOCAL_DB"] = "1"
    p = subprocess.run(
        [REF, "new"],
        input=program.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        timeout=timeout,
    )
    return p.stdout
