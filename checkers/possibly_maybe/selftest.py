#!/usr/bin/env python3
"""
Offline validation of the checker's core (generator, parser, compare) with NO
pwntools/socat needed.  It drives the binaries directly:

  * "remote"    == the repo's svm against a real db_server, entered exactly as
                   serve.sh does (first line -> argv, rest -> stdin, stderr
                   merged).  Validates the wire-protocol semantics.
  * "reference" == checkers/svm/svm_ref under SVM_LOCAL_DB (what checker.py's
                   check() compares against).

Proves remote==reference for deterministic programs (key window masked),
the stamp probe semantics, and the flag put/get round-trip.

Usage:  python3 selftest.py [num_deterministic]
Requires an x86-64 host and a built ../../db_server and ../../svm.
"""
import os, sys, subprocess, random, time, signal

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import gen, svm_proto as P
from refrun import run_reference

# The service binaries live under internal/possibly_maybe (built by its Makefile).
# Override with SVM=/path and DB=/path if you staged them elsewhere.
BIN = os.path.join(REPO, "internal", "possibly_maybe")
SVM = os.environ.get("SVM", os.path.join(BIN, "svm"))
DB  = os.environ.get("DB",  os.path.join(BIN, "db_server"))


def serve(request: bytes, timeout=5.0) -> bytes:
    nl = request.find(b"\n")
    first = request[:nl].decode()
    prog = request[nl + 1:]
    p = subprocess.run([SVM] + first.split(), input=prog,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return p.stdout


def remote_new(program):        return serve(b"new\n" + program.encode())
def remote_reuse(key, program): return serve(f"reuse {key}\n".encode() + program.encode())


def test_deterministic(n):
    ok = kept = 0
    for i in range(n):
        prog = gen.gen_deterministic(random.Random(random.randrange(1 << 40)))
        ref = P.parse_output(run_reference(prog))
        if ref.trap != "clean halt":
            continue
        kept += 1
        why = P.diff_deterministic(ref, P.parse_output(remote_new(prog)))
        if why:
            print(f"[MISMATCH #{i}] {why}\n{prog}")
            return False
        ok += 1
    print(f"deterministic: {ok}/{kept} matched (of {n} generated)")
    return kept > 0 and ok == kept


def test_timing(n):
    # honest service: real counter readings must pass check_timing, marker exact
    for i in range(n):
        prog, (off, marker) = gen.gen_timing(random.Random(random.randrange(1 << 40)))
        res = P.parse_output(remote_new(prog))
        if res.trap != "clean halt":
            print(f"[TIMING #{i}] bad run: {res}"); return False
        why = P.check_timing(res.outs)
        if why:
            print(f"[TIMING #{i}] honest run rejected: {why} ({res.outs[:3]})"); return False
        if res.heap[off:off + 8] != marker.to_bytes(8, "little"):
            print(f"[TIMING #{i}] marker mismatch"); return False
    # cheat detection: implausible timing triples must be rejected
    good_t = 8_600_000_000_000
    cheats = {
        "zeros":        [0, 0, 0],
        "tiny counter": [1, 2, 1],
        "huge const":   [(1 << 64) - 1, (1 << 64) - 1, 0],
        "huge t":       [1 << 62, 1 << 62, 0],
        "non-monotonic":[good_t + 100, good_t, (good_t - (good_t + 100)) & P_MASK],
        "huge delta":   [good_t, good_t + (1 << 40), 1 << 40],
        "bad delta":    [good_t, good_t + 200, 999999],
    }
    for name, outs in cheats.items():
        if P.check_timing(outs) is None:
            print(f"[TIMING cheat] '{name}' {outs} NOT flagged"); return False
    print(f"timing: {n}/{n} honest ok, {len(cheats)}/{len(cheats)} cheats flagged")
    return True


def test_flag(n):
    for i in range(n):
        flag = ("S" + "".join(random.choices(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=30)) + "=").encode()
        key = P.extract_key(remote_new(P.build_put_program(flag)))
        if not key:
            print(f"[FLAG #{i}] no key"); return False
        res = P.parse_output(remote_reuse(key, P.build_get_program(len(flag))))
        if P.extract_flag(res, len(flag)) != flag:
            print(f"[FLAG #{i}] round-trip mismatch"); return False
    print(f"flag round-trip: {n}/{n} ok")
    return True


P_MASK = (1 << 64) - 1


def main():
    ndet = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    subprocess.run(["pkill", "-f", "db_server"], stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    db = subprocess.Popen([DB], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    time.sleep(0.7)
    try:
        a = test_deterministic(ndet)
        b = test_timing(30)
        c = test_flag(20)
    finally:
        db.send_signal(signal.SIGKILL); db.wait()
    print("ALL PASS" if (a and b and c) else "FAILURES ABOVE")
    return 0 if (a and b and c) else 1


if __name__ == "__main__":
    try: signal.signal(signal.SIGALRM, signal.SIG_IGN)
    except Exception: pass
    sys.exit(main())
