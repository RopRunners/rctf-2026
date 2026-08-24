"""
Pure (transport-free) core shared by the checker and the test harness:
  * parse a run's combined output (stdout heap-dump + `out` values + the
    `[runner] ...` stderr lines) into a comparable RunResult,
  * compare two RunResults for the deterministic differential,
  * build the PUT / GET guest programs that store / retrieve a flag in a DB row.

Both the local reference (subprocess) and the remote service (socat) produce
the same textual surface, so the same parser handles both.
"""

import re

HEAP_SIZE = 4 * 1024 * 1024        # SVM_HEAP_SIZE (jit.h): 4 MiB
KEY_LEN   = 32                      # row key the runner writes at heap[0:32]
DB_VBASE   = 0x20000000
HEAP_VBASE = 0x40000000
FLAG_HEAP_OFF = 64                  # where GET drops the retrieved flag (clear of key)

_HEAP_BANNER = re.compile(rb"=== HEAP \((\d+) bytes\) ===")
_DUMP_LINE   = re.compile(rb"^([0-9a-f]{8})  (.*?)\|", re.M)
_HEXPAIR     = re.compile(rb"[0-9a-f]{2}")
_KEY_LINE    = re.compile(rb"row key:\s*([0-9a-f]{64})")
_FINISHED    = re.compile(rb"finished:\s*([^\n(]+?)\s*(?:\(exit value = (\d+)\))?\s*$", re.M)


class RunResult:
    __slots__ = ("outs", "trap", "exit_value", "heap", "raw")

    def __init__(self, outs, trap, exit_value, heap, raw):
        self.outs = outs                # list[int]
        self.trap = trap                # str, e.g. "clean halt"
        self.exit_value = exit_value    # int or None
        self.heap = heap                # bytes(HEAP_SIZE) or None
        self.raw = raw

    def __repr__(self):
        return f"RunResult(trap={self.trap!r}, exit={self.exit_value}, outs={self.outs})"


def parse_heap(blob: bytes) -> bytes:
    """Reconstruct the HEAP image from a `hexdump -C`-style dump (zero-runs
    collapsed to '*' stay zero).  Returns HEAP_SIZE bytes, or all-zero if no
    dump is present."""
    heap = bytearray(HEAP_SIZE)
    m = _HEAP_BANNER.search(blob)
    if not m:
        return bytes(heap)
    start = m.end()
    block = blob[start:]
    for line in _DUMP_LINE.finditer(block):
        off = int(line.group(1), 16)
        pairs = _HEXPAIR.findall(line.group(2))
        for i, h in enumerate(pairs):
            if off + i < HEAP_SIZE:
                heap[off + i] = int(h, 16)
    return bytes(heap)


def parse_output(blob: bytes) -> RunResult:
    if isinstance(blob, str):
        blob = blob.encode("latin1", "replace")

    hb = _HEAP_BANNER.search(blob)
    pre = blob[:hb.start()] if hb else blob

    # `out` values: bare-decimal lines in the pre-dump region.  The runner's
    # `[runner] ...` lines carry text so they never match, and the dump's
    # offset lines live after the banner, so they're excluded.
    outs = []
    for line in pre.split(b"\n"):
        s = line.strip()
        if s and s.isdigit():
            outs.append(int(s))

    trap, exit_value = None, None
    fm = None
    for fm in _FINISHED.finditer(blob):
        pass                            # take the last finished: line
    if fm:
        trap = fm.group(1).decode().strip()
        if fm.group(2) is not None:
            exit_value = int(fm.group(2))

    heap = parse_heap(blob) if hb else None
    return RunResult(outs, trap, exit_value, heap, blob)


def extract_key(blob: bytes):
    """The row's capability key (== flag_id) from a `new` run, or None."""
    if isinstance(blob, str):
        blob = blob.encode("latin1", "replace")
    m = _KEY_LINE.search(blob)
    return m.group(1).decode() if m else None


def _mask_key(heap: bytes) -> bytes:
    return b"\x00" * KEY_LEN + heap[KEY_LEN:]


def diff_deterministic(ref: RunResult, got: RunResult):
    """Compare a remote result to the trusted reference for a deterministic
    program.  Returns None if equivalent, else a human-readable reason.
    heap[0:32] (the per-run random key) is masked on both sides."""
    if got.outs != ref.outs:
        return f"out mismatch: ref={ref.outs} got={got.outs}"
    if got.trap != ref.trap:
        return f"trap mismatch: ref={ref.trap!r} got={got.trap!r}"
    if got.exit_value != ref.exit_value:
        return f"exit mismatch: ref={ref.exit_value} got={got.exit_value}"
    if ref.heap is None or got.heap is None:
        return "missing heap dump"
    if _mask_key(ref.heap) != _mask_key(got.heap):
        # locate first differing offset for diagnostics
        a, b = _mask_key(ref.heap), _mask_key(got.heap)
        for i in range(HEAP_SIZE):
            if a[i] != b[i]:
                return f"heap mismatch at 0x{i:x}: ref={a[i]:02x} got={b[i]:02x}"
        return "heap mismatch"
    return None


# ------------------------- stamp probe -------------------------------
# Plausible bounds for a real counter read.  On-box the counter is ~2^43 and a
# two-read delta over a tiny loop is a few hundred ticks, so these are loose
# enough that an honest service always passes, yet tight enough to flag a
# service that fakes stamp -- returning 0 / a tiny counter, an absurdly large
# constant, or a garbage delta -- as a cheat (-> MUMBLE).
COUNTER_MIN = 1 << 20   # ~1e6: rejects 0, small constants, fake 1,2,3.. counters
COUNTER_MAX = 1 << 60   # ~1.1e18: decades of uptime away; rejects 2^63/2^64 junk
DELTA_MAX = 1 << 34     # a clean run is wall-clock-capped well under this


def check_timing(outs):
    """None if (t0, t1, delta) is a plausible real stamp probe, else a reason
    string.  Implausible timings (too large, zero/tiny, or an impossible delta)
    are treated as a cheat by the caller."""
    if len(outs) < 3:
        return f"expected 3 timing outs, got {outs}"
    t0, t1, delta = outs[0], outs[1], outs[2]
    if not (COUNTER_MIN <= t0 <= COUNTER_MAX):
        return f"t0 implausible: {t0}"
    if not (COUNTER_MIN <= t1 <= COUNTER_MAX):
        return f"t1 implausible: {t1}"
    if t1 < t0:
        return f"non-monotonic counter: t0={t0} t1={t1}"
    if delta != ((t1 - t0) & ((1 << 64) - 1)):
        return f"delta inconsistent: {delta} != {t1 - t0}"
    if not (1 <= delta <= DELTA_MAX):
        return f"delta implausible: {delta}"
    return None


# ------------------------- flag programs ------------------------------
def _u64le(b: bytes) -> int:
    return int.from_bytes(b.ljust(8, b"\x00")[:8], "little")


def build_put_program(flag: bytes) -> str:
    """Store `flag` (<= ROW_SIZE bytes) into the DB row starting at offset 0."""
    lines = [f"mov r0, {DB_VBASE}"]
    for i in range(0, len(flag), 8):
        chunk = _u64le(flag[i:i + 8])
        lines.append(f"mov r1, {chunk}")
        lines.append(f"st [r0+{i}], r1")
    lines.append("halt r0")
    return "\n".join(lines) + "\n"


def build_get_program(nbytes: int) -> str:
    """Copy `nbytes` from the DB row (offset 0) into the heap at FLAG_HEAP_OFF,
    so the retrieved flag shows up in the post-run heap dump (clear of the
    key window at heap[0:32])."""
    lines = [f"mov r0, {DB_VBASE}", f"mov r2, {HEAP_VBASE}"]
    for i in range(0, nbytes, 8):
        lines.append(f"ld r1, [r0+{i}]")
        lines.append(f"st [r2+{FLAG_HEAP_OFF + i}], r1")
    lines.append("halt r1")
    return "\n".join(lines) + "\n"


def extract_flag(res: RunResult, nbytes: int) -> bytes:
    """Pull the retrieved flag bytes back out of a GET run's heap image."""
    if res.heap is None:
        return b""
    return res.heap[FLAG_HEAP_OFF:FLAG_HEAP_OFF + nbytes]
