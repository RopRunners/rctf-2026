"""
Random SVM program generator for the differential checker.

Two program *shapes*:

  * gen_deterministic() -- programs whose observable behaviour (out values +
    final trap/exit + heap image) is a pure function of the code.  No stamp
    (nondeterministic counter).  Memory is confined to known-zero state: the fresh
    DB row (128 B, server-zeroed) and heap offsets >= HEAP_SAFE (clear of the
    32-byte row key the runner writes at heap[0:32]).  These are compared to
    the trusted reference EXACTLY (with heap[0:32] masked).

  * gen_timing() -- a program that exercises stamp.  The timestamps live in
    "timing" registers isolated from the deterministic filler, so they never
    reach the exact-checked surface; the checker asserts them semantically
    (monotonic + plausible), and exact-checks the filler's memory effects.

The generator is deliberately conservative (addresses are always re-based to a
region base right before use, loops always count down from a small constant) so
programs reliably halt in-bounds.  The reference run is still the final filter:
anything that doesn't cleanly halt fast is discarded by the caller.
"""

import random

DB_VBASE   = 0x20000000
HEAP_VBASE = 0x40000000
ROW_SIZE   = 128
HEAP_SIZE  = 4 * 1024 * 1024        # SVM_HEAP_SIZE (jit.h): 4 MiB

# Guest heap region the deterministic generator is allowed to touch: strictly
# above the 32-byte row key at heap[0:32].  We start at 64 to leave the whole
# first line (and its masked window) alone.
HEAP_SAFE  = 64
RAND_ROT   = 23     # `rand` returns a rotated hardware counter; ror by this to unrotate

MASK64 = (1 << 64) - 1


class Gen:
    def __init__(self, rnd: random.Random):
        self.r = rnd
        self.lines = []
        self.nlabel = 0

    def label(self, stem="L"):
        self.nlabel += 1
        return f"{stem}{self.nlabel}"

    def emit(self, s):
        self.lines.append(s)

    def imm(self):
        # A spread of interesting immediates, including wide ones.
        choice = self.r.randint(0, 4)
        if choice == 0:
            return self.r.randint(0, 0xff)
        if choice == 1:
            return self.r.randint(0, 0xffffffff)
        if choice == 2:
            return self.r.getrandbits(64)
        if choice == 3:
            return self.r.choice([0, 1, 2, 0xffffffffffffffff, 0x8000000000000000])
        return self.r.randint(0, 1000)

    # ---- deterministic building blocks (registers r0..r5) -------------
    DET_REGS = list(range(6))          # r0..r5 are "deterministic"

    def alu(self):
        op = self.r.choice(["add", "sub", "and", "or", "xor"])
        rd = self.r.choice(self.DET_REGS)
        if self.r.random() < 0.5:
            self.emit(f"{op} r{rd}, {self.imm()}")
        else:
            rs = self.r.choice(self.DET_REGS)
            self.emit(f"{op} r{rd}, r{rs}")

    def movop(self):
        rd = self.r.choice(self.DET_REGS)
        self.emit(f"mov r{rd}, {self.imm()}")

    def mulop(self):
        rd = self.r.choice(self.DET_REGS)
        rs = self.r.choice(self.DET_REGS)
        self.emit(f"mul r{rd}, r{rs}")

    def shiftop(self):
        op = self.r.choice(["shl", "shr", "rol", "ror", "sar"])
        rd = self.r.choice(self.DET_REGS)
        self.emit(f"{op} r{rd}, {self.r.randint(0, 63)}")

    def unaryop(self):
        op = self.r.choice(["not", "neg", "bswap"])
        rd = self.r.choice(self.DET_REGS)
        self.emit(f"{op} r{rd}")

    def popcntop(self):
        rd = self.r.choice(self.DET_REGS)
        rs = self.r.choice(self.DET_REGS)
        self.emit(f"popcnt r{rd}, r{rs}")

    def memop(self):
        # Always re-base a scratch reg to a region base immediately before the
        # access, with an in-range displacement, so the address is always valid.
        rb = self.r.choice(self.DET_REGS)
        rv = self.r.choice(self.DET_REGS)
        if self.r.random() < 0.5:
            base, lo, hi = DB_VBASE, 0, ROW_SIZE
        else:
            base, lo, hi = HEAP_VBASE, HEAP_SAFE, HEAP_SIZE
        store = self.r.random() < 0.5
        wide  = self.r.random() < 0.5
        size  = 8 if wide else 1
        off   = self.r.randrange(lo, hi - size + 1)
        self.emit(f"mov r{rb}, {base}")
        if store:
            self.emit(f"{'st' if wide else 'stb'} [r{rb}+{off}], r{rv}")
        else:
            self.emit(f"{'ld' if wide else 'ldb'} r{rv}, [r{rb}+{off}]")

    def cond_skip(self):
        # forward jz/jnz over a few filler ops; taken-or-not is deterministic.
        lab = self.label("skip")
        rc = self.r.choice(self.DET_REGS)
        self.emit(f"{self.r.choice(['jz', 'jnz'])} r{rc}, {lab}")
        for _ in range(self.r.randint(1, 3)):
            self.alu()
        self.emit(f"{lab}:")

    def indirect_skip(self):
        # exercise jmpr via a table-validated forward jump to a real label.
        lab = self.label("ind")
        rc = self.r.choice(self.DET_REGS)
        self.emit(f"mov r{rc}, @{lab}")
        self.emit(f"jmpr r{rc}")
        for _ in range(self.r.randint(1, 2)):
            self.alu()                          # skipped
        self.emit(f"{lab}:")

    def pauseop(self):
        # `pause` is the only spin/serialization hint in the final ISA (the
        # xsync flush and the sync/rsync/wsync barriers were removed); it is a
        # pure no-op architecturally but must parse and execute without trapping.
        self.emit("pause")

    def loop(self):
        # Bounded countdown loop; the counter reg is not written inside.
        cnt = self.r.choice(self.DET_REGS)
        others = [x for x in self.DET_REGS if x != cnt]
        n = self.r.randint(2, 6)
        lab = self.label("loop")
        self.emit(f"mov r{cnt}, {n}")
        self.emit(f"{lab}:")
        for _ in range(self.r.randint(1, 3)):
            rd = self.r.choice(others)
            self.emit(f"add r{rd}, {self.r.randint(1, 9)}")
        self.emit(f"sub r{cnt}, 1")
        self.emit(f"jnz r{cnt}, {lab}")

    def outop(self):
        self.emit(f"out r{self.r.choice(self.DET_REGS)}")

    def det_stmt(self):
        self.r.choice([
            self.alu, self.alu, self.movop, self.mulop, self.shiftop,
            self.memop, self.memop, self.loop, self.outop,
            self.cond_skip, self.indirect_skip, self.pauseop,
            self.unaryop, self.popcntop,
        ])()


def gen_deterministic(rnd: random.Random, nstmt=None) -> str:
    g = Gen(rnd)
    if nstmt is None:
        nstmt = rnd.randint(12, 32)
    # seed a couple of regs so early outs aren't all zero
    for i in range(6):
        g.emit(f"mov r{i}, {g.imm()}")
    # optional subroutine exercised via call/ret
    use_call = rnd.random() < 0.5
    if use_call:
        g.emit("jmp _main")
        g.emit("_sub:")
        g.emit(f"add r{rnd.choice(Gen.DET_REGS)}, {rnd.randint(1, 100)}")
        g.emit("ret")
        g.emit("_main:")
    for _ in range(nstmt):
        g.det_stmt()
        if use_call and rnd.random() < 0.15:
            g.emit("call _sub")
    g.emit(f"out r{rnd.choice(Gen.DET_REGS)}")
    g.emit(f"halt r{rnd.choice(Gen.DET_REGS)}")
    return "\n".join(g.lines) + "\n"


def gen_timing(rnd: random.Random):
    """
    Returns (program, filler_marker). r6/r7 are the isolated timing registers;
    the deterministic filler uses r0..r5 only.  The program:
      - reads stamp into r6,
      - does a bounded loop of real work,
      - reads stamp into r7,
      - out r6 (t0), out r7 (t1), then out (t1 - t0) as delta,
      - writes a deterministic marker into the heap so the filler is
        exact-checkable,
      - halts.
    The checker asserts t1 >= t0 (monotonic), both large, delta >= 1, and
    exact-checks the heap marker.
    """
    g = Gen(rnd)
    marker = rnd.getrandbits(64)
    # `rand` returns a rotated hardware counter; rotate each sample back by
    # RAND_ROT so t0/t1/delta come out monotonic and comparable.
    g.emit("rand r6")                       # t0 (rotated)
    g.emit(f"ror r6, {RAND_ROT}")           # -> unrotated counter
    # bounded busy work on deterministic regs
    cnt = 4
    g.emit(f"mov r0, {cnt}")
    g.emit("_tl:")
    g.emit("add r1, 3")
    g.emit("mul r1, r1")
    g.emit("sub r0, 1")
    g.emit("jnz r0, _tl")
    g.emit("rand r7")                       # t1 (rotated)
    g.emit(f"ror r7, {RAND_ROT}")           # -> unrotated counter
    g.emit("out r6")
    g.emit("out r7")
    g.emit("mov r5, r7")
    g.emit("sub r5, r6")                    # delta = t1 - t0
    g.emit("out r5")
    # deterministic heap marker at a safe offset
    g.emit(f"mov r2, {HEAP_VBASE}")
    g.emit(f"mov r3, {marker}")
    g.emit(f"st [r2+{HEAP_SAFE}], r3")
    g.emit("halt r3")
    return "\n".join(g.lines) + "\n", (HEAP_SAFE, marker)


if __name__ == "__main__":
    import sys
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else random.randrange(1 << 30)
    r = random.Random(seed)
    print(f"; seed={seed}")
    print(gen_deterministic(r))
