#!/usr/bin/env python3

import random
import sys

from checklib import *
from svm_lib import *

import gen
import svm_proto as P


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 15
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        super(Checker, self).action(action, *args, **kwargs)

    # ------------------------------------------------------------------ #
    def _fresh_det_program(self):
        """A random deterministic program that the trusted reference confirms
        halts cleanly, together with its reference RunResult."""
        for _ in range(6):
            prog = gen.gen_deterministic(random.Random(random.randrange(1 << 40)))
            ref = P.parse_output(self.mch.reference(prog))
            if ref.trap == 'clean halt' and ref.heap is not None:
                return prog, ref
        # reference itself misbehaving is a checker-side problem, not the team's
        self.cquit(getattr(Status, 'CHECKER_ERROR', Status.MUMBLE),
                   'reference failed', 'no clean program')

    def check(self):
        # 1) differential: random programs must match the trusted reference
        for _ in range(3):
            prog, ref = self._fresh_det_program()
            got = P.parse_output(self.mch.run_new(prog))
            why = P.diff_deterministic(ref, got)
            if why is not None:
                self.cquit(Status.MUMBLE, 'wrong program output', why)

        # 2) stamp probe: plausible counter readings (implausible values -> cheat)
        #    plus the deterministic heap marker.  Timing regs are isolated from the
        #    exact-checked surface, so the counter readings never pollute the diff.
        tprog, (off, marker) = gen.gen_timing(random.Random(random.randrange(1 << 40)))
        tr = P.parse_output(self.mch.run_new(tprog))
        self.assert_eq(tr.trap, 'clean halt', 'timing program did not halt cleanly', Status.MUMBLE)
        why = P.check_timing(tr.outs)
        if why is not None:
            self.cquit(Status.MUMBLE, 'bad timer readings', why)
        self.assert_eq(tr.heap[off:off + 8], marker.to_bytes(8, 'little'),
                       'timing heap marker mismatch', Status.MUMBLE)

        # 3) persistence round-trip through the real db (new -> reuse)
        val = random.getrandbits(64)
        store = f"mov r0, {P.DB_VBASE}\nmov r1, {val}\nst [r0+0], r1\nhalt r1\n"
        key = P.extract_key(self.mch.run_new(store))
        if not key:
            self.cquit(Status.MUMBLE, 'no row key returned', 'store produced no key')
        load = (f"mov r0, {P.DB_VBASE}\nmov r2, {P.HEAP_VBASE}\n"
                f"ld r1, [r0+0]\nst [r2+{P.FLAG_HEAP_OFF}], r1\nhalt r1\n")
        rr = P.parse_output(self.mch.run_reuse(key, load))
        got_val = int.from_bytes(P.extract_flag(rr, 8), 'little')
        self.assert_eq(got_val, val, 'persistence round-trip mismatch', Status.MUMBLE)

        self.cquit(Status.OK)

    # ------------------------------------------------------------------ #
    def put(self, flag_id: str, flag: str, vuln: str):
        fb = flag.encode()
        out = self.mch.run_new(P.build_put_program(fb))
        key = P.extract_key(out)
        if not key:
            self.cquit(Status.MUMBLE, 'store failed', 'no key returned by service')
        self.assert_eq(P.parse_output(out).trap, 'clean halt',
                       'put program did not halt cleanly', Status.MUMBLE)

        # verify the flag is retrievable right now (storage sanity)
        rr = P.parse_output(self.mch.run_reuse(key, P.build_get_program(len(fb))))
        self.assert_eq(P.extract_flag(rr, len(fb)), fb,
                       'flag not retrievable immediately after put', Status.MUMBLE)

        # Public id leaks nothing about the capability key (the retrieval token
        # is the private field); echo the framework's opaque id for display.
        self.cquit(Status.OK, flag_id, key)

    def get(self, flag_id: str, flag: str, vuln: str):
        fb = flag.encode()
        rr = P.parse_output(self.mch.run_reuse(flag_id, P.build_get_program(len(fb))))
        self.assert_eq(P.extract_flag(rr, len(fb)), fb,
                       'flag missing or corrupted', Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == '__main__':
    c = Checker(sys.argv[2])

    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
    except Exception as e:
        # Public and private must not be the same string here. ForcAD renames
        # public_message to `message` and serves it to every team on the
        # scoreboard (storage.tasks.filter_teamtasks_for_participants), while
        # private_message stays with the organisers - so an unexpected exception
        # echoed into both puts checker internals, paths and library errors on a
        # public page. Generic outward, detailed inward.
        cquit(Status.MUMBLE, 'checker error', f'{type(e).__name__}: {e}')
