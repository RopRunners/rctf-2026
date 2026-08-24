from checklib import *
from pwnlib.tubes.remote import remote

import svm_proto as P
from refrun import run_reference

PORT = 17171


class CheckMachine:
    """Transport layer.  One TCP connection == one run: send the first line
    (`new` | `reuse <hexkey>`) then the guest program, half-close, read the
    merged stdout+stderr the service returns (socat forwards svm's stderr)."""

    def __init__(self, checker: BaseChecker):
        self.c = checker
        self.port = PORT

    def _run(self, first_line: str, program: str, timeout: float = 8.0) -> bytes:
        try:
            r = remote(self.c.host, self.port, timeout=timeout)
        except Exception as e:                       # can't connect -> service down
            self.c.cquit(Status.DOWN, 'service unreachable', f'connect: {e}')
            raise
        try:
            r.send((first_line + '\n').encode() + program.encode())
            try:
                r.shutdown('send')
            except Exception:
                pass
            data = r.recvall(timeout=timeout)
        except Exception as e:                       # connected but I/O broke -> mumble
            self.c.cquit(Status.MUMBLE, 'service I/O error', f'{first_line!r}: {e}')
            raise
        finally:
            try:
                r.close()
            except Exception:
                pass
        return data

    # one run per connection
    def run_new(self, program: str) -> bytes:
        return self._run('new', program)

    def run_reuse(self, key: str, program: str) -> bytes:
        return self._run(f'reuse {key}', program)

    # the trusted, checker-owned reference (local, SVM_LOCAL_DB)
    def reference(self, program: str) -> bytes:
        return run_reference(program)
