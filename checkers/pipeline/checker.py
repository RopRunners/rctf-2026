#!/usr/bin/env python3

import sys

from pipeline_lib import *


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 15
    uses_attack_data: bool = False

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except requests.exceptions.ConnectionError:
            self.cquit(Status.DOWN, "Connection error", "Got requests connection error")
        except requests.exceptions.Timeout:
            self.cquit(Status.DOWN, "Timeout", "Got timeout")

    def check(self):
        budget = time.monotonic() + CHECK_BUDGET_SECONDS

        current_build = self.mch.get_healthz_build()
        image_id = select_image_id(current_build)
        expected_build = get_build_by_id(image_id)
        digest = self.mch.push_image(image_id)
        deploy_deadline = min(time.monotonic() + DEPLOY_WAIT_SECONDS, budget)

        ok, detail = self.mch.wait_for_deploy(expected_build, digest, deploy_deadline)
        if not ok:
            self.cquit(Status.MUMBLE, "Deploy pipeline degraded", detail)

        self.mch.functional_check()
        self.mch.mirror_check()
        self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str, vuln: str):
        art_id, token = self.mch.store_flag(flag)
        self.cquit(
            Status.OK,
            public=f"{art_id}:{token}",
            private=json.dumps({"id": art_id, "token": token}),
        )

    def get(self, flag_id: str, flag: str, vuln: str):
        try:
            art_id, token = flag_id.split(":", 1)
        except ValueError:
            raise Exception(f"unparseable flag_id: {flag_id!r}")

        self.mch.retrieve_flag(art_id, token, flag)
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])

    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
