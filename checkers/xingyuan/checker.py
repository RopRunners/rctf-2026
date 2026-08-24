#!/usr/bin/env python3

import sys
import requests

from checklib import *
from xingyuan_lib import *


class Checker(BaseChecker):
    vulns: int = 3
    timeout: int = 15
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except requests.exceptions.ConnectionError:
            self.cquit(Status.DOWN, 'Connection error', 'Got requests connection error')
        except requests.exceptions.Timeout:
            self.cquit(Status.DOWN, 'Timeout', 'Service did not respond in time')

    def check(self):
        session = get_initialized_session()

        self.mch.get_index(session, Status.MUMBLE)

        username, password = rnd_username(), rnd_password()
        player_id, starter = self.mch.register(session, username, password, Status.MUMBLE)

        showcase = self.mch.get_profile(session, player_id, Status.MUMBLE)
        ids = [it.get('instance_id') for it in showcase]
        self.assert_in(starter, ids, 'Starter character missing from showcase', Status.MUMBLE)

        note = rnd_string(20)
        self.mch.set_note(session, starter, note, Status.MUMBLE)
        got = self.mch.get_note(session, starter, Status.MUMBLE)
        self.assert_eq(got, note, 'Private note did not round-trip', Status.MUMBLE)

        self.mch.pull(session, Status.MUMBLE)

        recipient = get_initialized_session()
        ur, pr = rnd_username(), rnd_password()
        self.mch.register(recipient, ur, pr, Status.MUMBLE)
        gift_msg = rnd_string(20)
        self.mch.send_gift(session, ur, None, gift_msg, 0, Status.MUMBLE)
        inbox = self.mch.get_inbox(recipient, Status.MUMBLE)
        messages = [g.get('message') for g in inbox]
        self.assert_in(gift_msg, messages, 'Gift did not arrive in the inbox', Status.MUMBLE)

        memo = rnd_string(20)
        self.mch.save_backup(session, memo, Status.MUMBLE)
        backup = self.mch.load_backup(session, Status.MUMBLE)
        self.assert_eq(backup.get('memo'), memo, 'Backup memo did not round-trip', Status.MUMBLE)

        importer = get_initialized_session()
        ui, pi = rnd_username(), rnd_password()
        self.mch.register(importer, ui, pi, Status.MUMBLE)
        self.mch.probe_import(importer, Status.MUMBLE)

        self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str, vuln: str):
        if vuln == '3':
            session = get_initialized_session()
            username, password = rnd_username(), rnd_password()
            player_id, _ = self.mch.register(session, username, password, Status.MUMBLE)
            self.mch.save_backup(session, flag, Status.MUMBLE)
            self.cquit(Status.OK, str(player_id), f'{username}:{password}')

        if vuln == '2':
            sender = get_initialized_session()
            us, ps = rnd_username(), rnd_password()
            self.mch.register(sender, us, ps, Status.MUMBLE)

            recipient = get_initialized_session()
            ur, pr = rnd_username(), rnd_password()
            rid, _ = self.mch.register(recipient, ur, pr, Status.MUMBLE)

            gift_id = self.mch.send_gift(sender, ur, None, flag, 0, Status.MUMBLE)
            self.cquit(Status.OK, str(rid), f'{ur}:{pr}:{gift_id}')

        session = get_initialized_session()
        username, password = rnd_username(), rnd_password()
        player_id, starter = self.mch.register(session, username, password, Status.MUMBLE)
        self.mch.set_note(session, starter, flag, Status.MUMBLE)
        self.cquit(Status.OK, str(player_id), f'{username}:{password}:{starter}')

    def get(self, flag_id: str, flag: str, vuln: str):
        session = get_initialized_session()
        parts = flag_id.split(':')
        username, password = parts[0], parts[1]
        self.mch.login(session, username, password, Status.CORRUPT)

        if vuln == '3':
            backup = self.mch.load_backup(session, Status.CORRUPT)
            self.assert_eq(backup.get('memo'), flag, 'Flag missing from archive backup', Status.CORRUPT)
            self.cquit(Status.OK)

        ref = parts[2]
        if vuln == '2':
            inbox = self.mch.get_inbox(session, Status.CORRUPT)
            found = next((g.get('message') for g in inbox if str(g.get('id')) == ref), None)
            self.assert_eq(found, flag, 'Flag missing from received gift', Status.CORRUPT)
            self.cquit(Status.OK)

        note = self.mch.get_note(session, ref, Status.CORRUPT)
        self.assert_eq(note, flag, 'Flag missing from private note', Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == '__main__':
    c = Checker(sys.argv[2])

    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
