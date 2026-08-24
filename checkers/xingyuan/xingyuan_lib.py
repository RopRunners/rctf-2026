import requests
from checklib import *

PORT = 1337

# (connect, read) timeouts. Read is generous enough for /api/import, which makes
# a server-side fetch of its own, but small enough that a hung service yields a
# clean DOWN instead of stalling until the orchestrator kills the checker.
REQ_TIMEOUT = (3.05, 7)
IMPORT_TIMEOUT = (3.05, 10)


class CheckMachine:
    def __init__(self, checker: BaseChecker):
        self.c = checker
        self.port = PORT

    @property
    def url(self):
        return f'http://{self.c.host}:{self.port}'

    def get_index(self, session: requests.Session, status: Status):
        resp = session.get(f'{self.url}/', timeout=REQ_TIMEOUT)
        self.c.assert_eq(resp.status_code, 200, 'Index page is down', status)
        self.c.assert_in('Xingyuan', resp.text, 'Index page looks wrong', status)

    def register(self, session: requests.Session, username: str, password: str, status: Status):
        resp = session.post(f'{self.url}/api/register',
                            json={'username': username, 'password': password},
                            timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on register', status)
        self.c.assert_eq(type(data), dict, 'Invalid response on register', status)
        self.c.assert_eq(data.get('ok'), True, "Can't register", status)
        return data['player_id'], data['starter_instance_id']

    def login(self, session: requests.Session, username: str, password: str, status: Status):
        resp = session.post(f'{self.url}/api/login',
                            json={'username': username, 'password': password},
                            timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on login', status)
        self.c.assert_eq(data.get('ok'), True, "Can't login", status)

    def get_profile(self, session: requests.Session, player_id, status: Status):
        resp = session.get(f'{self.url}/api/profile/{player_id}', timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on profile', status)
        self.c.assert_eq(data.get('ok'), True, "Can't read profile", status)
        showcase = data.get('showcase')
        self.c.assert_eq(type(showcase), list, 'Invalid showcase', status)
        return showcase

    def set_note(self, session: requests.Session, instance_id, note: str, status: Status):
        resp = session.post(f'{self.url}/api/inventory/{instance_id}/note',
                            json={'note': note}, timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on set note', status)
        self.c.assert_eq(data.get('ok'), True, "Can't save note", status)

    def get_note(self, session: requests.Session, instance_id, status: Status) -> str:
        resp = session.get(f'{self.url}/api/inventory/{instance_id}/note', timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on get note', status)
        self.c.assert_eq(data.get('ok'), True, "Can't read note", status)
        note = data.get('note')
        self.c.assert_eq(type(note), str, 'Invalid note', status)
        return note

    def pull(self, session: requests.Session, status: Status):
        resp = session.post(f'{self.url}/api/pull', json={}, timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on pull', status)
        self.c.assert_eq(data.get('ok'), True, "Can't pull on the banner", status)

    def send_gift(self, session: requests.Session, to_username, character_id, message, gems, status: Status):
        resp = session.post(f'{self.url}/api/gift',
                            json={'to': to_username, 'character_id': character_id,
                                  'message': message, 'gems': gems},
                            timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on gift', status)
        self.c.assert_eq(data.get('ok'), True, "Can't send gift", status)
        return data['gift_id']

    def get_inbox(self, session: requests.Session, status: Status):
        resp = session.get(f'{self.url}/api/inbox', timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on inbox', status)
        self.c.assert_eq(data.get('ok'), True, "Can't read inbox", status)
        inbox = data.get('inbox')
        self.c.assert_eq(type(inbox), list, 'Invalid inbox', status)
        return inbox

    def save_backup(self, session: requests.Session, memo: str, status: Status):
        resp = session.post(f'{self.url}/api/backup', json={'memo': memo}, timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on backup', status)
        self.c.assert_eq(data.get('ok'), True, "Can't save backup", status)

    def load_backup(self, session: requests.Session, status: Status):
        resp = session.get(f'{self.url}/api/backup', timeout=REQ_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on backup load', status)
        self.c.assert_eq(data.get('ok'), True, "Can't load backup", status)
        backup = data.get('backup')
        self.c.assert_eq(type(backup), dict, 'Invalid backup', status)
        return backup

    def probe_import(self, session: requests.Session, status: Status):
        # We deliberately do NOT test a *successful* import here. A real import
        # needs the box to fetch a valid export over the network, and the only
        # such source in a round is the box's own public /export - which the box
        # can only reach if the game network does NAT hairpin (routes the box's
        # own public IP back to itself). Many setups don't, so relying on it
        # would MUMBLE every round for a perfectly healthy service.
        #
        # Instead we verify the endpoint is present and degrades gracefully on
        # an unreachable source: it must stay up, require the session, and
        # answer with well-formed JSON rather than a 404/500. That catches a
        # removed or crashing /api/import while staying fair to any real SSRF
        # fix (which still returns a clean error for this host).
        url = 'http://import-probe.invalid/history.json'
        resp = session.post(f'{self.url}/api/import', json={'url': url}, timeout=IMPORT_TIMEOUT)
        data = self.c.get_json(resp, 'Invalid response on import', status)
        self.c.assert_eq(type(data.get('ok')), bool, 'Import endpoint misbehaving', status)
