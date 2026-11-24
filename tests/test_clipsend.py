"""Offline tests for ClipSend (no server needed). Run: pytest tests/"""
import base64
import json
import os
import subprocess
import sys
import threading
import time
import zlib

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import clipsend as cs  # noqa: E402

MB = 5 * 1024 * 1024
BASE = {'v': 3, 'from': 'a', 'to': 'b'}
KEY_A, KEY_B, KEY_EVIL = cs.DeviceKey.generate(), cs.DeviceKey.generate(), cs.DeviceKey.generate()


class MemTrust:
    """TrustStore without a file."""
    def __init__(self, d=None):
        self.d = dict(d or {})

    def get(self, dev):
        return self.d.get(dev)

    def devices(self):
        return sorted(self.d)

    def set(self, dev, peer):
        self.d[dev] = peer

    def remove(self, dev):
        self.d.pop(dev, None)


TRUST_B = MemTrust({'a': KEY_A.public})          # b has confirmed a


def roundtrip(msg, sender_key=KEY_A, recipient_pub=KEY_B.public, receiver_key=KEY_B, trust=TRUST_B, cap=MB):
    msg = {**BASE, 'ts': time.time(), **msg}
    blob = cs.encode_message(msg, sender_key, recipient_pub, cap)
    return cs.decode_message(blob, receiver_key, trust, cap, 'b')


@pytest.fixture(scope='session')
def qapp():
    app = cs.QtWidgets.QApplication.instance() or cs.QtWidgets.QApplication([])
    yield app
    # the offscreen platform segfaults at exit while it still owns a QMimeData
    app.clipboard().clear()


# ---------------------------------------------------------------- codec / encryption
def test_text_roundtrip_strips_nul():
    assert roundtrip({'kind': 'text', 'text': 'hällo\x00 wörld ✓'})['text'] == 'hällo wörld ✓'


def test_image_roundtrip():
    png = b'\x89PNG\r\n\x1a\n' + os.urandom(1000)
    r = roundtrip({'kind': 'image', 'mime': 'image/png', 'data': base64.b64encode(png).decode()})
    assert r['data'] == png


def test_ciphertext_hides_content():
    blob = cs.encode_message({**BASE, 'ts': time.time(), 'kind': 'text', 'text': 'top secret ' * 20},
                             KEY_A, KEY_B.public, MB)
    assert b'secret' not in blob and blob.startswith(cs.MAGIC)


@pytest.mark.parametrize('kw', [
    dict(trust=MemTrust()),                                            # sender not confirmed
    dict(trust=MemTrust({'a': KEY_EVIL.public})),                      # confirmed key differs
    dict(sender_key=KEY_EVIL),                                         # forged: signed with another key
    dict(recipient_pub=KEY_EVIL.public),                               # encrypted for another key
    dict(receiver_key=KEY_EVIL),                                       # wrong private key
])
def test_key_rejections(kw):
    with pytest.raises(cs.Rejected):
        roundtrip({'kind': 'text', 'text': 'x'}, **kw)


@pytest.mark.parametrize('msg', [
    {'kind': 'text', 'text': 'x', 'to': 'c'},                            # not for me
    {'kind': 'text', 'text': 'x', 'from': 'b'},                          # from myself
    {'kind': 'text', 'text': 'x', 'from': '../x'},                       # bad sender
    {'kind': 'other', 'x': 'y'},                                         # unknown kind
    {'kind': 'image', 'mime': 'image/svg+xml', 'data': 'PHN2Zz4='},
    {'kind': 'image', 'mime': 'image/png', 'data': base64.b64encode(b'GIF89a\x01\x00').decode()},
])
def test_rejections(msg):
    with pytest.raises(cs.Rejected):
        roundtrip(msg)


def test_text_over_limit_rejected():
    with pytest.raises(cs.Rejected):
        roundtrip({'kind': 'text', 'text': 'x' * 2000}, cap=1000)


def test_tampered_item_rejected():
    blob = cs.encode_message({**BASE, 'ts': time.time(), 'kind': 'text', 'text': 'x'}, KEY_A, KEY_B.public, MB)
    for pos in (len(cs.MAGIC) + 5, -70, -1):              # header, ciphertext, signature
        bad = bytearray(blob)
        bad[pos] ^= 1
        with pytest.raises(cs.Rejected):
            cs.decode_message(bytes(bad), KEY_B, TRUST_B, MB, 'b')


def test_foreign_or_truncated_items_rejected():
    for blob in (b'plain\n' + zlib.compress(b'{}'), b'', cs.MAGIC + b'\x00'):
        with pytest.raises(cs.Rejected):
            cs.decode_message(blob, KEY_B, TRUST_B, MB, 'b')


def test_zip_bomb_rejected():
    bomb = zlib.compress(b'{"v":3,"text":"' + b'0' * 50_000_000 + b'"}', 9)
    assert len(bomb) < 100_000
    blob = cs.seal(bomb, KEY_A, 'a', 'b', KEY_B.public)
    with pytest.raises(cs.Rejected):
        cs.decode_message(blob, KEY_B, TRUST_B, MB, 'b')


@pytest.mark.parametrize('path', ['../../etc/passwd', '/etc/passwd', 'a/../../b', '..', 'a/./..', ''])
def test_path_traversal_rejected(path):
    with pytest.raises(cs.Rejected):
        roundtrip({'kind': 'files', 'files': [{'path': path, 'data': ''}]})


# ---------------------------------------------------------------- keys, key file, trust
def test_bundle_is_self_signed_and_bound_to_the_device():
    bundle = KEY_A.bundle('laptop')
    assert cs.parse_bundle(bundle, 'laptop') == KEY_A.public
    with pytest.raises(cs.Rejected):
        cs.parse_bundle(bundle, 'desktop')                               # replayed under another name
    d = json.loads(bundle)
    d['enc'] = json.loads(KEY_EVIL.bundle('laptop'))['enc']               # swapped encryption key
    with pytest.raises(cs.Rejected):
        cs.parse_bundle(json.dumps(d), 'laptop')
    for junk in ('', '{}', 'x' * 5000, json.dumps({'v': 1, 'device': 'laptop'})):
        with pytest.raises(cs.Rejected):
            cs.parse_bundle(junk, 'laptop')


def test_fingerprint_format():
    fp = KEY_A.public.fingerprint
    assert len(fp.split()) == 8 and all(len(g) == 4 for g in fp.split())
    assert fp != KEY_B.public.fingerprint


def test_key_file_roundtrip_and_wrong_password(tmp_path):
    path = str(tmp_path / 'device_key.json')
    cs.save_device_key(KEY_A, 'correct horse', path)
    if not cs.WINDOWS:
        assert os.stat(path).st_mode & 0o077 == 0
    assert b'correct' not in open(path, 'rb').read()
    assert cs.load_device_key('correct horse', path).public == KEY_A.public
    with pytest.raises(ValueError):
        cs.load_device_key('wrong horse', path)


def test_trust_store_persists(tmp_path):
    path = str(tmp_path / 'trusted.json')
    t = cs.TrustStore(path)
    t.set('laptop', KEY_A.public)
    assert cs.TrustStore(path).get('laptop') == KEY_A.public
    t.remove('laptop')
    assert cs.TrustStore(path).get('laptop') is None


def test_device_status_and_pending():
    trust = MemTrust({'a': KEY_A.public, 'c': KEY_B.public})
    peers = {'a': KEY_A.public, 'c': KEY_EVIL.public, 'd': KEY_B.public, 'e': None}
    assert cs.device_status('a', peers['a'], trust.get('a')) == ('confirmed', True)
    assert cs.device_status('c', peers['c'], trust.get('c'))[1] is False       # key changed: blocked
    assert cs.device_status('d', peers['d'], None)[1] is False
    assert cs.pending_devices(peers, trust) == ['c', 'd']


def test_keyring_password_flow(monkeypatch, tmp_path, qapp):
    """New key: password goes to the keyring; next start unlocks silently with it."""
    store = {}
    monkeypatch.setattr(cs, 'KEY_FILE', str(tmp_path / 'device_key.json'))
    monkeypatch.setattr(cs, 'keyring_available', lambda: True)
    monkeypatch.setattr(cs, 'keyring_set', lambda pw: store.update(pw=pw) or True)
    monkeypatch.setattr(cs, 'keyring_get', lambda: store.get('pw'))
    monkeypatch.setattr(cs, 'ask_password', lambda *a: pytest.fail('must not ask for a password'))
    app = cs.TrayApp.__new__(cs.TrayApp)
    app.cfg = {**cs.DEFAULTS, 'device_name': 'me'}
    app.my_key = None
    assert app._unlock() and app.my_key is not None
    first = app.my_key.public
    app.my_key = None
    assert app._unlock() and app.my_key.public == first


# ---------------------------------------------------------------- files
@pytest.mark.parametrize('name,expected', [
    ('CON', '_CON'), ('nul.txt', '_nul.txt'), ('com1', '_com1'), ('LPT9.log', '_LPT9.log'),
    ('file.txt:Zone.Identifier', 'file.txt_Zone.Identifier'), ('a<b>c|d?e*f"g', 'a_b_c_d_e_f_g'),
    ('trailing. . ', 'trailing'), ('console.txt', 'console.txt'), ('normal name.pdf', 'normal name.pdf'),
])
def test_windows_name_sanitizing(name, expected):
    assert cs.win_safe_component(name) == expected


def test_collect_and_write_files(tmp_path):
    src = tmp_path / 'src'
    (src / 'sub' / 'deeper').mkdir(parents=True)
    (src / 'a.txt').write_text('A')
    binary = bytes(range(256)) * 10 + b'\r\n\n\r\x1a'          # catches text-mode writes on Windows
    (src / 'sub' / 'deeper' / 'b.bin').write_bytes(binary)
    (tmp_path / 'single.bin').write_bytes(b'\x01' * 1000)
    skipped_expected = 0
    try:
        os.symlink(tmp_path / 'single.bin', src / 'sub' / 'link')
        skipped_expected = 1
    except OSError:                     # Windows without symlink privilege
        pass
    files, total, skipped = cs.collect_files([str(src), str(tmp_path / 'single.bin'),
                                              str(tmp_path / 'single.bin')], MB)
    assert skipped == skipped_expected
    with pytest.raises(cs.Rejected):
        cs.collect_files([str(tmp_path / 'single.bin')], 500)

    odd = [{'path': 'name‮gnp.txt', 'data': ''}, {'path': 'CON', 'data': 'eA=='}]
    r = roundtrip({'kind': 'files', 'files': files + odd})
    dest, top, written = cs.write_received_files(r['files'], str(tmp_path / 'dl'), 'a')
    names = sorted(os.path.relpath(os.path.join(d, f), dest).replace(os.sep, '/')
                   for d, _, fs in os.walk(dest) for f in fs)
    assert 'src/sub/deeper/b.bin' in names and 'single (2).bin' in names and 'namegnp.txt' in names
    assert ('_CON' if cs.WINDOWS else 'CON') in names
    assert open(os.path.join(dest, 'src', 'sub', 'deeper', 'b.bin'), 'rb').read() == binary
    assert written == total + 1
    if cs.WINDOWS:
        assert 'ZoneId=3' in open(os.path.join(dest, 'single.bin') + ':Zone.Identifier').read()
    else:
        for d, _, fs in os.walk(dest):
            for f in fs:
                assert not os.stat(os.path.join(d, f)).st_mode & 0o111, 'received file is executable'


# ---------------------------------------------------------------- Qt / platform
def test_qt_clipboard_roundtrip(qapp, tmp_path):
    if cs.is_wayland():
        pytest.skip('Wayland uses wl-clipboard')
    cb = cs.Clipboard()
    cb.set_text('hello')
    assert cb.read(1000) == {'kind': 'text', 'text': 'hello'}
    f = tmp_path / 'x.txt'
    f.write_text('x')
    cb.set_files([str(f)])
    r = cb.read(1000)
    assert r['kind'] == 'files' and os.path.samefile(r['paths'][0], f)
    img = cs.QtGui.QImage(8, 8, cs.QtGui.QImage.Format.Format_RGB32)
    img.fill(0xff0000)
    buf = cs.QtCore.QBuffer()
    buf.open(cs.QtCore.QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, 'PNG')
    cb.set_image('image/png', bytes(buf.data()))
    r = cb.read(100_000)
    assert r['kind'] == 'image' and r['data'].startswith(b'\x89PNG')
    cb.set_text('x' * 2000)
    with pytest.raises(cs.Rejected):
        cb.read(1000)


def test_control_channel(qapp, tmp_path, monkeypatch):
    if not cs.WINDOWS:
        monkeypatch.setenv('XDG_RUNTIME_DIR', '/tmp' if len(str(tmp_path)) > 80 else str(tmp_path))
    server = cs.WinControlServer() if cs.WINDOWS else cs.ControlServer()
    got = []
    server.command.connect(got.append)
    server.start()
    try:
        # the client side runs as a separate process, exactly like `clipsend --send`
        script = os.path.join(os.path.dirname(__file__), '..', 'clipsend.py')
        proc = subprocess.Popen([sys.executable, script, '--send'])
        end = time.time() + 30
        while (proc.poll() is None or not got) and time.time() < end:
            qapp.processEvents()
            time.sleep(0.02)
        assert proc.returncode == 0
        assert got == ['send']
        # unknown commands are refused
        code = ('import sys; sys.path.insert(0, sys.argv[1]); import clipsend; '
                'sys.exit(0 if clipsend.send_command("bogus") is False else 3)')
        proc = subprocess.Popen([sys.executable, '-c', code, os.path.dirname(script)])
        while proc.poll() is None and time.time() < end:
            qapp.processEvents()
            time.sleep(0.02)
        assert proc.returncode == 0 and got == ['send']
    finally:
        server.close()
        server.deleteLater()
        qapp.processEvents()


@pytest.mark.skipif(not cs.WINDOWS, reason='Windows only')
def test_windows_lock():
    fd = cs.acquire_lock()
    assert fd is not None
    try:
        assert cs.acquire_lock() is None
    finally:
        os.close(fd)


def test_autostart_launcher(tmp_path, monkeypatch):
    monkeypatch.setenv('APPDATA', str(tmp_path))
    path = cs.startup_launcher_path()
    os.makedirs(os.path.dirname(path))
    cs.set_autostart(True)
    code = open(path, encoding='utf-8').read()
    compile(code, path, 'exec')
    assert repr(os.path.abspath(cs.__file__)) in code and 'runpy.run_path' in code
    cs.set_autostart(False)
    assert not os.path.exists(path)


# ---------------------------------------------------------------- connection state
class FakeTransport:
    """In-memory stand-in for a transport (Nextcloud / Firebase); fails while `down` is set."""
    kind = 'fake'

    def __init__(self):
        self.down = False
        self.resets = 0
        self.inbox = {}          # device -> {name: blob}
        self.registered = set()
        self.deleted = []
        self.trash_purges = 0
        self.keys = {}

    def _check(self):
        if self.down:
            raise ConnectionError('network is down')

    def register(self, me, bundle):
        self._check()
        self.registered.add(me)
        self.inbox.setdefault(me, {})
        self.keys[me] = bundle

    def device_keys(self):
        self._check()
        return dict(self.keys)

    def inbox_version(self, me):
        self._check()
        return ','.join(sorted(self.inbox.get(me, {})))

    def list_items(self, device):
        self._check()
        return [{'name': n, 'size': len(b)} for n, b in self.inbox.get(device, {}).items()]

    def fetch(self, device, name, cap):
        self._check()
        return self.inbox.get(device, {}).get(name)

    def put(self, device, name, blob):
        self._check()
        self.inbox.setdefault(device, {})[name] = blob

    def delete(self, device, name):
        self._check()
        self.inbox.get(device, {}).pop(name, None)
        self.deleted.append((device, name))

    def devices(self):
        self._check()
        return sorted(self.registered | set(self.inbox))

    def purge_trash(self):
        self.trash_purges += 1

    def reset(self):
        self.resets += 1

    def watch(self, me, stop):
        raise cs.PushUnavailable('fake')

    def close_watch(self):
        pass


class Recorder(cs.QtCore.QObject):
    """QObject receiver, like TrayApp."""
    def __init__(self):
        super().__init__()
        self.states = []

    def on_status(self, s):
        self.states.append(s)


KEY_ME, KEY_OTHER = cs.DeviceKey.generate(), cs.DeviceKey.generate()


_ENGINES = []


@pytest.fixture(autouse=True)
def _stop_engines():
    """Every engine is stopped and its threads have ended before the next test starts."""
    yield
    while _ENGINES:
        eng = _ENGINES.pop()
        eng.stop()
        assert eng.join(15), 'engine threads did not end'
    cs._RETIRED.clear()


def make_engine(**over):
    cfg = {**cs.DEFAULTS, 'server_url': 'https://cloud.example.com', 'user': 'u', 'app_password': 'p',
           'device_name': 'me', 'use_push': False, 'poll_interval': 0.05, **over}
    eng = cs.Engine(cfg, KEY_ME, MemTrust({'other': KEY_OTHER.public}))
    eng.t = FakeTransport()
    _ENGINES.append(eng)
    rec = Recorder()
    eng.status.connect(rec.on_status)
    eng._rec = rec                                 # keep alive
    return eng, rec.states


def wait_until(cond, timeout=10):
    app = cs.QtWidgets.QApplication.instance()     # cross-thread signals are queued
    end = time.time() + timeout
    while not cond() and time.time() < end:
        app.processEvents()
        time.sleep(0.02)
    app.processEvents()
    return cond()


def test_state_recovers_after_outage(qapp):
    eng, states = make_engine()
    eng.start()
    try:
        assert wait_until(lambda: states[-1:] == ['connected'])
        eng.t.down = True
        assert wait_until(lambda: states[-1].startswith('offline'))
        assert eng.t.resets >= 2                        # broken connections are dropped
        eng.t.down = False
        eng.wake()
        assert wait_until(lambda: states[-1] == 'connected', timeout=5)
        assert states == ['connected', states[1], 'connected']   # no flapping, no duplicates
    finally:
        eng.stop()


def test_single_glitch_does_not_flash_offline(qapp):
    eng, states = make_engine()
    calls = []
    real = eng.t.inbox_version

    def flaky(path):
        calls.append(1)
        if len(calls) == 3:
            raise ConnectionError('stale keep-alive connection')
        return real(path)
    eng.t.inbox_version = flaky
    eng.start()
    try:
        assert wait_until(lambda: len(calls) > 6)
        assert states == ['connected']
    finally:
        eng.stop()


def test_successful_send_marks_connected(qapp):
    eng, states = make_engine(receive_enabled=False)
    eng._set_status('offline (ConnectionError), retrying')
    eng.send_async({'kind': 'text', 'text': 'hi'}, 'other')
    assert wait_until(lambda: states[-1:] == ['connected'])
    assert len(eng.t.inbox['other']) == 1


def test_sleep_detects_resume(monkeypatch):
    eng, _ = make_engine()
    real = time.time
    jump = {'t': 0.0}
    monkeypatch.setattr(cs.time, 'time', lambda: real() + jump['t'])
    threading.Timer(0.3, lambda: jump.update(t=3600.0)).start()    # "slept" for an hour
    t0 = time.monotonic()
    assert eng._sleep(60) is True
    assert time.monotonic() - t0 < 5


# ---------------------------------------------------------------- clipboard + selection
def test_wayland_writes_clipboard_and_selection(monkeypatch):
    calls = []

    class FakePopen:
        returncode = 0

        def __init__(self, args, **kw):
            calls.append(args)

        def communicate(self, data, timeout=None):
            pass
    monkeypatch.setattr(cs.subprocess, 'Popen', FakePopen)
    cb = cs.Clipboard()
    cb.wl = True
    cb.selection = True
    cb.set_text('hi')
    assert ['wl-copy', '--type', 'text/plain;charset=utf-8', '--primary'] in calls
    assert ['wl-copy', '--type', 'text/plain;charset=utf-8'] in calls
    calls.clear()
    cb.selection = False
    cb.set_files(['/tmp/x'])
    assert calls == [['wl-copy', '--type', 'text/uri-list']]


def test_qt_writes_clipboard_and_selection(qapp):
    modes = []
    class FakeCb:
        def supportsSelection(self):
            return True

        def setMimeData(self, md, mode):
            modes.append((mode, md.text()))
    cb = cs.Clipboard()
    cb._qt_clipboard = FakeCb                     # instance attribute: Qt classes stay untouched
    cb.wl = False
    cb.selection = True
    cb.set_text('hi')
    Mode = cs.QtGui.QClipboard.Mode
    assert modes == [(Mode.Selection, 'hi'), (Mode.Clipboard, 'hi')]


def test_certificate_error_pauses_polling(qapp):
    import requests
    eng, states = make_engine()
    calls = []

    def intercepted(path):
        calls.append(1)
        raise requests.exceptions.SSLError('certificate verify failed')
    eng.t.inbox_version = intercepted
    eng.start()
    try:
        assert wait_until(lambda: states[-1:] == ['certificate error'])
        time.sleep(1.0)
        assert len(calls) == 1                     # no retry storm against the firewall
    finally:
        eng.stop()


# ---------------------------------------------------------------- delivery and cleanup
class MsgRecorder(cs.QtCore.QObject):
    def __init__(self):
        super().__init__()
        self.msgs = []

    def on_msg(self, m):
        self.msgs.append(m)


def item(sender, to, text, age_s=0.0):
    ts = time.time() - age_s
    msg = {'v': 3, 'from': sender, 'to': to, 'kind': 'text', 'text': text, 'ts': ts, 'id': os.urandom(16).hex()}
    key = {'other': KEY_OTHER, 'me': KEY_ME}[sender]
    peer = {'other': KEY_OTHER, 'me': KEY_ME}.get(to, KEY_OTHER).public
    return f'{int(ts * 1000):013d}-{msg["id"]}.clipsend', cs.encode_message(msg, key, peer, MB)


def test_item_is_deleted_after_successful_read(qapp):
    eng, states = make_engine()
    rec = MsgRecorder()
    eng.received.connect(rec.on_msg)
    name, blob = item('other', 'me', 'hello')
    eng.t.inbox['me'] = {name: blob}
    eng.start()
    try:
        assert wait_until(lambda: rec.msgs)
        assert rec.msgs[0]['text'] == 'hello'
        assert eng.t.inbox['me'] == {} and ('me', name) in eng.t.deleted
    finally:
        eng.stop()


def test_sweep_deletes_expired_items_in_all_inboxes(qapp):
    eng, _ = make_engine(max_age_min=5)
    old_mine, b1 = item('other', 'me', 'x', age_s=301)
    old_other, b2 = item('me', 'laptop', 'y', age_s=600)     # for a device that is switched off
    fresh, b3 = item('me', 'laptop', 'z', age_s=10)
    eng.t.inbox = {'me': {old_mine: b1}, 'laptop': {old_other: b2, fresh: b3}}
    eng._sweep()
    assert eng.t.inbox == {'me': {}, 'laptop': {fresh: b3}}
    assert eng.t.trash_purges == 1


def test_default_max_age_is_five_minutes():
    assert cs.DEFAULTS['max_age_min'] == 5


# ---------------------------------------------------------------- Firebase transport
def test_firebase_url_and_key_checks():
    ok = 'https://proj-default-rtdb.europe-west1.firebasedatabase.app'
    assert cs.check_firebase_url(ok + '/') == ok
    assert cs.check_firebase_url('https://proj-default-rtdb.firebaseio.com') == 'https://proj-default-rtdb.firebaseio.com'
    for bad in ('http://proj.firebaseio.com', 'https://evil.example.com', 'https://x.firebaseio.com.evil.com',
                'https://proj.firebaseio.com/path', 'https://proj.firebaseio.com:8443', ''):
        with pytest.raises(ValueError):
            cs.check_firebase_url(bad)
    with pytest.raises(ValueError):
        cs.check_firebase_api_key('short')
    assert cs.fb_unkey(cs.fb_key('my.host-1')) == 'my.host-1' and '.' not in cs.fb_key('my.host-1')


class FakeResp:
    def __init__(self, status=200, body=b'null', lines=()):
        self.status_code = status
        self.body = body
        self.lines = list(lines)

    def iter_content(self, n):
        yield self.body

    def iter_lines(self, chunk_size=1):
        yield from self.lines

    def close(self):
        pass


class FakeSession:
    def __init__(self, responder):
        self.calls = []
        self.responder = responder

    def request(self, method, url, params=None, **kw):
        self.calls.append((method, url, params, kw.get('json')))
        return self.responder(method, url, params, kw)

    def close(self):
        pass


class FakeAuth:
    def __init__(self):
        self.invalidated = 0

    def token(self):
        return 'TOKEN'

    def invalidate(self):
        self.invalidated += 1


def firebase(responder):
    cfg = {**cs.DEFAULTS, 'backend': 'firebase', 'fb_db_url': 'https://p-default-rtdb.firebaseio.com',
           'fb_api_key': 'A' * 39, 'fb_uid': 'uid123', 'fb_refresh_token': 'rt'}
    t = cs.make_transport(cfg)
    assert isinstance(t, cs.FirebaseTransport)
    t.auth = FakeAuth()
    sess = FakeSession(responder)
    t._local.s = sess
    return t, sess


def test_firebase_put_fetch_delete_and_signal():
    store = {}

    def responder(method, url, params, kw):
        path = url.split('firebaseio.com', 1)[1]
        if method == 'PUT':
            store[path] = kw['json']
            return FakeResp()
        if method == 'DELETE':
            store.pop(path, None)
            return FakeResp()
        if params.get('shallow'):
            prefix = path[:-len('.json')] + '/'
            keys = {k[len(prefix):].split('/')[0][:-len('.json')]: True for k in store if k.startswith(prefix)}
            return FakeResp(body=json.dumps(keys or None).encode())
        return FakeResp(body=json.dumps(store.get(path)).encode())

    t, sess = firebase(responder)
    name, blob = item('me', 'lap.top', 'hi')
    t.put('lap.top', name, blob)
    key = name[:-len('.clipsend')]
    assert f'/users/uid123/inbox/lap,top/{key}.json' in store            # '.' escaped in keys
    assert '/users/uid123/signal/lap,top.json' in store                 # receiver gets woken up
    assert all(c[2]['auth'] == 'TOKEN' for c in sess.calls)
    assert [e['name'] for e in t.list_items('lap.top')] == [name]
    assert t.fetch('lap.top', name, MB) == blob
    t.delete('lap.top', name)
    assert t.fetch('lap.top', name, MB) is None and t.list_items('lap.top') == []
    with pytest.raises(cs.Rejected):
        t.put('lap.top', name, b'x' * (8 * 1024 * 1024))                # over the Firebase value limit


def test_firebase_retries_once_with_fresh_token_then_fails():
    t, sess = firebase(lambda *a: FakeResp(status=401))
    with pytest.raises(cs.AuthError):
        t.devices()
    assert len(sess.calls) == 2 and t.auth.invalidated == 2


def test_firebase_event_stream():
    lines = [b'event: put', b'data: {"path":"/","data":null}', b'',
             b'event: keep-alive', b'data: null', b'',
             b'event: put', b'data: {"path":"/","data":1700000000000}', b'',
             b'event: auth_revoked', b'data: credential is no longer valid', b'']
    t, _ = firebase(lambda *a: FakeResp(lines=lines))
    events = list(t.watch('me', threading.Event()))
    assert events == ['connected', 'change', 'change']
    assert t.auth.invalidated == 1                                       # token renewed on reconnect
    t2, _ = firebase(lambda *a: FakeResp(lines=[b'event: cancel', b'data: null']))
    with pytest.raises(cs.AuthError):
        list(t2.watch('me', threading.Event()))


# ---------------------------------------------------------------- Nextcloud trash bin
def test_nextcloud_trash_purge_only_touches_clipsend_items():
    cfg = {**cs.DEFAULTS, 'server_url': 'https://cloud.example.com', 'user': 'u', 'app_password': 'p'}
    t = cs.make_transport(cfg)
    assert isinstance(t, cs.NextcloudTransport)
    deleted = []
    t.dav.trash_names = lambda: ['1794414209987-' + 'a' * 32 + '.clipsend.d1794414210',
                                 'thesis.pdf.d1794414210', '1794414209987-' + 'a' * 32 + '.clipsend']
    t.dav.trash_delete = deleted.append
    t.purge_trash()
    assert deleted == ['1794414209987-' + 'a' * 32 + '.clipsend.d1794414210']


def test_engine_publishes_key_and_only_sends_to_confirmed_devices(qapp):
    eng, _ = make_engine()
    rec = MsgRecorder()
    eng.error.connect(lambda t, m: rec.on_msg(m))
    eng.t.keys = {'other': KEY_OTHER.bundle('other'), 'stranger': KEY_EVIL.bundle('stranger')}
    eng.start()
    try:
        assert wait_until(lambda: 'me' in eng.t.keys)
        assert cs.parse_bundle(eng.t.keys['me'], 'me') == KEY_ME.public          # own key published
        assert wait_until(lambda: set(eng.peers) == {'other', 'stranger'})
        eng.send_async({'kind': 'text', 'text': 'hi'}, '*')
        assert wait_until(lambda: eng.t.inbox.get('other'))
        assert not eng.t.inbox.get('stranger')                                    # never to unconfirmed
        blob = next(iter(eng.t.inbox['other'].values()))
        assert cs.decode_message(blob, KEY_OTHER, MemTrust({'me': KEY_ME.public}), MB, 'other')['text'] == 'hi'
        eng.t.keys['other'] = KEY_EVIL.bundle('other')                           # key swapped on the server
        eng.refresh_devices()
        eng.send_async({'kind': 'text', 'text': 'again'}, 'other')
        assert wait_until(lambda: any('new key' in m for m in rec.msgs))
        assert len(eng.t.inbox['other']) == 1
    finally:
        eng.stop()


def test_item_from_unconfirmed_device_is_rejected_and_deleted(qapp):
    eng, _ = make_engine()
    rec = MsgRecorder()
    eng.error.connect(lambda t, m: rec.on_msg(m))
    msg = {'v': 3, 'from': 'stranger', 'to': 'me', 'kind': 'text', 'text': 'x', 'ts': time.time(), 'id': 'f' * 32}
    name = f'{int(msg["ts"] * 1000):013d}-{msg["id"]}.clipsend'
    eng.t.inbox['me'] = {name: cs.encode_message(msg, KEY_EVIL, KEY_ME.public, MB)}
    eng.start()
    try:
        assert wait_until(lambda: rec.msgs)
        assert 'not confirmed' in rec.msgs[0] and eng.t.inbox['me'] == {}
    finally:
        eng.stop()


def test_new_device_popup_accept_and_not_now(qapp):
    """A new key opens one popup with both fingerprints; Accept confirms it, Not now asks no more."""
    app = cs.TrayApp.__new__(cs.TrayApp)
    cs.QtCore.QObject.__init__(app)
    app.cfg = {**cs.DEFAULTS, 'device_name': 'me'}
    app.my_key, app.trust, app.engine = KEY_A, MemTrust(), None
    app.peers, app._prompted, app._prompt = {}, set(), None
    app._update_tooltip = lambda: None

    app._on_devices({'laptop': KEY_B.public, 'phone': KEY_EVIL.public})
    box = app._prompt
    assert box is not None and 'laptop' in box.text()
    assert KEY_B.public.fingerprint in box.text() and KEY_A.public.fingerprint in box.text()
    next(b for b in box.buttons() if b.text() == 'Accept').click()
    assert app.trust.get('laptop') == KEY_B.public
    assert wait_until(lambda: app._prompt is not None and 'phone' in app._prompt.text())
    next(b for b in app._prompt.buttons() if b.text() == 'Not now').click()
    assert app.trust.get('phone') is None
    qapp.processEvents()
    app._on_devices(dict(app.peers))                          # same keys again: no new popup
    assert app._prompt is None
    app._on_devices({**app.peers, 'laptop': KEY_EVIL.public})  # changed key: asks again, with a warning
    assert 'CHANGED' in app._prompt.text()
    app._prompt.reject()


def test_no_notification_right_after_a_clipboard_write(qapp):
    """Notification first, then the clipboard write; later ones wait 2 s (else Plasma deadlocks)."""
    calls = []

    class Tray:
        isVisible = staticmethod(lambda: True)
        showMessage = staticmethod(lambda title, *a: calls.append((title, time.monotonic())))

    class Clip:
        set_text = staticmethod(lambda text: calls.append(('clipboard', time.monotonic())))

    app = cs.TrayApp.__new__(cs.TrayApp)
    cs.QtCore.QObject.__init__(app)
    app.cfg, app.tray, app.clip = {**cs.DEFAULTS}, Tray(), Clip()
    app._clip_written, app._start_blink = -1e9, lambda s: None
    app._on_received({'from': 'laptop', 'kind': 'text', 'text': 'hi'})
    assert [c[0] for c in calls] == ['Clipboard received', 'clipboard']
    app.notify('later', 'x')
    assert len(calls) == 2                                      # deferred, not shown yet
    assert wait_until(lambda: len(calls) == 3, timeout=5)
    assert calls[2][1] - calls[1][1] >= 2.0


def test_stopped_engine_stays_referenced_until_its_threads_end(qapp):
    eng, _ = make_engine()
    release = threading.Event()
    eng._spawn(release.wait, 'busy')                # e.g. a request that is still in progress
    eng.stop()
    assert eng in cs._RETIRED
    release.set()
    assert eng.join(5) and not eng.alive()
