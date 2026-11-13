"""Offline tests for ClipSend (no server needed). Run: pytest tests/"""
import base64
import os
import subprocess
import sys
import threading
import time
import zlib

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import clipsendx as cs  # noqa: E402

MB = 5 * 1024 * 1024
BASE = {'v': 2, 'from': 'a', 'to': 'b'}
PLAIN, ENC, ENC2 = cs.Crypto(''), cs.Crypto('correct horse'), cs.Crypto('wrong horse')


def roundtrip(msg, sender=PLAIN, receiver=PLAIN, cap=MB):
    msg = {**BASE, 'ts': time.time(), **msg}
    return cs.decode_message(cs.encode_message(msg, sender, cap), receiver, cap, 'b')


@pytest.fixture(scope='session')
def qapp():
    app = cs.QtWidgets.QApplication.instance() or cs.QtWidgets.QApplication([])
    yield app
    # the offscreen platform segfaults at exit while it still owns a QMimeData
    app.clipboard().clear()


# ---------------------------------------------------------------- codec
def test_text_roundtrip_strips_nul():
    assert roundtrip({'kind': 'text', 'text': 'hällo\x00 wörld ✓'})['text'] == 'hällo wörld ✓'


def test_encrypted_roundtrip():
    assert roundtrip({'kind': 'text', 'text': 'secret'}, ENC, ENC)['text'] == 'secret'


def test_image_roundtrip():
    png = b'\x89PNG\r\n\x1a\n' + os.urandom(1000)
    r = roundtrip({'kind': 'image', 'mime': 'image/png', 'data': base64.b64encode(png).decode()})
    assert r['data'] == png


@pytest.mark.parametrize('msg,sender,receiver', [
    ({'kind': 'text', 'text': 'x'}, ENC, ENC2),                      # wrong passphrase
    ({'kind': 'text', 'text': 'x'}, PLAIN, ENC),                     # unencrypted although passphrase set
    ({'kind': 'text', 'text': 'x'}, ENC, PLAIN),                     # encrypted, no passphrase
    ({'kind': 'text', 'text': 'x', 'to': 'c'}, PLAIN, PLAIN),        # not for me
    ({'kind': 'text', 'text': 'x', 'from': 'b'}, PLAIN, PLAIN),      # from myself
    ({'kind': 'text', 'text': 'x', 'from': '../x'}, PLAIN, PLAIN),   # bad sender
    ({'kind': 'exec', 'cmd': 'rm -rf ~'}, PLAIN, PLAIN),             # unknown kind
    ({'kind': 'image', 'mime': 'image/svg+xml', 'data': 'PHN2Zz4='}, PLAIN, PLAIN),
    ({'kind': 'image', 'mime': 'image/png', 'data': base64.b64encode(b'MZ\x90\x00').decode()}, PLAIN, PLAIN),
])
def test_rejections(msg, sender, receiver):
    with pytest.raises(cs.Rejected):
        roundtrip(msg, sender, receiver)


def test_text_over_limit_rejected():
    with pytest.raises(cs.Rejected):
        roundtrip({'kind': 'text', 'text': 'x' * 2000}, cap=1000)


def test_tampered_ciphertext_rejected():
    blob = bytearray(cs.encode_message({**BASE, 'ts': time.time(), 'kind': 'text', 'text': 'x'}, ENC, MB))
    blob[-1] ^= 1
    with pytest.raises(cs.Rejected):
        cs.decode_message(bytes(blob), ENC, MB, 'b')


def test_zip_bomb_rejected():
    bomb = cs.MAGIC_PLAIN + zlib.compress(b'{"v":2,"text":"' + b'0' * 50_000_000 + b'"}', 9)
    assert len(bomb) < 100_000
    with pytest.raises(cs.Rejected):
        cs.decode_message(bomb, PLAIN, MB, 'b')


@pytest.mark.parametrize('path', ['../../etc/passwd', '/etc/passwd', 'a/../../b', '..', 'a/./..', ''])
def test_path_traversal_rejected(path):
    with pytest.raises(cs.Rejected):
        roundtrip({'kind': 'files', 'files': [{'path': path, 'data': ''}]})


@pytest.mark.parametrize('name,expected', [
    ('CON', '_CON'), ('nul.txt', '_nul.txt'), ('com1', '_com1'), ('LPT9.log', '_LPT9.log'),
    ('file.txt:Zone.Identifier', 'file.txt_Zone.Identifier'), ('a<b>c|d?e*f"g', 'a_b_c_d_e_f_g'),
    ('trailing. . ', 'trailing'), ('console.txt', 'console.txt'), ('normal name.pdf', 'normal name.pdf'),
])
def test_windows_name_sanitizing(name, expected):
    assert cs.win_safe_component(name) == expected


# ---------------------------------------------------------------- files
def test_collect_and_write_files(tmp_path):
    src = tmp_path / 'src'
    (src / 'sub' / 'deeper').mkdir(parents=True)
    (src / 'a.txt').write_text('A')
    binary = bytes(range(256)) * 10 + b'\r\n\n\r\x1a'          # catches text-mode writes on Windows
    (src / 'sub' / 'deeper' / 'b.bin').write_bytes(binary)
    (tmp_path / 'single.bin').write_bytes(b'\x01' * 1000)
    skipped_expected = 0
    if hasattr(os, 'symlink'):
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

    evil = [{'path': 'evil‮txt.exe', 'data': ''}, {'path': 'CON', 'data': 'eA=='}]
    r = roundtrip({'kind': 'files', 'files': files + evil})
    dest, top, written = cs.write_received_files(r['files'], str(tmp_path / 'dl'), 'a')
    names = sorted(os.path.relpath(os.path.join(d, f), dest).replace(os.sep, '/')
                   for d, _, fs in os.walk(dest) for f in fs)
    assert 'src/sub/deeper/b.bin' in names and 'single (2).bin' in names and 'eviltxt.exe' in names
    assert ('_CON' if cs.WINDOWS else 'CON') in names
    assert open(os.path.join(dest, 'src', 'sub', 'deeper', 'b.bin'), 'rb').read() == binary
    assert written == total + 1
    if not cs.WINDOWS:
        for d, _, fs in os.walk(dest):
            for f in fs:
                assert not os.stat(os.path.join(d, f)).st_mode & 0o111, 'received file is executable'
    else:
        zone = open(os.path.join(dest, 'single.bin') + ':Zone.Identifier').read()
        assert 'ZoneId=3' in zone


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
        script = os.path.join(os.path.dirname(__file__), '..', 'clipsendx.py')
        proc = subprocess.Popen([sys.executable, script, '--send'])
        end = time.time() + 30
        while (proc.poll() is None or not got) and time.time() < end:
            qapp.processEvents()
            time.sleep(0.02)
        assert proc.returncode == 0
        assert got == ['send']
        # unknown commands are refused (again from a separate process: a QLocalSocket made in
        # a Python thread without event loop leaves dangling Qt objects on Windows)
        code = ('import sys; sys.path.insert(0, sys.argv[1]); import clipsendx; '
                'sys.exit(0 if clipsendx.send_command("rm -rf") is False else 3)')
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
def test_windows_lock(tmp_path):
    fd = cs.acquire_lock()
    assert fd is not None
    try:
        assert cs.acquire_lock() is None
    finally:
        os.close(fd)


@pytest.mark.skipif(not (cs.WINDOWS and os.environ.get('CI')), reason='modifies HKCU/Start Menu: CI only')
def test_windows_install_uninstall(monkeypatch, tmp_path):
    winreg = cs.winreg
    monkeypatch.setattr(cs, 'INSTALL_DIR', str(tmp_path / 'Programs' / 'ClipSend'))
    argv = cs.win_install(start=False)
    assert os.path.exists(os.path.join(cs.INSTALL_DIR, 'clipsendx.py'))
    assert os.path.exists(cs.start_menu_lnk())
    assert cs.get_autostart()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cs.RUN_KEY) as k:
        assert winreg.QueryValueEx(k, 'ClipSend')[0] == cs.quote_argv(argv)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cs.UNINSTALL_KEY) as k:
        assert winreg.QueryValueEx(k, 'UninstallString')[0].endswith('--uninstall')
    cs.win_uninstall()
    assert not cs.get_autostart()
    assert not os.path.exists(cs.start_menu_lnk())
    assert not os.path.exists(cs.INSTALL_DIR)


# ---------------------------------------------------------------- connection state
class FakeDav:
    """Stands in for WebDav: fails while `down` is set."""
    def __init__(self):
        self.down = False
        self.resets = 0
        self.puts = []

    def _check(self):
        if self.down:
            raise ConnectionError('network is down')

    def makedirs(self, path):
        self._check()

    def etag(self, path):
        self._check()
        return '"e1"'

    def listdir(self, path):
        self._check()
        return []

    def put(self, path, data):
        self._check()
        self.puts.append(path)

    def reset(self):
        self.resets += 1


class Recorder(cs.QtCore.QObject):
    """QObject receiver like TrayApp (a bare list.append as slot crashes PySide6 on Windows)."""
    def __init__(self):
        super().__init__()
        self.states = []

    def on_status(self, s):
        self.states.append(s)


def make_engine(**over):
    cfg = {**cs.DEFAULTS, 'server_url': 'https://cloud.example.com', 'user': 'u', 'app_password': 'p',
           'device_name': 'me', 'use_push': False, 'poll_interval': 0.05, **over}
    eng = cs.Engine(cfg)
    eng.dav = FakeDav()
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
        eng.dav.down = True
        assert wait_until(lambda: states[-1].startswith('offline'))
        assert eng.dav.resets >= 2                      # broken connections are dropped
        eng.dav.down = False
        eng.wake()
        assert wait_until(lambda: states[-1] == 'connected', timeout=5)
        assert states == ['connected', states[1], 'connected']   # no flapping, no duplicates
    finally:
        eng.stop()


def test_single_glitch_does_not_flash_offline(qapp):
    eng, states = make_engine()
    calls = []
    real = eng.dav.etag

    def flaky(path):
        calls.append(1)
        if len(calls) == 3:
            raise ConnectionError('stale keep-alive connection')
        return real(path)
    eng.dav.etag = flaky
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
    assert len(eng.dav.puts) == 1


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
