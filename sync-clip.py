#!/usr/bin/env python3
import os, sys, time, json, hashlib, tempfile, glob, shutil, subprocess, atexit

# Optional Qt (PyQt5 preferred; fall back to PySide6)
Qt = None
QApp = None
try:
    from PyQt5 import QtWidgets, QtGui, QtCore
    Qt = QtWidgets
    QApp = QtWidgets.QApplication
except Exception:
    try:
        from PySide6 import QtWidgets, QtGui, QtCore
        Qt = QtWidgets
        QApp = QtWidgets.QApplication
    except Exception:
        Qt = None
        QtGui = None
        QtCore = None


    
#%% PATCH DNS
# --- install DNS patch BEFORE importing nc_py_api ---
import socket

# Configure your overrides here
DNS_MAP = {
    "drive.skjerns.de": "91.204.46.106",   # add more host->ip as needed
}

# Keep originals so we can restore later
_ORIG_GETADDRINFO = socket.getaddrinfo
_ORIG_GETHOSTBYNAME_EX = socket.gethostbyname_ex

def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Resolve select hosts to fixed IPs; otherwise defer to system resolver."""
    if host in DNS_MAP:
        ip = DNS_MAP[host]
        # Decide families. Respect caller's family if constrained.
        fams = []
        if family and family != socket.AF_UNSPEC:
            fams = [family]
        else:
            if ":" in ip:
                fams.append(socket.AF_INET6)
            if "." in ip:
                fams.append(socket.AF_INET)
            if not fams:
                fams = [socket.AF_INET]

        results = []
        for fam in fams:
            sockaddr = (ip, port, 0, 0) if fam == socket.AF_INET6 else (ip, port)
            results.append((fam, type or socket.SOCK_STREAM, proto or 0, "", sockaddr))
        return results
    return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)

def _patched_gethostbyname_ex(host):
    """Support legacy lookups used by some libraries."""
    if host in DNS_MAP:
        ip = DNS_MAP[host]
        return (host, [host], [ip])
    return _ORIG_GETHOSTBYNAME_EX(host)

def unpatch_dns():
    """Restore the original socket resolvers."""
    socket.getaddrinfo = _ORIG_GETADDRINFO
    socket.gethostbyname_ex = _ORIG_GETHOSTBYNAME_EX

# Activate patch globally
socket.getaddrinfo = _patched_getaddrinfo
socket.gethostbyname_ex = _patched_gethostbyname_ex
# --- end DNS patch installation ---


# Now import and use nc_py_api; it will inherit the patched resolver
# Nextcloud WebDAV client
from nc_py_api import Nextcloud

# If/when you want to restore system DNS:
# unpatch_dns()

#%%

APP_NAME = 'clip_sync'
STATE_FILE = os.path.join(os.path.expanduser('~'), '.config', 'clip_sync', 'state.json')
LOCK_FILE = os.path.join(os.path.expanduser('~'), '.cache', 'clip_sync', 'instance.lock')

def log(msg):
    """Short stdout log."""
    ts = time.strftime('%H:%M:%S')
    print(f'[{ts}] {msg}', flush=True)

def sha256_text(s):
    return hashlib.sha256(s.encode('utf-8', 'ignore')).hexdigest()

def ensure_dir(p):
    d = os.path.dirname(p)
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)

def atomic_write_json_local(path, obj):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.cliptmp-', dir=d)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False)
            f.write('\n')
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass

def atomic_read_json_local(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def acquire_single_instance():
    ensure_dir(LOCK_FILE)
    try:
        import fcntl
        fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            try: os.close(fd)
            except Exception: pass
            log('another instance running; exiting')
            return None
        try:
            os.ftruncate(fd, 0)
            os.write(fd, str(os.getpid()).encode())
        except Exception:
            pass
        return ('flock', fd)
    except Exception:
        dirlock = LOCK_FILE + '.d'
        try:
            os.makedirs(dirlock)
            with open(os.path.join(dirlock, 'pid'), 'w') as f:
                f.write(str(os.getpid()))
            return ('dir', dirlock)
        except Exception:
            log('another instance running (dirlock); exiting')
            return None

def release_single_instance(token):
    if not token:
        return
    kind, val = token
    if kind == 'flock':
        try: os.close(val)
        except Exception: pass
    elif kind == 'dir':
        try: shutil.rmtree(val, ignore_errors=True)
        except Exception: pass

class Settings:
    """Persistent toggles for Send/Receive/Notifications."""
    def __init__(self, path=STATE_FILE):
        self.path = path
        d = atomic_read_json_local(self.path)
        self.send = bool(d.get('send', True))
        self.receive = bool(d.get('receive', True))
        self.notifications = bool(d.get('notifications', True))
    def save(self):
        atomic_write_json_local(self.path, {
            'send': self.send, 'receive': self.receive, 'notifications': self.notifications
        })

class Clipboard:
    """Clipboard access via wl-clipboard, xclip, or Tk."""
    def __init__(self):
        self.mode = None
        self.tk = None
        if shutil.which('wl-copy') and shutil.which('wl-paste'):
            self.mode = 'wl'
        elif shutil.which('xclip'):
            self.mode = 'xclip'
        else:
            try:
                import tkinter as tk
                self.tk = tk.Tk()
                self.tk.withdraw()
                self.mode = 'tk'
            except Exception:
                self.mode = None

    def get(self):
        if self.mode == 'wl':
            try:
                out = subprocess.run(['wl-paste','--no-newline'], capture_output=True, text=True)
                return out.stdout if out.returncode == 0 else ''
            except Exception:
                return ''
        if self.mode == 'xclip':
            try:
                out = subprocess.run(['xclip','-selection','clipboard','-out'], capture_output=True, text=True)
                return out.stdout if out.returncode == 0 else ''
            except Exception:
                return ''
        if self.mode == 'tk':
            try:
                self.tk.update()
                return self.tk.clipboard_get()
            except Exception:
                return ''
        return ''

    def set(self, text):
        if self.mode == 'wl':
            try:
                p = subprocess.Popen(['wl-copy'], stdin=subprocess.PIPE, text=True)
                p.communicate(text)
                return p.returncode == 0
            except Exception:
                return False
        if self.mode == 'xclip':
            try:
                p = subprocess.Popen(['xclip','-selection','clipboard','-in'], stdin=subprocess.PIPE, text=True)
                p.communicate(text)
                return p.returncode == 0
            except Exception:
                return False
        if self.mode == 'tk':
            try:
                self.tk.clipboard_clear()
                self.tk.clipboard_append(text)
                self.tk.update()
                return True
            except Exception:
                return False
        return False

class Notifier:
    """Tray bubbles or notify-send fallback."""
    def __init__(self, settings, tray_icon=None):
        self.settings = settings
        self.tray_icon = tray_icon
        self.has_notify_send = bool(shutil.which('notify-send'))
    def notify(self, title, message):
        if not self.settings.notifications:
            return
        try:
            if self.tray_icon and Qt and QtWidgets.QSystemTrayIcon.supportsMessages():
                self.tray_icon.showMessage(title, message, QtGui.QIcon(), 3000)
                return
        except Exception:
            pass
        if self.has_notify_send:
            try:
                subprocess.Popen(['notify-send', title, message])
                return
            except Exception:
                pass
        log(f'NOTICE {title}: {message}')

class NcSync:
    """Nextcloud WebDAV clipboard sync with per-node files."""
    def __init__(self, url, user, app_password, remote_dir, node_id, cb, settings, notifier, interval=0.5, max_bytes=1_000_000):
        self.url = url
        self.user = user
        self.app_password = app_password
        self.remote_dir = remote_dir.rstrip('/')
        self.node_id = node_id
        self.cb = cb
        self.settings = settings
        self.notifier = notifier
        self.interval = interval
        self.max_bytes = max_bytes

        self.nc = None
        self.my_rel = f'{self.remote_dir}/{self.node_id}.clip.json'
        self.last_local_hash = None
        self.peer_etags = {}
        self._connect_and_prepare()
        self._snapshot_start_state()

    def _connect_and_prepare(self):
        log(f'connecting to {self.url} as {self.user}')
        self.nc = Nextcloud(nextcloud_url=self.url, nc_auth_user=self.user, nc_auth_pass=self.app_password)
        try:
            log(f'MKDIR {self.remote_dir} (ensure exists)')
            self.nc.files.makedirs(self.remote_dir, exist_ok=True)
        except Exception:
            pass

    def _snapshot_start_state(self):
        try:
            init_text = self.cb.get() or ''
            self.last_local_hash = sha256_text(init_text)
        except Exception:
            self.last_local_hash = None
        # Snapshot existing peers so we ignore history
        try:
            log(f'LIST {self.remote_dir} (snapshot, no-sync-on-start)')
            for n in self.nc.files.listdir(self.remote_dir, depth=1, exclude_self=True):
                if n.is_dir: continue
                name = getattr(n, 'name', '')
                if name.endswith('.clip.json'):
                    if f'{self.remote_dir}/{name}' == self.my_rel:
                        continue
                    et = getattr(n, 'etag', None)
                    self.peer_etags[name] = et
        except Exception:
            pass

    def _list_peers(self):
        """Return {name: (node, etag)}."""
        out = {}
        try:
            log(f'LIST {self.remote_dir}')
            for n in self.nc.files.listdir(self.remote_dir, depth=1, exclude_self=True):
                if n.is_dir: continue
                name = getattr(n, 'name', '')
                if not name.endswith('.clip.json'): continue
                if f'{self.remote_dir}/{name}' == self.my_rel: continue
                out[name] = (n, getattr(n, 'etag', None))
        except Exception:
            return {}
        return out

    def _download_json(self, node_or_path, name_for_log):
        try:
            log(f'GET {name_for_log}')
            data = self.nc.files.download(node_or_path)
            if not data: return {}
            return json.loads(data.decode('utf-8', 'ignore'))
        except Exception:
            return {}

    def _upload_atomic(self, path, payload_str):
        tmp = f'{path}.tmp.{os.getpid()}.{int(time.time()*1000)}'
        try:
            log(f'PUT {tmp} ({len(payload_str.encode("utf-8","ignore"))}B)')
            self.nc.files.upload(tmp, payload_str)
            log(f'MOVE {tmp} -> {path}')
            self.nc.files.move(tmp, path, overwrite=True)
        except Exception:
            try:
                self.nc.files.delete(tmp, not_fail=True)
            except Exception:
                pass

    def _pull(self):
        peers = self._list_peers()
        for name, (node, etag) in peers.items():
            old = self.peer_etags.get(name)
            if etag and old == etag:
                continue
            log(f'FOUND change in {name}')
            data = self._download_json(node, name)
            origin = data.get('origin', name.rsplit('.', 2)[0])
            if origin == self.node_id:
                log(f'SKIP own-origin from {name}')
                self.peer_etags[name] = etag
                continue
            content = data.get('content', '')
            h = data.get('hash') or sha256_text(content)
            if h and h == self.last_local_hash:
                log('SKIP same-hash as local')
                self.peer_etags[name] = etag
                continue
            applied = self.cb.set(content)
            if applied:
                self.last_local_hash = h
                self.peer_etags[name] = etag
                log(f'APPLY from {origin} ({len(content)} chars)')
                self.notifier.notify('Clipboard received', f'From {origin}')

    def _push(self):
        try:
            text = self.cb.get() or ''
            enc = text.encode('utf-8','ignore')
            if len(enc) > self.max_bytes:
                enc = enc[:self.max_bytes]
                text = enc.decode('utf-8','ignore')
            h = sha256_text(text)
            if h != self.last_local_hash:
                payload = {
                    'origin': self.node_id,
                    'ts': int(time.time()),
                    'hash': h,
                    'format': 'text',
                    'content': text
                }
                log(f'SEND update ({len(text)} chars)')
                self._upload_atomic(self.my_rel, json.dumps(payload, ensure_ascii=False))
                self.last_local_hash = h
                self.notifier.notify('Clipboard sent', 'Shared via Nextcloud')
        except Exception:
            pass

    def tick(self):
        if self.settings.receive: self._pull()
        if self.settings.send:    self._push()

class TrayApp:
    """Qt tray and periodic WebDAV sync ticks."""
    def __init__(self, ncsync, settings):
        self.ncsync = ncsync
        self.settings = settings
        self.app = QApp(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)

        self.tray = QtWidgets.QSystemTrayIcon(self._icon(), self.app)
        self.tray.setToolTip('Clipboard Sync (Nextcloud)')
        self.menu = QtWidgets.QMenu()

        self.act_send = self.menu.addAction('Send'); self.act_send.setCheckable(True)
        self.act_receive = self.menu.addAction('Receive'); self.act_receive.setCheckable(True)
        self.act_notify = self.menu.addAction('Notifications'); self.act_notify.setCheckable(True)
        self.menu.addSeparator()
        self.act_quit = self.menu.addAction('Quit')

        self.tray.setContextMenu(self.menu)
        self._load_states_into_menu()

        self.act_send.toggled.connect(self._toggle_send)
        self.act_receive.toggled.connect(self._toggle_receive)
        self.act_notify.toggled.connect(self._toggle_notify)
        self.act_quit.triggered.connect(self.app.quit)

        self.ncsync.notifier.tray_icon = self.tray

        self.timer = QtCore.QTimer()
        self.timer.setInterval(int(self.ncsync.interval * 1000))
        self.timer.timeout.connect(self.ncsync.tick)

    def _icon(self):
        candidates = [
            'umbr-message-asynchronous',
            'mail-send-receive',
            'network-transmit-receive',
            'folder-sync',
            'view-refresh',
            'emblem-synchronizing',
            'edit-paste',
            'accessories-clipboard',
        ]
        if QtGui.QIcon.hasThemeIcon:
            for name in candidates:
                try:
                    if QtGui.QIcon.hasThemeIcon(name):
                        ic = QtGui.QIcon.fromTheme(name)
                        if not ic.isNull(): return ic
                except Exception:
                    pass
        try:
            style = self.app.style()
            ic = style.standardIcon(QtWidgets.QStyle.SP_BrowserReload)
            if not ic.isNull(): return ic
        except Exception:
            pass
        pm = QtGui.QPixmap(22, 22); pm.fill(QtGui.QColor(60, 60, 60))
        painter = QtGui.QPainter(pm)
        painter.setPen(QtGui.QPen(QtGui.QColor(220, 220, 220)))
        painter.drawRect(4, 4, 14, 14)
        painter.end()
        return QtGui.QIcon(pm)

    def _load_states_into_menu(self):
        self.act_send.setChecked(self.settings.send)
        self.act_receive.setChecked(self.settings.receive)
        self.act_notify.setChecked(self.settings.notifications)

    def _toggle_send(self, checked):
        self.settings.send = bool(checked); self.settings.save(); log(f'SET Send={self.settings.send}')

    def _toggle_receive(self, checked):
        self.settings.receive = bool(checked); self.settings.save(); log(f'SET Receive={self.settings.receive}')

    def _toggle_notify(self, checked):
        self.settings.notifications = bool(checked); self.settings.save(); log(f'SET Notifications={self.settings.notifications}')

    def run(self):
        log('tray mode')
        self.tray.show()
        self.timer.start()
        self.app.exec_()

def run_headless(ncsync):
    log('headless mode')
    while True:
        try:
            ncsync.tick()
            time.sleep(ncsync.interval)
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(ncsync.interval)

def load_creds_json(path):
    """Load creds JSON; map to url, user, app_password, remote_dir."""
    data = atomic_read_json_local(path)
    url = data.get('url')
    user = data.get('user')
    app_password = data.get('app_password') or data.get('app_api_token') or data.get('password')
    remote_dir = data.get('remote_dir')
    return {'url': url, 'user': user, 'app_password': app_password, 'remote_dir': remote_dir}

def parse_args(argv):
    """Usage: script <node-id> [--creds ./credentials.json] [--interval 0.5]"""
    if len(argv) < 2 or argv[1].startswith('-'):
        print('Usage: clip_sync_nextcloud.py <node-id> [--creds ./credentials.json] [--interval 0.5]')
        sys.exit(2)
    node_id = argv[1]
    creds = './credentials.json'
    interval = 0.5
    i = 2
    while i < len(argv):
        a = argv[i]
        if a == '--creds':
            if i + 1 >= len(argv):
                print('Error: --creds needs a path'); sys.exit(2)
            creds = argv[i + 1]; i += 2
        elif a == '--interval':
            if i + 1 >= len(argv):
                print('Error: --interval needs a value'); sys.exit(2)
            try:
                interval = float(argv[i + 1])
            except Exception:
                print('Error: --interval must be a number'); sys.exit(2)
            i += 2
        else:
            print(f'Unknown argument: {a}')
            print('Usage: clip_sync_nextcloud.py <node-id> [--creds ./credentials.json] [--interval 0.5]')
            sys.exit(2)
    return node_id, creds, interval

def main():
    token = acquire_single_instance()
    if not token:
        sys.exit(0)
    atexit.register(lambda: release_single_instance(token))

    if Nextcloud is None:
        print('nc_py_api is not installed. Install with: python3 -m pip install --user nc_py_api')
        sys.exit(1)

    node_id, cred_path, interval = parse_args(sys.argv)
    creds = load_creds_json(cred_path)
    missing = [k for k in ('url', 'user', 'app_password', 'remote_dir') if not creds.get(k)]
    if missing:
        print('credentials JSON must contain: url, user, remote_dir and one of app_password/app_api_token/password')
        sys.exit(2)

    log(f'start node={node_id} interval={interval}s')
    log(f'using creds file {cred_path}')

    cb = Clipboard()
    if cb.mode is None:
        print('No clipboard backend found (need wl-clipboard, xclip, or Tkinter).')
        sys.exit(1)

    settings = Settings()
    notifier = Notifier(settings)
    ncsync = NcSync(creds['url'], creds['user'], creds['app_password'], creds['remote_dir'],
                    node_id, cb, settings, notifier, interval=interval)

    if Qt and os.environ.get('DISPLAY'):
        app = TrayApp(ncsync, settings)
        app.run()
    else:
        run_headless(ncsync)

if __name__ == '__main__':
    main()
