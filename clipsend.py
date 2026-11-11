#!/usr/bin/env python3
"""
ClipSend - send your clipboard (text, images or files) to your other machine(s),
using a Nextcloud account as relay.

  * Left-click the tray icon  -> send the current clipboard
  * Right-click               -> menu (send to..., settings, ...)
  * `clipsend --send`         -> same as left click (bind it to a KDE shortcut)

Transport: every device has an inbox folder on Nextcloud
(<remote_dir>/inbox/<device>/).  Sending = one WebDAV PUT into the inbox of
each target.  Receiving = the device watches its own inbox, either via
Nextcloud's notify_push websocket (instant, if the server has the app) or by
polling the inbox folder's ETag (one tiny PROPFIND over a kept-alive
connection per interval).
"""
import argparse
import base64
import errno
import fcntl
import html
import json
import logging
import logging.handlers
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
import zlib

APP = 'clipsend'
VERSION = '2.0'

# --------------------------------------------------------------------------- #
# paths
# --------------------------------------------------------------------------- #
CONFIG_DIR = os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config'), APP)
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
CACHE_DIR = os.path.join(os.environ.get('XDG_CACHE_HOME') or os.path.expanduser('~/.cache'), APP)
LOG_FILE = os.path.join(CACHE_DIR, 'clipsend.log')


def runtime_dir():
    d = os.environ.get('XDG_RUNTIME_DIR')
    if d and os.path.isdir(d) and os.access(d, os.W_OK):
        return d
    d = os.path.join('/tmp', f'{APP}-{os.getuid()}')
    os.makedirs(d, mode=0o700, exist_ok=True)
    st = os.lstat(d)
    if st.st_uid != os.getuid() or (st.st_mode & 0o077) or not os.path.isdir(d):
        raise RuntimeError(f'insecure runtime dir {d}')
    return d


log = logging.getLogger(APP)

# --------------------------------------------------------------------------- #
# Qt binding shim (PySide6 / PyQt6 / PyQt5)
# --------------------------------------------------------------------------- #
QT_API = None
for _name in ('PySide6', 'PyQt6', 'PyQt5'):
    try:
        _mod = __import__(_name, fromlist=['QtCore', 'QtGui', 'QtWidgets'])
        QtCore, QtGui, QtWidgets = _mod.QtCore, _mod.QtGui, _mod.QtWidgets
        QT_API = _name
        break
    except ImportError:
        continue
if QT_API is None:
    sys.exit('ClipSend needs a Qt binding: install PySide6, PyQt6 or PyQt5')

Signal = getattr(QtCore, 'Signal', None) or getattr(QtCore, 'pyqtSignal')
QAction = getattr(QtGui, 'QAction', None) or getattr(QtWidgets, 'QAction')


def qenum(owner, enum_name, member):
    """Access Qt enums in a way that works for scoped (Qt6) and flat (PyQt5) enums."""
    e = getattr(owner, enum_name, None)
    if e is not None and hasattr(e, member):
        return getattr(e, member)
    return getattr(owner, member)


def qexec(obj):
    return (getattr(obj, 'exec', None) or getattr(obj, 'exec_'))()


# --------------------------------------------------------------------------- #
# limits / constants
# --------------------------------------------------------------------------- #
MAGIC_PLAIN = b'CLIPSEND/2 plain\n'
MAGIC_ENC = b'CLIPSEND/2 aesgcm\n'
MSG_RE = re.compile(r'^(\d{13})-([0-9a-f]{32})\.clipsend$')
DEVICE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
MAX_FILES = 2000                 # per message
MAX_BATCH = 20                   # messages processed per inbox check
MAX_PROPFIND_BYTES = 4 << 20     # cap for server XML responses
IMAGE_MAGIC = {
    'image/png': [b'\x89PNG\r\n\x1a\n'],
    'image/jpeg': [b'\xff\xd8\xff'],
    'image/gif': [b'GIF87a', b'GIF89a'],
    'image/bmp': [b'BM'],
    'image/webp': [b'RIFF'],
}
TEXT_TYPES = ('text/plain;charset=utf-8', 'text/plain', 'UTF8_STRING', 'STRING', 'TEXT')
# Characters that are stripped from received file names / shown strings:
# control chars and bidi overrides (used to disguise e.g. "evil‮txt.exe").
_BAD_CHARS = re.compile('[\x00-\x1f\x7f​-‏‪-‮⁦-⁩﻿]')


def human_size(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


def clean_display(s, maxlen=120):
    """Make untrusted text safe for a (rich-text) notification."""
    s = _BAD_CHARS.sub(' ', str(s))
    s = re.sub(r'\s+', ' ', s).strip()
    if len(s) > maxlen:
        s = s[:maxlen - 1] + '…'
    return html.escape(s)


def sanitize_device(name):
    name = re.sub(r'[^A-Za-z0-9._-]', '-', name or '').strip('.-_')[:64]
    return name or 'device'


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
DEFAULTS = {
    'server_url': '',
    'user': '',
    'app_password': '',
    'remote_dir': '/ClipSend',
    'server_ip': '',              # optional: pin server hostname to this IP
    'device_name': sanitize_device(socket.gethostname().split('.')[0]),
    'target': '*',                # '*' = all other devices
    'max_size_mb': 5.0,
    'max_age_min': 60,
    'receive_enabled': True,
    'apply_to_clipboard': True,
    'download_dir': os.path.join(os.path.expanduser('~'), 'Downloads', 'ClipSend'),
    'use_push': True,
    'poll_interval': 0.5,
    'passphrase': '',
    'notifications': True,
}


def _coerce(cfg):
    out = dict(DEFAULTS)
    for k, default in DEFAULTS.items():
        v = cfg.get(k, default)
        try:
            if isinstance(default, bool):
                v = bool(v)
            elif isinstance(default, int):
                v = int(v)
            elif isinstance(default, float):
                v = float(v)
            else:
                v = str(v)
        except (TypeError, ValueError):
            v = default
        out[k] = v
    out['max_size_mb'] = min(max(out['max_size_mb'], 0.01), 1024.0)
    out['max_age_min'] = min(max(out['max_age_min'], 1), 60 * 24 * 30)
    out['poll_interval'] = min(max(out['poll_interval'], 0.5), 300.0)
    out['device_name'] = sanitize_device(out['device_name'])
    if out['target'] != '*' and not DEVICE_RE.match(out['target']):
        out['target'] = '*'
    return out


def load_config():
    try:
        st = os.stat(CONFIG_FILE)
        if st.st_mode & 0o077:
            os.chmod(CONFIG_FILE, 0o600)
        with open(CONFIG_FILE, encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except FileNotFoundError:
        data = {}
    except (OSError, ValueError) as e:
        log.error('could not read config %s: %s', CONFIG_FILE, e)
        data = {}
    return _coerce(data)


def save_config(cfg):
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    tmp = CONFIG_FILE + f'.tmp{os.getpid()}'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(_coerce(cfg), f, indent=2)
        f.write('\n')
    os.replace(tmp, CONFIG_FILE)


def config_complete(cfg):
    return all(cfg.get(k) for k in ('server_url', 'user', 'app_password', 'remote_dir'))


def import_legacy(path):
    """Import the credentials.json of the old sync-clip.py."""
    with open(path, encoding='utf-8') as f:
        old = json.load(f)
    cfg = load_config()
    if config_complete(cfg):
        print(f'{CONFIG_FILE} already configured, not importing {path}')
        return
    cfg['server_url'] = old.get('url', '')
    cfg['user'] = old.get('user', '')
    cfg['app_password'] = old.get('app_password') or old.get('app_api_token') or old.get('password') or ''
    cfg['remote_dir'] = old.get('remote_dir') or DEFAULTS['remote_dir']
    save_config(cfg)
    print(f'imported {path} -> {CONFIG_FILE}')


# --------------------------------------------------------------------------- #
# optional DNS pinning (replaces the old hard-coded DNS_MAP patch)
# --------------------------------------------------------------------------- #
_DNS_PINS = {}
_orig_getaddrinfo = socket.getaddrinfo


def _pinned_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    ip = _DNS_PINS.get(host)
    if ip:
        return _orig_getaddrinfo(ip, port, family, type, proto, flags | socket.AI_NUMERICHOST)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = _pinned_getaddrinfo


def validate_ip(ip):
    if ip:
        try:
            socket.inet_pton(socket.AF_INET6 if ':' in ip else socket.AF_INET, ip)
        except OSError:
            raise ValueError(f'invalid IP address {ip!r}') from None


def set_dns_pin(host, ip):
    validate_ip(ip)
    if ip:
        _DNS_PINS[host] = ip
    else:
        _DNS_PINS.pop(host, None)


# --------------------------------------------------------------------------- #
# crypto (optional end-to-end encryption with a shared passphrase)
# --------------------------------------------------------------------------- #
class Crypto:
    def __init__(self, passphrase):
        self.passphrase = passphrase.encode('utf-8') if passphrase else b''
        self._keys = {}
        if self.passphrase:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401  (fail early)

    @property
    def enabled(self):
        return bool(self.passphrase)

    def _key(self, salt):
        k = self._keys.get(salt)
        if k is None:
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
            k = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(self.passphrase)
            if len(self._keys) > 64:
                self._keys.clear()
            self._keys[salt] = k
        return k

    def seal(self, plain):
        if not self.enabled:
            return MAGIC_PLAIN + plain
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if not hasattr(self, '_send_salt'):
            self._send_salt = secrets.token_bytes(16)
        salt = self._send_salt
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._key(salt)).encrypt(nonce, plain, MAGIC_ENC + salt)
        return MAGIC_ENC + salt + nonce + ct

    def open(self, blob):
        if blob.startswith(MAGIC_ENC):
            if not self.enabled:
                raise ValueError('received an encrypted item but no passphrase is set')
            from cryptography.exceptions import InvalidTag
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            body = blob[len(MAGIC_ENC):]
            if len(body) < 16 + 12 + 16:
                raise ValueError('truncated encrypted item')
            salt, nonce, ct = body[:16], body[16:28], body[28:]
            try:
                return AESGCM(self._key(salt)).decrypt(nonce, ct, MAGIC_ENC + salt)
            except InvalidTag:
                raise ValueError('decryption failed (wrong passphrase or tampered data)') from None
        if blob.startswith(MAGIC_PLAIN):
            if self.enabled:
                raise ValueError('rejected unencrypted item (a passphrase is configured)')
            return blob[len(MAGIC_PLAIN):]
        raise ValueError('not a ClipSend item')


# --------------------------------------------------------------------------- #
# message encoding / validation
# --------------------------------------------------------------------------- #
class Rejected(Exception):
    pass


def wire_cap(max_bytes):
    """Upper bound for an encoded message (JSON, before/after compression) given a content limit."""
    return 2 * max_bytes + 256 * 1024


def encode_message(msg, crypto, max_bytes):
    raw = json.dumps(msg, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(raw) > wire_cap(max_bytes):
        raise Rejected('content too large after encoding')
    return crypto.seal(zlib.compress(raw, 6))


def decode_message(blob, crypto, max_bytes, me):
    try:
        comp = crypto.open(blob)
    except ValueError as e:
        raise Rejected(str(e)) from None
    cap = wire_cap(max_bytes)
    d = zlib.decompressobj()
    try:
        raw = d.decompress(comp, cap + 1)
    except zlib.error:
        raise Rejected('corrupt item') from None
    if len(raw) > cap or d.unconsumed_tail:
        raise Rejected('item too large after decompression')
    try:
        msg = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise Rejected('malformed item') from None
    return validate_message(msg, max_bytes, me)


def _b64(s, budget):
    if not isinstance(s, str) or len(s) > wire_cap(budget):
        raise Rejected('bad data field')
    try:
        b = base64.b64decode(s, validate=True)
    except (ValueError, TypeError):
        raise Rejected('bad base64') from None
    return b


def validate_message(msg, max_bytes, me):
    if not isinstance(msg, dict) or msg.get('v') != 2:
        raise Rejected('unsupported item version')
    sender, to, ts, kind = msg.get('from'), msg.get('to'), msg.get('ts'), msg.get('kind')
    if not (isinstance(sender, str) and DEVICE_RE.match(sender)):
        raise Rejected('bad sender')
    if to != me:
        raise Rejected(f'item addressed to {to!r}, not to this device')
    if sender == me:
        raise Rejected('item from myself')
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        raise Rejected('bad timestamp')
    out = {'from': sender, 'ts': float(ts), 'kind': kind}
    if kind == 'text':
        text = msg.get('text')
        if not isinstance(text, str):
            raise Rejected('bad text')
        text = text.replace('\x00', '')
        if len(text.encode('utf-8', 'surrogatepass')) > max_bytes:
            raise Rejected(f'text larger than limit ({human_size(max_bytes)})')
        out['text'] = text
    elif kind == 'image':
        mime = msg.get('mime')
        if mime not in IMAGE_MAGIC:
            raise Rejected(f'image type {mime!r} not allowed')
        data = _b64(msg.get('data'), max_bytes)
        if len(data) > max_bytes:
            raise Rejected(f'image larger than limit ({human_size(max_bytes)})')
        if not any(data.startswith(m) for m in IMAGE_MAGIC[mime]):
            raise Rejected('image content does not match its type')
        if mime == 'image/webp' and data[8:12] != b'WEBP':
            raise Rejected('image content does not match its type')
        out['mime'], out['data'] = mime, data
    elif kind == 'files':
        files = msg.get('files')
        if not isinstance(files, list) or not files or len(files) > MAX_FILES:
            raise Rejected('bad file list')
        total, parsed = 0, []
        for f in files:
            if not isinstance(f, dict) or not isinstance(f.get('path'), str):
                raise Rejected('bad file entry')
            data = _b64(f.get('data'), max_bytes)
            total += len(data)
            if total > max_bytes:
                raise Rejected(f'files larger than limit ({human_size(max_bytes)})')
            parts = safe_relpath(f['path'])
            parsed.append((parts, data))
        out['files'] = parsed
    else:
        raise Rejected(f'unknown kind {kind!r}')
    return out


def safe_component(part):
    part = unicodedata.normalize('NFC', _BAD_CHARS.sub('', part)).strip()
    part = part.replace('/', '_').replace('\\', '_')
    if part in ('', '.', '..'):
        raise Rejected('unsafe path in file list')
    while len(part.encode('utf-8')) > 200:
        part = part[:-1]
    return part


def safe_relpath(path):
    if len(path) > 4096 or path.startswith('/'):
        raise Rejected('unsafe path in file list')
    parts = [p for p in path.split('/') if p != '']
    if not parts or len(parts) > 32:
        raise Rejected('unsafe path in file list')
    return [safe_component(p) for p in parts]


def write_received_files(files, download_dir, sender):
    """Write files into a fresh directory. Returns (dest_dir, top_level_paths, total_bytes)."""
    os.makedirs(download_dir, mode=0o700, exist_ok=True)
    base_real = os.path.realpath(download_dir)
    stamp = time.strftime('%Y-%m-%d_%H%M%S')
    for i in range(100):
        dest = os.path.join(base_real, f'{stamp}_{sender}' + (f'_{i}' if i else ''))
        try:
            os.mkdir(dest, 0o755)
            break
        except FileExistsError:
            continue
    else:
        raise OSError('could not create a destination directory')
    top, total = [], 0
    for parts, data in files:
        target = os.path.join(dest, *parts)
        # paranoia: the result must stay inside dest (components are already sanitized)
        if os.path.commonpath([dest, os.path.abspath(target)]) != dest:
            raise Rejected('path escapes destination')
        parent = os.path.dirname(target)
        os.makedirs(parent, mode=0o755, exist_ok=True)
        if os.path.realpath(parent) != os.path.abspath(parent):
            raise Rejected('symlink in destination path')
        stem, ext = os.path.splitext(parts[-1])
        for n in range(1, 1000):
            try:
                # O_EXCL + O_NOFOLLOW: never overwrite or follow anything; 0o644: never executable
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                break
            except FileExistsError:
                target = os.path.join(parent, f'{stem} ({n + 1}){ext}')
        else:
            raise OSError('too many name collisions')
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        total += len(data)
        first = os.path.join(dest, parts[0]) if len(parts) > 1 else target
        if first not in top:
            top.append(first)
    return dest, top, total


def collect_files(paths, max_bytes):
    """Gather local files/dirs for sending. Symlinks inside directories are skipped."""
    entries, total, skipped = [], 0, 0

    def add(abspath, rel):
        nonlocal total
        st = os.stat(abspath)
        total += st.st_size
        if total > max_bytes:
            raise Rejected(f'files are too large ({human_size(total)}+, limit {human_size(max_bytes)})')
        if len(entries) >= MAX_FILES:
            raise Rejected(f'too many files (limit {MAX_FILES})')
        entries.append((abspath, rel))

    for p in paths:
        p = os.path.abspath(p)
        name = os.path.basename(p.rstrip('/')) or 'root'
        if os.path.isfile(p):
            add(p, name)
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p, followlinks=False):
                dirs.sort()
                for fn in sorted(files):
                    fp = os.path.join(root, fn)
                    if os.path.islink(fp) or not os.path.isfile(fp):
                        skipped += 1
                        continue
                    add(fp, os.path.join(name, os.path.relpath(fp, p)))
        else:
            skipped += 1
    if not entries:
        raise Rejected('no regular files to send')
    out, real_total = [], 0
    for abspath, rel in entries:
        with open(abspath, 'rb') as f:
            data = f.read(max_bytes + 1 - real_total)
        real_total += len(data)
        if real_total > max_bytes:
            raise Rejected(f'files are too large (limit {human_size(max_bytes)})')
        out.append({'path': rel, 'data': base64.b64encode(data).decode('ascii')})
    return out, real_total, skipped


# --------------------------------------------------------------------------- #
# WebDAV client
# --------------------------------------------------------------------------- #
class AuthError(Exception):
    pass


class DavError(Exception):
    pass


def check_server_url(server_url):
    u = urllib.parse.urlsplit(server_url.strip().rstrip('/'))
    if u.scheme not in ('https', 'http') or not u.hostname:
        raise ValueError('server URL must look like https://cloud.example.com')
    if u.scheme == 'http' and u.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('refusing plain http:// (credentials and clipboard would be sent in clear text)')
    return u


class WebDav:
    """Minimal Nextcloud WebDAV client; one requests.Session per thread (keep-alive)."""

    def __init__(self, server_url, user, password, server_ip=None):
        import requests
        self.requests = requests
        u = check_server_url(server_url)
        self.host = u.hostname
        self.server = f'{u.scheme}://{u.netloc}{u.path}'
        self.user = user
        self.auth = (user, password)
        self.root_path = f'{u.path}/remote.php/dav/files/{urllib.parse.quote(user, safe="")}'
        self.root = f'{u.scheme}://{u.netloc}{self.root_path}'
        if server_ip is not None:
            set_dns_pin(self.host, server_ip.strip())
        self._local = threading.local()

    @property
    def s(self):
        s = getattr(self._local, 's', None)
        if s is None:
            s = self.requests.Session()
            s.auth = self.auth
            s.headers['User-Agent'] = f'ClipSend/{VERSION}'
            s.max_redirects = 0
            self._local.s = s
        return s

    def url(self, path):
        return self.root + urllib.parse.quote(path)

    def _req(self, method, path, ok=(200, 201, 204, 207), stream=False, **kw):
        r = self.s.request(method, self.url(path), timeout=(10, 30), allow_redirects=False,
                           stream=stream, **kw)
        if r.status_code == 401:
            r.close()
            raise AuthError('authentication failed - check user / app password')
        if r.status_code not in ok:
            r.close()
            raise DavError(f'{method} {path}: HTTP {r.status_code}')
        return r

    def _read_capped(self, r, cap):
        buf = bytearray()
        for chunk in r.iter_content(64 * 1024):
            buf += chunk
            if len(buf) > cap:
                r.close()
                raise Rejected(f'server response exceeds {human_size(cap)}')
        return bytes(buf)

    def propfind(self, path, depth):
        body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop>'
                '<d:getetag/><d:getcontentlength/><d:resourcetype/></d:prop></d:propfind>')
        r = self._req('PROPFIND', path, ok=(207, 404), stream=True, data=body,
                      headers={'Depth': str(depth), 'Content-Type': 'application/xml'})
        if r.status_code == 404:
            r.close()
            return None
        root = ET.fromstring(self._read_capped(r, MAX_PROPFIND_BYTES))
        ns = '{DAV:}'
        out = []
        for resp in root.findall(f'{ns}response'):
            href = urllib.parse.unquote(resp.findtext(f'{ns}href', ''))
            prop = resp.find(f'{ns}propstat/{ns}prop')
            if prop is None:
                continue
            is_dir = prop.find(f'{ns}resourcetype/{ns}collection') is not None
            try:
                size = int(prop.findtext(f'{ns}getcontentlength') or 0)
            except ValueError:
                size = 0
            out.append({'href': href, 'name': href.rstrip('/').rsplit('/', 1)[-1],
                        'dir': is_dir, 'size': size, 'etag': prop.findtext(f'{ns}getetag')})
        return out

    def etag(self, path):
        res = self.propfind(path, 0)
        return res[0]['etag'] if res else None

    def listdir(self, path):
        res = self.propfind(path, 1)
        if res is None:
            return None
        me = urllib.parse.unquote(self.root_path + path).rstrip('/')
        return [e for e in res if e['href'].rstrip('/') != me]

    def makedirs(self, path):
        cur = ''
        for part in [p for p in path.split('/') if p]:
            cur += '/' + part
            self._req('MKCOL', cur, ok=(201, 405)).close()   # 405 = exists

    def put(self, path, data):
        self._req('PUT', path, ok=(200, 201, 204), data=data,
                  headers={'Content-Type': 'application/octet-stream'}).close()

    def get(self, path, cap):
        r = self._req('GET', path, ok=(200,), stream=True)
        return self._read_capped(r, cap)

    def delete(self, path):
        self._req('DELETE', path, ok=(204, 200, 404)).close()

    def capabilities(self):
        r = self.s.get(f'{self.server}/ocs/v2.php/cloud/capabilities?format=json',
                       headers={'OCS-APIRequest': 'true'}, timeout=(10, 30), allow_redirects=False)
        if r.status_code == 401:
            raise AuthError('authentication failed - check user / app password')
        r.raise_for_status()
        return r.json()['ocs']['data']['capabilities']


def norm_remote_dir(d):
    parts = [p for p in (d or '').strip().split('/') if p]
    if any(p in ('.', '..') for p in parts):
        raise ValueError('remote folder must not contain . or ..')
    return '/' + '/'.join(parts) if parts else ''


# --------------------------------------------------------------------------- #
# clipboard access
# --------------------------------------------------------------------------- #
def is_wayland():
    return bool(os.environ.get('WAYLAND_DISPLAY')) or os.environ.get('XDG_SESSION_TYPE') == 'wayland'


class Clipboard:
    """Wayland: wl-clipboard (works without focus via data-control on KWin). X11: QClipboard."""

    def __init__(self):
        self.wl = is_wayland() and shutil.which('wl-paste') and shutil.which('wl-copy')
        if is_wayland() and not self.wl:
            log.warning('Wayland session but wl-clipboard is missing; clipboard access may fail')

    # ---- reading ----
    def types(self):
        if self.wl:
            try:
                p = subprocess.run(['wl-paste', '--list-types'], capture_output=True, timeout=5)
            except subprocess.TimeoutExpired:
                return []
            if p.returncode != 0:
                return []
            return [t.strip() for t in p.stdout.decode('utf-8', 'replace').splitlines() if t.strip()]
        md = QtGui.QGuiApplication.clipboard().mimeData()
        return list(md.formats()) if md is not None else []

    def get(self, mime, cap):
        if self.wl:
            p = subprocess.Popen(['wl-paste', '--no-newline', '--type', mime],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            killer = threading.Timer(10, p.kill)
            killer.start()
            try:
                data = p.stdout.read(cap + 1)
            finally:
                killer.cancel()
                p.kill()
                p.wait()
            if len(data) > cap:
                raise Rejected(f'clipboard content is larger than the limit ({human_size(cap)})')
            return data
        md = QtGui.QGuiApplication.clipboard().mimeData()
        data = bytes(md.data(mime)) if md is not None else b''
        if len(data) > cap:
            raise Rejected(f'clipboard content is larger than the limit ({human_size(cap)})')
        return data

    def get_text(self, types, cap):
        if not self.wl:
            text = QtGui.QGuiApplication.clipboard().text()
            if len(text.encode('utf-8', 'surrogatepass')) > cap:
                raise Rejected(f'text is larger than the limit ({human_size(cap)})')
            return text
        for t in TEXT_TYPES:
            if t in types:
                return self.get(t, cap).decode('utf-8', 'replace')
        if any(t.startswith('text/') for t in types):
            return self.get('text/plain', cap).decode('utf-8', 'replace')
        return ''

    def read(self, max_bytes):
        """Return a content dict describing the clipboard."""
        types = self.types()
        tl = [t.lower() for t in types]
        if 'text/uri-list' in tl:
            raw = self.get('text/uri-list', 1 << 20).decode('utf-8', 'replace')
            paths = []
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                u = urllib.parse.urlsplit(line)
                if u.scheme != 'file' or u.netloc not in ('', 'localhost', socket.gethostname()):
                    paths = []
                    break
                paths.append(urllib.parse.unquote(u.path))
            if paths and all(os.path.exists(p) for p in paths):
                return {'kind': 'files', 'paths': paths}
        images = [t for t in types if t.lower() in IMAGE_MAGIC]
        if images:
            mime = 'image/png' if 'image/png' in images else images[0]
            data = self.get(mime, max_bytes)
            if data:
                return {'kind': 'image', 'mime': mime.lower(), 'data': data}
        text = self.get_text(types, max_bytes)
        if text:
            return {'kind': 'text', 'text': text}
        return {'kind': 'none'}

    # ---- writing ----
    def _wl_copy(self, mime, data):
        # stdout/stderr must not be pipes: wl-copy forks a server that keeps them open
        p = subprocess.Popen(['wl-copy', '--type', mime], stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate(data, timeout=10)
        if p.returncode != 0:
            raise OSError(f'wl-copy failed ({p.returncode})')

    def set_text(self, text):
        if self.wl:
            return self._wl_copy('text/plain;charset=utf-8', text.encode('utf-8', 'surrogatepass'))
        QtGui.QGuiApplication.clipboard().setText(text)

    def set_image(self, mime, data):
        if self.wl:
            return self._wl_copy(mime, data)
        md = QtCore.QMimeData()
        md.setData(mime, QtCore.QByteArray(data))
        img = QtGui.QImage.fromData(data)
        if not img.isNull():
            md.setImageData(img)
        QtGui.QGuiApplication.clipboard().setMimeData(md)

    def set_files(self, paths):
        uris = [QtCore.QUrl.fromLocalFile(p) for p in paths]
        if self.wl:
            data = ''.join(bytes(u.toEncoded()).decode('ascii') + '\r\n' for u in uris)
            return self._wl_copy('text/uri-list', data.encode('ascii'))
        md = QtCore.QMimeData()
        md.setUrls(uris)
        QtGui.QGuiApplication.clipboard().setMimeData(md)


# --------------------------------------------------------------------------- #
# sync engine (network side, runs in background threads)
# --------------------------------------------------------------------------- #
class Engine(QtCore.QObject):
    received = Signal(object)        # validated message dict
    sent = Signal(str)               # summary
    error = Signal(str, str)         # title, message
    status = Signal(str)             # short status for the tooltip
    devices_changed = Signal(object)

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self.me = cfg['device_name']
        self.max_bytes = int(cfg['max_size_mb'] * 1024 * 1024)
        self.base = norm_remote_dir(cfg['remote_dir'])
        self.inbox_root = f'{self.base}/inbox'
        self.inbox = f'{self.inbox_root}/{self.me}'
        self.dav = WebDav(cfg['server_url'], cfg['user'], cfg['app_password'], cfg['server_ip'])
        self.crypto = Crypto(cfg['passphrase'])
        self.devices = []
        self.push_ok = False
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._send_lock = threading.Lock()
        self._ws = None

    # ---- lifecycle ----
    def start(self):
        threading.Thread(target=self._poll_loop, name='clipsend-poll', daemon=True).start()
        if self.cfg['use_push'] and self.cfg['receive_enabled']:
            threading.Thread(target=self._push_loop, name='clipsend-push', daemon=True).start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        ws = self._ws
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    def wake(self):
        self._wake.set()

    def _emit(self, sig, *args):
        if not self._stop.is_set():
            sig.emit(*args)

    # ---- receiving ----
    def _poll_loop(self):
        last_etag, backoff, next_dev_refresh = None, 0.0, 0.0
        ready = False
        while not self._stop.is_set():
            try:
                if not ready:
                    self.dav.makedirs(self.inbox)
                    ready = True
                    self._emit(self.status, 'connected')
                if self.cfg['receive_enabled']:
                    etag = self.dav.etag(self.inbox)
                    if etag is None:
                        ready = False
                    elif etag != last_etag:
                        self._process_inbox()
                        last_etag = etag
                if time.monotonic() >= next_dev_refresh:
                    self.refresh_devices()
                    next_dev_refresh = time.monotonic() + 60
                if backoff:
                    self._emit(self.status, 'connected')
                backoff = 0.0
            except AuthError as e:
                self._emit(self.error, 'ClipSend: login failed', str(e))
                self._emit(self.status, 'login failed')
                backoff = 600.0       # do not hammer the server (brute-force lockout)
            except Exception as e:
                log.warning('poll error: %s', e)
                backoff = min(60.0, max(2.0, backoff * 2))
                self._emit(self.status, f'offline ({type(e).__name__}), retrying')
            if backoff:
                interval = backoff
            elif self.push_ok:
                interval = 30.0       # push is the main signal; this is only a safety net
            else:
                interval = self.cfg['poll_interval']
            self._wake.wait(interval)
            self._wake.clear()

    def _process_inbox(self):
        entries = self.dav.listdir(self.inbox) or []
        msgs = sorted((e for e in entries if not e['dir'] and MSG_RE.match(e['name'])),
                      key=lambda e: e['name'])[:MAX_BATCH]
        cap = wire_cap(self.max_bytes)
        for e in msgs:
            if self._stop.is_set():
                return
            path = f'{self.inbox}/{e["name"]}'
            try:
                if e['size'] > cap:
                    raise Rejected(f'item too large ({human_size(e["size"])})')
                # network errors propagate to the poll loop (item stays for the next attempt)
                blob = self.dav.get(path, cap)
            except Rejected as ex:
                log.warning('rejected %s: %s', e['name'], ex)
                self._emit(self.error, 'ClipSend: rejected incoming item', clean_display(str(ex), 300))
                self._delete_quietly(path)
                continue
            self._delete_quietly(path)
            try:
                msg = decode_message(blob, self.crypto, self.max_bytes, self.me)
                age = time.time() - msg['ts']
                if abs(age) > self.cfg['max_age_min'] * 60:
                    log.info('discarding stale item from %s (%.0f min old)', msg['from'], age / 60)
                    continue
                if msg['kind'] == 'files':
                    dest, top, total = write_received_files(msg.pop('files'), self.cfg['download_dir'],
                                                            msg['from'])
                    msg.update(dest=dest, paths=top, total=total)
                log.info('received %s from %s', msg['kind'], msg['from'])
                self._emit(self.received, msg)
            except Rejected as ex:
                log.warning('rejected %s: %s', e['name'], ex)
                self._emit(self.error, 'ClipSend: rejected incoming item', clean_display(str(ex), 300))
            except OSError as ex:      # writing files failed
                log.warning('failed to process %s: %s', e['name'], ex)
                self._emit(self.error, 'ClipSend: receive failed', clean_display(str(ex), 300))

    def _delete_quietly(self, path):
        try:
            self.dav.delete(path)
        except Exception as ex:
            log.warning('could not delete %s: %s', path, ex)

    def refresh_devices(self):
        entries = self.dav.listdir(self.inbox_root) or []
        devs = sorted(e['name'] for e in entries
                      if e['dir'] and DEVICE_RE.match(e['name']) and e['name'] != self.me)
        if devs != self.devices:
            self.devices = devs
            self._emit(self.devices_changed, list(devs))
        return devs

    # ---- push (Nextcloud notify_push) ----
    def _push_loop(self):
        try:
            import websocket   # websocket-client
        except ImportError:
            log.info('websocket-client not installed: polling only')
            return
        backoff = 5
        endpoint = None
        while not self._stop.is_set():
            try:
                if endpoint is None:
                    caps = self.dav.capabilities()
                    endpoint = ((caps.get('notify_push') or {}).get('endpoints') or {}).get('websocket')
                    if not endpoint:
                        log.info('server has no notify_push app: polling every %.1fs', self.cfg['poll_interval'])
                        self._emit(self.status, 'connected (polling)')
                        return
                    u = urllib.parse.urlsplit(endpoint)
                    if u.scheme != 'wss' and u.hostname not in ('localhost', '127.0.0.1'):
                        log.warning('refusing non-TLS push endpoint %s', endpoint)
                        return
                    if u.hostname != self.dav.host:
                        log.warning('push endpoint on foreign host %s - not sending credentials', u.hostname)
                        return
                ws = websocket.create_connection(endpoint, timeout=30)
                self._ws = ws
                ws.send(self.dav.auth[0])
                ws.send(self.dav.auth[1])
                reply = ws.recv()
                if reply != 'authenticated':
                    log.warning('push auth failed: %r', str(reply)[:100])
                    return
                log.info('push connected (%s)', endpoint)
                self.push_ok = True
                self._emit(self.status, 'connected (push)')
                self._wake.set()          # check once right away
                backoff = 5
                while not self._stop.is_set():
                    try:
                        m = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        ws.ping()
                        continue
                    if isinstance(m, str) and m.startswith('notify_file'):
                        self._wake.set()
            except Exception as e:
                if self._stop.is_set():
                    break
                log.info('push connection lost (%s), reconnect in %ss', e, backoff)
            finally:
                self.push_ok = False
                if self._ws is not None:
                    try:
                        self._ws.close()
                    except Exception:
                        pass
                    self._ws = None
            self._stop.wait(backoff)
            backoff = min(300, backoff * 2)

    # ---- sending ----
    def send_async(self, content, target):
        if not self._send_lock.acquire(blocking=False):
            self._emit(self.error, 'ClipSend', 'Still sending the previous item…')
            return
        threading.Thread(target=self._send, args=(content, target), daemon=True).start()

    def _send(self, content, target):
        try:
            kind = content['kind']
            msg = {'v': 2, 'from': self.me, 'kind': kind}
            if kind == 'text':
                if len(content['text'].encode('utf-8', 'surrogatepass')) > self.max_bytes:
                    raise Rejected(f'text is larger than the limit ({human_size(self.max_bytes)})')
                msg['text'] = content['text']
                n = len(content['text'])
                summary = f'text ({n} character{"s" if n != 1 else ""})'
            elif kind == 'image':
                msg['mime'] = content['mime']
                msg['data'] = base64.b64encode(content['data']).decode('ascii')
                summary = f'image ({human_size(len(content["data"]))})'
            elif kind == 'files':
                files, total, skipped = collect_files(content['paths'], self.max_bytes)
                msg['files'] = files
                summary = f'{len(files)} file{"s" if len(files) != 1 else ""} ({human_size(total)})'
                if skipped:
                    summary += f', skipped {skipped} symlink/special'
            else:
                raise Rejected('clipboard is empty')

            if target and target != '*':
                targets = [target]
            else:
                targets = self.refresh_devices()
            if not targets:
                raise Rejected('no other device found - start ClipSend on the other machine first')
            for t in targets:
                msg.update(to=t, ts=time.time(), id=uuid.uuid4().hex)
                blob = encode_message(msg, self.crypto, self.max_bytes)
                name = f'{int(msg["ts"] * 1000):013d}-{msg["id"]}.clipsend'
                tdir = f'{self.inbox_root}/{t}'
                self._cleanup_stale(tdir)
                self.dav.put(f'{tdir}/{name}', blob)
                log.info('sent %s to %s (%s on the wire)', kind, t, human_size(len(blob)))
            self._emit(self.sent, f'{summary} → {", ".join(targets)}')
        except Rejected as e:
            self._emit(self.error, 'ClipSend: not sent', clean_display(str(e), 300))
        except AuthError as e:
            self._emit(self.error, 'ClipSend: login failed', str(e))
        except Exception as e:
            log.exception('send failed')
            self._emit(self.error, 'ClipSend: send failed', clean_display(f'{type(e).__name__}: {e}', 300))
        finally:
            self._send_lock.release()

    def _cleanup_stale(self, tdir):
        """Delete items nobody picked up (e.g. device offline) so inboxes cannot grow forever."""
        try:
            entries = self.dav.listdir(tdir) or []
        except DavError:
            return
        cutoff = (time.time() - self.cfg['max_age_min'] * 60) * 1000
        for e in entries:
            m = MSG_RE.match(e['name'])
            if m and int(m.group(1)) < cutoff:
                self.dav.delete(f'{tdir}/{e["name"]}')

    # ---- used by the settings dialog ----
    @staticmethod
    def test_connection(cfg):
        saved = dict(_DNS_PINS)
        try:
            dav = WebDav(cfg['server_url'], cfg['user'], cfg['app_password'], cfg['server_ip'])
            base = norm_remote_dir(cfg['remote_dir'])
            dav.makedirs(f'{base}/inbox')
            devs = [e['name'] for e in (dav.listdir(f'{base}/inbox') or []) if e['dir']]
            try:
                push = bool((dav.capabilities().get('notify_push') or {}).get('endpoints'))
            except Exception:
                push = False
            return devs, push
        finally:
            _DNS_PINS.clear()
            _DNS_PINS.update(saved)


# --------------------------------------------------------------------------- #
# local control socket (`clipsend --send` etc.)
# --------------------------------------------------------------------------- #
COMMANDS = ('send', 'settings', 'quit', 'ping')


def sock_path():
    return os.path.join(runtime_dir(), f'{APP}.sock')


class ControlServer(QtCore.QObject):
    command = Signal(str)

    def start(self):
        path = sock_path()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            self.sock.bind(path)
        finally:
            os.umask(old)
        self.sock.listen(4)
        threading.Thread(target=self._serve, daemon=True, name='clipsend-ctl').start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
                    _pid, uid, _gid = struct.unpack('3i', cred)
                    if uid != os.getuid():
                        continue
                    conn.settimeout(2)
                    cmd = conn.recv(64).decode('ascii', 'ignore').strip()
                    if cmd in COMMANDS:
                        if cmd != 'ping':
                            self.command.emit(cmd)
                        conn.sendall(b'ok\n')
                    else:
                        conn.sendall(b'unknown command\n')
                except OSError:
                    pass


def send_command(cmd):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(sock_path())
            s.sendall(cmd.encode() + b'\n')
            return s.recv(64).decode().strip() == 'ok'
    except OSError:
        return False


def acquire_lock():
    path = os.path.join(runtime_dir(), f'{APP}.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        os.close(fd)
        if e.errno in (errno.EAGAIN, errno.EACCES):
            return None
        raise
    return fd


# --------------------------------------------------------------------------- #
# settings dialog
# --------------------------------------------------------------------------- #
class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, cfg, devices, parent=None):
        super().__init__(parent)
        self.setWindowTitle('ClipSend Settings')
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(520)
        self.cfg = dict(cfg)
        W = QtWidgets
        lay = W.QVBoxLayout(self)

        # connection
        g = W.QGroupBox('Nextcloud connection')
        f = W.QFormLayout(g)
        self.url = W.QLineEdit(cfg['server_url'])
        self.url.setPlaceholderText('https://cloud.example.com')
        self.user = W.QLineEdit(cfg['user'])
        self.pw = W.QLineEdit(cfg['app_password'])
        self.pw.setEchoMode(qenum(W.QLineEdit, 'EchoMode', 'Password'))
        self.pw.setToolTip('Use an app password (Nextcloud → Settings → Security), ideally of a dedicated account.')
        self.rdir = W.QLineEdit(cfg['remote_dir'])
        self.ip = W.QLineEdit(cfg['server_ip'])
        self.ip.setPlaceholderText('optional, e.g. if DNS cannot resolve the server')
        test = W.QPushButton('Test connection')
        test.clicked.connect(self._test)
        f.addRow('Server URL', self.url)
        f.addRow('User', self.user)
        f.addRow('App password', self.pw)
        f.addRow('Remote folder', self.rdir)
        f.addRow('Fixed server IP', self.ip)
        f.addRow('', test)
        lay.addWidget(g)

        # device & sending
        g = W.QGroupBox('Sending')
        f = W.QFormLayout(g)
        self.dev = W.QLineEdit(cfg['device_name'])
        self.dev.setToolTip('Name of this machine. Letters, digits, . _ - only.')
        self.target = W.QComboBox()
        self.target.setEditable(True)
        self.target.addItem('All other devices', '*')
        for d in devices:
            self.target.addItem(d, d)
        if cfg['target'] != '*':
            i = self.target.findData(cfg['target'])
            if i < 0:
                self.target.addItem(cfg['target'], cfg['target'])
                i = self.target.count() - 1
            self.target.setCurrentIndex(i)
        self.maxsize = W.QDoubleSpinBox()
        self.maxsize.setRange(0.01, 1024)
        self.maxsize.setDecimals(2)
        self.maxsize.setSuffix(' MB')
        self.maxsize.setValue(cfg['max_size_mb'])
        self.maxsize.setToolTip('Largest text / image / file set that is sent or accepted.')
        f.addRow('This device', self.dev)
        f.addRow('Left-click sends to', self.target)
        f.addRow('Max. transfer size', self.maxsize)
        lay.addWidget(g)

        # receiving
        g = W.QGroupBox('Receiving')
        f = W.QFormLayout(g)
        self.recv = W.QCheckBox('Receive items from other devices')
        self.recv.setChecked(cfg['receive_enabled'])
        self.apply = W.QCheckBox('Put received items into the clipboard')
        self.apply.setChecked(cfg['apply_to_clipboard'])
        row = W.QHBoxLayout()
        self.ddir = W.QLineEdit(cfg['download_dir'])
        b = W.QPushButton('…')
        b.setMaximumWidth(32)
        b.clicked.connect(self._browse)
        row.addWidget(self.ddir)
        row.addWidget(b)
        self.push = W.QCheckBox('Use instant push if the server supports it (notify_push)')
        self.push.setChecked(cfg['use_push'])
        self.poll = W.QDoubleSpinBox()
        self.poll.setRange(0.5, 300)
        self.poll.setDecimals(1)
        self.poll.setSuffix(' s')
        self.poll.setValue(cfg['poll_interval'])
        self.age = W.QSpinBox()
        self.age.setRange(1, 60 * 24 * 30)
        self.age.setSuffix(' min')
        self.age.setValue(cfg['max_age_min'])
        f.addRow(self.recv)
        f.addRow(self.apply)
        f.addRow('Save received files to', row)
        f.addRow(self.push)
        f.addRow('Poll interval (no push)', self.poll)
        f.addRow('Discard items older than', self.age)
        lay.addWidget(g)

        # security & misc
        g = W.QGroupBox('Security')
        f = W.QFormLayout(g)
        self.pp = W.QLineEdit(cfg['passphrase'])
        self.pp.setEchoMode(qenum(W.QLineEdit, 'EchoMode', 'Password'))
        self.pp.setPlaceholderText('empty = no end-to-end encryption')
        self.pp.setToolTip('Same passphrase on all devices. Content is encrypted (AES-GCM) before upload, '
                           'and anything not encrypted with it is rejected.')
        self.notif = W.QCheckBox('Show notifications for sent / received items')
        self.notif.setChecked(cfg['notifications'])
        f.addRow('Shared passphrase', self.pp)
        f.addRow(self.notif)
        lay.addWidget(g)

        bb = W.QDialogButtonBox(qenum(W.QDialogButtonBox, 'StandardButton', 'Save')
                                | qenum(W.QDialogButtonBox, 'StandardButton', 'Cancel'))
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _browse(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, 'Save received files to', self.ddir.text())
        if d:
            self.ddir.setText(d)

    def _collect(self):
        c = dict(self.cfg)
        c.update(server_url=self.url.text().strip(), user=self.user.text().strip(),
                 app_password=self.pw.text().strip(), remote_dir=self.rdir.text().strip(),
                 server_ip=self.ip.text().strip(), device_name=self.dev.text().strip(),
                 max_size_mb=self.maxsize.value(), receive_enabled=self.recv.isChecked(),
                 apply_to_clipboard=self.apply.isChecked(),
                 download_dir=os.path.expanduser(self.ddir.text().strip()) or DEFAULTS['download_dir'],
                 use_push=self.push.isChecked(), poll_interval=self.poll.value(),
                 max_age_min=self.age.value(), passphrase=self.pp.text(),
                 notifications=self.notif.isChecked())
        text = self.target.currentText().strip()
        idx = self.target.findText(text)
        c['target'] = self.target.itemData(idx) if idx >= 0 else text
        if not c['target']:
            c['target'] = '*'
        return c

    def _validate(self, c):
        if not DEVICE_RE.match(c['device_name']):
            return 'Device name may only contain letters, digits, ".", "_" and "-".'
        if c['target'] != '*' and not DEVICE_RE.match(c['target']):
            return 'Invalid target device name.'
        if c['target'] == c['device_name']:
            return 'The target cannot be this device.'
        try:
            norm_remote_dir(c['remote_dir'])
            validate_ip(c['server_ip'])
            if c['server_url']:
                check_server_url(c['server_url'])
        except ValueError as e:
            return str(e)
        if c['passphrase'] and len(c['passphrase']) < 8:
            return 'Use a passphrase of at least 8 characters (or leave it empty).'
        if c['passphrase']:
            try:
                Crypto(c['passphrase'])
            except ImportError:
                return 'Encryption needs the Python package "cryptography".'
        return None

    def _test(self):
        c = self._collect()
        err = self._validate(c)
        if err:
            QtWidgets.QMessageBox.warning(self, 'ClipSend', err)
            return
        QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(qenum(QtCore.Qt, 'CursorShape', 'WaitCursor')))
        try:
            devs, push = Engine.test_connection(c)
            msg = (f'Connection OK.\n\nRegistered devices: {", ".join(devs) or "none yet"}\n'
                   f'Instant push (notify_push): {"available" if push else "not available, will poll"}')
            QtWidgets.QApplication.restoreOverrideCursor()
            QtWidgets.QMessageBox.information(self, 'ClipSend', msg)
        except Exception as e:
            QtWidgets.QApplication.restoreOverrideCursor()
            QtWidgets.QMessageBox.warning(self, 'ClipSend', f'Connection failed:\n{e}')

    def _save(self):
        c = self._collect()
        err = self._validate(c)
        if err:
            QtWidgets.QMessageBox.warning(self, 'ClipSend', err)
            return
        self.cfg = _coerce(c)
        self.accept()


# --------------------------------------------------------------------------- #
# tray application
# --------------------------------------------------------------------------- #
# Own icon (a paper plane on a coloured tile) so it can't be confused with
# Klipper's clipboard icon. The colour shows the state. Drawn with QPainter,
# so no SVG plugin is needed; clipsend.svg is the same design for launchers.
ICON_COLORS = {
    'idle': ('#7b3fe4', '#00b4d8'),      # violet -> cyan
    'busy': ('#ff6d00', '#ffb300'),      # orange (sending)
    'recv': ('#00a86b', '#2ed3a0'),      # green (received)
    'offline': ('#6b7280', '#9ca3af'),   # grey (not configured / offline)
}
_ICONS = {}


def _paint_icon(size, c1, c2):
    pm = QtGui.QPixmap(size, size)
    pm.fill(QtGui.QColor(0, 0, 0, 0))
    p = QtGui.QPainter(pm)
    p.setRenderHint(qenum(QtGui.QPainter, 'RenderHint', 'Antialiasing'))
    p.scale(size / 64.0, size / 64.0)
    grad = QtGui.QLinearGradient(0, 0, 64, 64)
    grad.setColorAt(0, QtGui.QColor(c1))
    grad.setColorAt(1, QtGui.QColor(c2))
    p.setPen(qenum(QtCore.Qt, 'PenStyle', 'NoPen'))
    p.setBrush(QtGui.QBrush(grad))
    p.drawRoundedRect(QtCore.QRectF(2, 2, 60, 60), 15, 15)

    def poly(*pts):
        return QtGui.QPolygonF([QtCore.QPointF(x, y) for x, y in pts])
    p.setBrush(QtGui.QColor('#ffffff'))              # paper plane
    p.drawPolygon(poly((11, 31), (53, 12), (39, 53), (30, 38)))
    p.setBrush(QtGui.QColor(0, 0, 0, 55))            # folded wing (shadow)
    p.drawPolygon(poly((30, 38), (53, 12), (27, 47)))
    p.end()
    return pm


def app_icon(state='idle'):
    ic = _ICONS.get(state)
    if ic is None:
        ic = QtGui.QIcon()
        for size in (16, 22, 24, 32, 48, 64, 128):
            ic.addPixmap(_paint_icon(size, *ICON_COLORS[state]))
        _ICONS[state] = ic
    return ic


class TrayApp(QtCore.QObject):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.cfg = load_config()
        self.clip = Clipboard()
        self.engine = None
        self.devices = []
        self.state = 'not configured'
        self.dialog = None
        self._sending = False

        self.icon_idle = app_icon('offline')
        self.icon_busy = app_icon('busy')
        self.icon_recv = app_icon('recv')
        self.tray = QtWidgets.QSystemTrayIcon(self.icon_idle, self)
        self.tray.activated.connect(self._activated)

        self.menu = QtWidgets.QMenu()
        self.header = QAction('', self.menu)
        self.header.setEnabled(False)
        self.menu.addAction(self.header)
        self.menu.addSeparator()
        self.menu.addAction('Send clipboard').triggered.connect(lambda: self.send())
        self.sendto = self.menu.addMenu('Send clipboard to')
        self.menu.addSeparator()
        self.act_recv = self.menu.addAction('Receive')
        self.act_recv.setCheckable(True)
        self.act_recv.toggled.connect(self._toggle_recv)
        self.menu.addAction('Open received files').triggered.connect(self._open_downloads)
        self.menu.addAction('Settings…').triggered.connect(self.show_settings)
        self.menu.addSeparator()
        self.menu.addAction('Quit').triggered.connect(self.quit)
        self.menu.aboutToShow.connect(self._update_menu)
        self.tray.setContextMenu(self.menu)

        self.ctl = ControlServer()
        self.ctl.command.connect(self._command)
        self.ctl.start()

        self._restart_engine()
        self._update_tooltip()

    # ---- engine ----
    def _restart_engine(self):
        if self.engine:
            self.engine.stop()
            self.engine = None
        if not config_complete(self.cfg):
            self.state = 'not configured'
            self._update_tooltip()
            return
        try:
            self.engine = Engine(self.cfg)
        except Exception as e:
            self.state = 'configuration error'
            self.notify('ClipSend: configuration error', clean_display(str(e), 300), error=True)
            return
        self.engine.received.connect(self._on_received)
        self.engine.sent.connect(self._on_sent)
        self.engine.error.connect(self._on_error)
        self.engine.status.connect(self._on_status)
        self.engine.devices_changed.connect(self._on_devices)
        self.state = 'connecting'
        self.engine.start()
        self._update_tooltip()

    def _on_status(self, s):
        self.state = s
        self._update_tooltip()

    def _on_devices(self, devs):
        self.devices = devs
        self._update_tooltip()

    def _update_tooltip(self):
        self.icon_idle = app_icon('idle' if self.state.startswith('connected') else 'offline')
        if not self._sending:
            self.tray.setIcon(self.icon_idle)
        tgt = 'all other devices' if self.cfg['target'] == '*' else self.cfg['target']
        tip = (f'ClipSend – {self.cfg["device_name"]} ({self.state})\n'
               f'Left-click: send clipboard to {tgt}')
        if self.devices:
            tip += f'\nOther devices: {", ".join(self.devices)}'
        self.tray.setToolTip(tip)

    def _update_menu(self):
        self.header.setText(f'ClipSend – {self.cfg["device_name"]} ({self.state})')
        self.act_recv.blockSignals(True)
        self.act_recv.setChecked(self.cfg['receive_enabled'])
        self.act_recv.blockSignals(False)
        self.sendto.clear()
        self.sendto.addAction('All other devices').triggered.connect(lambda: self.send('*'))
        if self.devices:
            self.sendto.addSeparator()
        for d in self.devices:
            self.sendto.addAction(d).triggered.connect(lambda _=False, d=d: self.send(d))
        if self.engine:
            self.engine.wake()

    # ---- actions ----
    def _activated(self, reason):
        if reason == qenum(QtWidgets.QSystemTrayIcon, 'ActivationReason', 'Trigger'):
            self.send()

    def _command(self, cmd):
        if cmd == 'send':
            self.send()
        elif cmd == 'settings':
            self.show_settings()
        elif cmd == 'quit':
            self.quit()

    def send(self, target=None):
        if not self.engine:
            self.notify('ClipSend', 'Not configured yet – opening settings.', error=True)
            self.show_settings()
            return
        max_bytes = int(self.cfg['max_size_mb'] * 1024 * 1024)
        try:
            content = self.clip.read(max_bytes)
        except Rejected as e:
            self.notify('ClipSend: not sent', clean_display(str(e), 300), error=True)
            return
        except Exception as e:
            log.exception('reading clipboard failed')
            self.notify('ClipSend: cannot read clipboard', clean_display(str(e), 300), error=True)
            return
        if content['kind'] == 'none':
            self.notify('ClipSend', 'Clipboard is empty (or has an unsupported type).', error=True)
            return
        self._sending = True
        self.tray.setIcon(self.icon_busy)
        self.engine.send_async(content, target or self.cfg['target'])

    def _on_sent(self, summary):
        self._sending = False
        self.tray.setIcon(self.icon_idle)
        self.notify('Clipboard sent', clean_display(summary, 200))

    def _on_error(self, title, msg):
        self._sending = False
        self.tray.setIcon(self.icon_idle)
        self.notify(title, msg, error=True)

    def _on_received(self, msg):
        sender = msg['from']
        try:
            if msg['kind'] == 'text':
                if self.cfg['apply_to_clipboard']:
                    self.clip.set_text(msg['text'])
                body = f'Text from {sender}: “{clean_display(msg["text"], 60)}”'
            elif msg['kind'] == 'image':
                if self.cfg['apply_to_clipboard']:
                    self.clip.set_image(msg['mime'], msg['data'])
                body = f'Image from {sender} ({human_size(len(msg["data"]))})'
            else:
                if self.cfg['apply_to_clipboard']:
                    self.clip.set_files(msg['paths'])
                n = len(msg['paths'])
                body = (f'{n} item{"s" if n != 1 else ""} from {sender} ({human_size(msg["total"])}), '
                        f'saved to {clean_display(msg["dest"], 200)}')
        except Exception as e:
            log.exception('applying received item failed')
            self.notify('ClipSend: could not set clipboard', clean_display(str(e), 300), error=True)
            return
        self.tray.setIcon(self.icon_recv)
        QtCore.QTimer.singleShot(2500, lambda: self.tray.setIcon(self.icon_idle))
        self.notify('Clipboard received', body)

    def _toggle_recv(self, on):
        self.cfg['receive_enabled'] = bool(on)
        save_config(self.cfg)
        self._restart_engine()

    def _open_downloads(self):
        d = self.cfg['download_dir']
        os.makedirs(d, mode=0o700, exist_ok=True)
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(d))

    def show_settings(self):
        if self.dialog is not None:
            self.dialog.raise_()
            self.dialog.activateWindow()
            return
        self.dialog = SettingsDialog(self.cfg, self.devices)
        try:
            if qexec(self.dialog):
                self.cfg = self.dialog.cfg
                save_config(self.cfg)
                self._restart_engine()
                self._update_tooltip()
        finally:
            self.dialog.deleteLater()
            self.dialog = None

    def notify(self, title, body, error=False):
        if not error and not self.cfg['notifications']:
            return
        log.info('%s: %s', title, html.unescape(body))
        if not self.tray.isVisible():
            return
        icon = qenum(QtWidgets.QSystemTrayIcon, 'MessageIcon', 'Warning' if error else 'Information')
        self.tray.showMessage(title, body, icon, 6000 if error else 3000)

    def show_when_tray_ready(self, tries=0):
        if QtWidgets.QSystemTrayIcon.isSystemTrayAvailable() or tries >= 60:
            self.tray.show()
            if not config_complete(self.cfg):
                QtCore.QTimer.singleShot(500, self.show_settings)
        else:   # autostart can race with plasmashell
            QtCore.QTimer.singleShot(1000, lambda: self.show_when_tray_ready(tries + 1))

    def quit(self):
        if self.engine:
            self.engine.stop()
        try:
            self.ctl.sock.close()
            os.unlink(sock_path())
        except OSError:
            pass
        self.app.quit()


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def setup_logging(verbose):
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%Y-%m-%d %H:%M:%S')
    fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1 << 20, backupCount=2)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(sh)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)


def main():
    ap = argparse.ArgumentParser(prog='clipsend', description='Send your clipboard to your other machines.')
    g = ap.add_mutually_exclusive_group()
    g.add_argument('--send', action='store_true', help='tell the running instance to send the clipboard')
    g.add_argument('--settings', action='store_true', help='open the settings of the running instance')
    g.add_argument('--quit', action='store_true', help='quit the running instance')
    g.add_argument('--import-legacy', metavar='JSON', help='import credentials.json of the old sync-clip.py')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    if args.import_legacy:
        import_legacy(args.import_legacy)
        return 0
    for cmd in ('send', 'settings', 'quit'):
        if getattr(args, cmd):
            if send_command(cmd):
                return 0
            print('ClipSend is not running.', file=sys.stderr)
            return 1

    setup_logging(args.verbose)
    lock = acquire_lock()
    if lock is None:
        print('ClipSend is already running (use --settings / --send / --quit).', file=sys.stderr)
        return 0

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName('ClipSend')
    app.setDesktopFileName('clipsend')
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(app_icon())
    tray = TrayApp(app)
    tray.show_when_tray_ready()
    log.info('ClipSend %s started (Qt: %s, clipboard: %s)', VERSION, QT_API,
             'wl-clipboard' if tray.clip.wl else 'Qt')
    return qexec(app)


if __name__ == '__main__':
    sys.exit(main())
