#!/usr/bin/env python3
"""
ClipSend - send your clipboard (text, images or files) to your other machine(s),
end-to-end encrypted, using Google Firebase or a Nextcloud account as relay.

  * Left-click the tray icon  -> send the current clipboard
  * Right-click               -> menu (send to..., settings, ...)
  * `clipsend --send`         -> same as left click (bind it to a keyboard shortcut)

Runs on Linux (KDE Plasma, X11 or Wayland) and Windows 10/11, as a plain
Python script (nothing compiled, no installer).

Transport: every device has an inbox, either a folder on Nextcloud
(<remote_dir>/inbox/<device>/, via WebDAV) or a node in a Firebase Realtime
Database (users/<uid>/inbox/<device>).  Sending = one write into the inbox of
each target.  Receiving = the device watches its own inbox (Firebase event
stream, or Nextcloud's notify_push websocket if the server has the app) or
polls it, and deletes each item right after reading it.  Every client also
deletes items older than max_age_min from all inboxes once a minute.
"""
import argparse
import base64
import errno
import faulthandler
import hashlib
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

WINDOWS = sys.platform == 'win32'
if WINDOWS:
    import msvcrt
else:
    import fcntl

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    sys.exit('ClipSend needs the Python package "cryptography" (pip install cryptography)')

APP = 'clipsend'
VERSION = '3.1'

# --------------------------------------------------------------------------- #
# paths
# --------------------------------------------------------------------------- #
if WINDOWS:
    CONFIG_DIR = os.path.join(os.environ.get('APPDATA') or os.path.expanduser('~'), 'ClipSend')
    CACHE_DIR = os.path.join(os.environ.get('LOCALAPPDATA') or os.path.expanduser('~'), 'ClipSend')
else:
    CONFIG_DIR = os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config'), APP)
    CACHE_DIR = os.path.join(os.environ.get('XDG_CACHE_HOME') or os.path.expanduser('~/.cache'), APP)
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
LOG_FILE = os.path.join(CACHE_DIR, 'clipsend.log')


def runtime_dir():
    if WINDOWS:     # %LOCALAPPDATA% is private to the user by ACL
        os.makedirs(CACHE_DIR, exist_ok=True)
        return CACHE_DIR
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
# control chars, zero-width chars and bidi overrides (U+202E can make a name display reversed)
_BAD_CHARS = re.compile('[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]')


def human_size(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


def clean_display(s, maxlen=120):
    """Make untrusted text safe for a notification (KDE renders markup, Windows plain text)."""
    s = _BAD_CHARS.sub(' ', str(s))
    s = re.sub(r'\s+', ' ', s).strip()
    if len(s) > maxlen:
        s = s[:maxlen - 1] + '…'
    return s if WINDOWS else html.escape(s)


def sanitize_device(name):
    name = re.sub(r'[^A-Za-z0-9._-]', '-', name or '').strip('.-_')[:64]
    return name or 'device'


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
DEFAULTS = {
    'backend': 'nextcloud',       # 'nextcloud' or 'firebase'
    'server_url': '',
    'user': '',
    'app_password': '',
    'remote_dir': '/ClipSend',
    'fb_db_url': '',              # Firebase Realtime Database URL
    'fb_api_key': '',             # Firebase Web API key (not secret, identifies the project)
    'fb_email': '',
    'fb_uid': '',
    'fb_refresh_token': '',       # from signing in; the password itself is not stored
    'device_name': sanitize_device(socket.gethostname().split('.')[0]),
    'target': '*',                # '*' = all other devices
    'max_size_mb': 5.0,
    'max_age_min': 5,             # items older than this are deleted from the server
    'receive_enabled': True,
    'apply_to_clipboard': True,
    'set_selection': True,        # Linux: also replace the primary selection (middle-click paste)
    'download_dir': os.path.join(os.path.expanduser('~'), 'Downloads', 'ClipSend'),
    'use_push': True,
    'poll_interval': 0.5,
    'use_keyring': True,          # keep the device key's password in KWallet / Credential Manager
    'notify_sent': True,          # popup after sending
    'notify_received': True,      # popup after receiving (errors are always shown)
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
    if out['backend'] not in ('nextcloud', 'firebase'):
        out['backend'] = 'nextcloud'
    return out


def load_config():
    try:
        st = os.stat(CONFIG_FILE)
        if not WINDOWS and st.st_mode & 0o077:
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
    if cfg.get('backend') == 'firebase':
        return all(cfg.get(k) for k in ('fb_db_url', 'fb_api_key', 'fb_uid', 'fb_refresh_token'))
    return all(cfg.get(k) for k in ('server_url', 'user', 'app_password', 'remote_dir'))


# --------------------------------------------------------------------------- #
# device keys and end-to-end encryption
#
# Every device has its own key pair: Ed25519 (signing) + X25519 (encryption).
# The public half is published next to the device's inbox; another device uses
# it only after you confirmed its fingerprint (Devices… in the tray menu).
# Each item is encrypted for one target (ephemeral X25519 + HKDF + AES-256-GCM)
# and signed by the sender, so the server (or anyone with the storage login)
# can neither read nor forge items.
# --------------------------------------------------------------------------- #
class Rejected(Exception):
    pass


MAGIC = b'CLIPSEND/3\n'
KEY_FILE = os.path.join(CONFIG_DIR, 'device_key.json')
TRUST_FILE = os.path.join(CONFIG_DIR, 'trusted_devices.json')
KEYRING_SERVICE = 'ClipSend'
KEYRING_USER = 'device-key'
MAX_BUNDLE = 2048


def _raw_pub(k):
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _raw_priv(k):
    return k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())


def _b64e(b):
    return base64.b64encode(b).decode('ascii')


def _b64d(s, n=None):
    try:
        b = base64.b64decode(s, validate=True)
    except (ValueError, TypeError):
        raise Rejected('bad base64') from None
    if n is not None and len(b) != n:
        raise Rejected('bad key length')
    return b


def _bundle_signed_part(device, sign_pub, enc_pub):
    return b'clipsend-key-v1\n' + device.encode('ascii') + b'\n' + sign_pub + enc_pub


class PeerKey:
    """Public keys of a device."""

    def __init__(self, sign_pub, enc_pub):
        self.sign_pub, self.enc_pub = sign_pub, enc_pub
        Ed25519PublicKey.from_public_bytes(sign_pub)       # validate
        X25519PublicKey.from_public_bytes(enc_pub)

    @property
    def fingerprint(self):
        h = hashlib.sha256(b'clipsend-fp-v1' + self.sign_pub + self.enc_pub).hexdigest()[:32].upper()
        return ' '.join(h[i:i + 4] for i in range(0, 32, 4))

    def verify(self, sig, data):
        try:
            Ed25519PublicKey.from_public_bytes(self.sign_pub).verify(sig, data)
            return True
        except InvalidSignature:
            return False

    def __eq__(self, other):
        return isinstance(other, PeerKey) and (self.sign_pub, self.enc_pub) == (other.sign_pub, other.enc_pub)

    def to_dict(self):
        return {'sign': _b64e(self.sign_pub), 'enc': _b64e(self.enc_pub)}

    @classmethod
    def from_dict(cls, d):
        return cls(_b64d(d['sign'], 32), _b64d(d['enc'], 32))


class DeviceKey:
    """This device's private keys."""

    def __init__(self, sign_sk, enc_sk):
        self.sign_sk, self.enc_sk = sign_sk, enc_sk
        self.public = PeerKey(_raw_pub(sign_sk.public_key()), _raw_pub(enc_sk.public_key()))

    @classmethod
    def generate(cls):
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @classmethod
    def from_raw(cls, raw):
        if len(raw) != 64:
            raise ValueError('bad key file')
        return cls(Ed25519PrivateKey.from_private_bytes(raw[:32]), X25519PrivateKey.from_private_bytes(raw[32:]))

    def raw(self):
        return _raw_priv(self.sign_sk) + _raw_priv(self.enc_sk)

    def bundle(self, device):
        """Self-signed public key record that is published for the other devices."""
        p = self.public
        sig = self.sign_sk.sign(_bundle_signed_part(device, p.sign_pub, p.enc_pub))
        return json.dumps({'v': 1, 'device': device, 'sign': _b64e(p.sign_pub), 'enc': _b64e(p.enc_pub),
                           'sig': _b64e(sig)}, separators=(',', ':'))


def parse_bundle(text, device):
    """Published key record of `device` -> PeerKey. Raises Rejected if malformed or not self-signed."""
    if not isinstance(text, str) or len(text) > MAX_BUNDLE:
        raise Rejected('bad key record')
    try:
        d = json.loads(text)
    except ValueError:
        raise Rejected('bad key record') from None
    if not isinstance(d, dict) or d.get('v') != 1 or d.get('device') != device:
        raise Rejected('key record for another device')
    try:
        peer = PeerKey(_b64d(d.get('sign'), 32), _b64d(d.get('enc'), 32))
    except ValueError:
        raise Rejected('bad key') from None
    if not peer.verify(_b64d(d.get('sig'), 64), _bundle_signed_part(device, peer.sign_pub, peer.enc_pub)):
        raise Rejected('key record signature invalid')
    return peer


# ---- private key at rest: encrypted with a password (kept in the system keyring if possible) ----
def _password_key(password, salt):
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode('utf-8'))


def save_device_key(key, password, path=None):
    path = path or KEY_FILE
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_password_key(password, salt)).encrypt(nonce, key.raw(), b'clipsend-device-key-v1')
    data = json.dumps({'v': 1, 'kdf': 'scrypt', 'salt': _b64e(salt), 'nonce': _b64e(nonce), 'key': _b64e(ct)})
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = f'{path}.tmp{os.getpid()}'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(data + '\n')
    os.replace(tmp, path)


def load_device_key(password, path=None):
    """Raises ValueError('wrong password') or OSError."""
    with open(path or KEY_FILE, encoding='utf-8') as f:
        d = json.load(f)
    try:
        salt, nonce, ct = _b64d(d['salt'], 16), _b64d(d['nonce'], 12), _b64d(d['key'])
    except (KeyError, Rejected):
        raise ValueError('damaged key file') from None
    try:
        raw = AESGCM(_password_key(password, salt)).decrypt(nonce, ct, b'clipsend-device-key-v1')
    except InvalidTag:
        raise ValueError('wrong password') from None
    return DeviceKey.from_raw(raw)


def keyring_available():
    try:
        import keyring
        from keyring.backends import fail
        return not isinstance(keyring.get_keyring(), fail.Keyring)
    except Exception:
        return False


def keyring_get():
    try:
        import keyring
        return keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception as e:
        log.info('system keyring not usable: %s', e)
        return None


def keyring_set(password):
    try:
        import keyring
        keyring.set_password(KEYRING_SERVICE, KEYRING_USER, password)
        return True
    except Exception as e:
        log.warning('could not store the key password in the system keyring: %s', e)
        return False


def keyring_delete():
    try:
        import keyring
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:
        pass


# ---- confirmed devices ----
class TrustStore:
    """Devices whose fingerprint you confirmed. Thread safe; saved in TRUST_FILE."""

    def __init__(self, path=None):
        self.path = path or TRUST_FILE
        self._lock = threading.Lock()
        self._d = {}
        try:
            with open(self.path, encoding='utf-8') as f:
                for dev, v in json.load(f).items():
                    if DEVICE_RE.match(dev):
                        self._d[dev] = PeerKey.from_dict(v)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError, Rejected) as e:
            log.error('could not read %s: %s', self.path, e)

    def get(self, device):
        with self._lock:
            return self._d.get(device)

    def devices(self):
        with self._lock:
            return sorted(self._d)

    def set(self, device, peer):
        with self._lock:
            self._d[device] = peer
            self._save()

    def remove(self, device):
        with self._lock:
            self._d.pop(device, None)
            self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        tmp = f'{self.path}.tmp{os.getpid()}'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump({d: p.to_dict() for d, p in self._d.items()}, f, indent=2)
        os.replace(tmp, self.path)


# ---- sealing items ----
def _item_key(shared, eph_pub, recipient_pub, sender, recipient):
    info = b'clipsend-item-v3\n' + sender.encode() + b'\n' + recipient.encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub, info=info).derive(shared)


def seal(plain, my_key, sender, recipient, recipient_peer):
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_pub(eph.public_key())
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_peer.enc_pub))
    key = _item_key(shared, eph_pub, recipient_peer.enc_pub, sender, recipient)
    hdr = json.dumps({'from': sender, 'to': recipient, 'eph': _b64e(eph_pub)}, separators=(',', ':')).encode()
    nonce = os.urandom(12)
    head = MAGIC + struct.pack('>H', len(hdr)) + hdr + nonce
    body = head + AESGCM(key).encrypt(nonce, plain, head)
    return body + my_key.sign_sk.sign(body)


def unseal(blob, my_key, me, trust):
    """-> (sender, plaintext). Rejects anything not from a confirmed device, not for me, or tampered."""
    if not blob.startswith(MAGIC):
        raise Rejected('not a ClipSend item')
    p = len(MAGIC)
    if len(blob) < p + 2:
        raise Rejected('truncated item')
    (hlen,) = struct.unpack('>H', blob[p:p + 2])
    if hlen > 1024 or len(blob) < p + 2 + hlen + 12 + 16 + 64:
        raise Rejected('truncated item')
    try:
        hdr = json.loads(blob[p + 2:p + 2 + hlen])
        sender, to, eph_pub = hdr['from'], hdr['to'], _b64d(hdr['eph'], 32)
    except (ValueError, KeyError, TypeError):
        raise Rejected('bad item header') from None
    if not (isinstance(sender, str) and DEVICE_RE.match(sender)) or sender == me:
        raise Rejected('bad sender')
    if to != me:
        raise Rejected(f'item addressed to {to!r}, not to this device')
    peer = trust.get(sender)
    if peer is None:
        raise Rejected(f'item from {sender}, which is not confirmed: confirm it under Devices… first')
    body, sig = blob[:-64], blob[-64:]
    if not peer.verify(sig, body):
        raise Rejected(f'item from {sender} has an invalid signature (its key changed? check Devices…)')
    head_len = p + 2 + hlen + 12
    head, nonce = body[:head_len], body[head_len - 12:head_len]
    shared = my_key.enc_sk.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = _item_key(shared, eph_pub, my_key.public.enc_pub, sender, me)
    try:
        return sender, AESGCM(key).decrypt(nonce, body[head_len:], head)
    except InvalidTag:
        raise Rejected('could not decrypt the item') from None


# --------------------------------------------------------------------------- #
# message encoding / validation
# --------------------------------------------------------------------------- #
def wire_cap(max_bytes):
    """Upper bound for an encoded message (JSON, before/after compression) given a content limit."""
    return 2 * max_bytes + 256 * 1024


def encode_message(msg, my_key, recipient_peer, max_bytes):
    raw = json.dumps(msg, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(raw) > wire_cap(max_bytes):
        raise Rejected('content too large after encoding')
    return seal(zlib.compress(raw, 6), my_key, msg['from'], msg['to'], recipient_peer)


def decode_message(blob, my_key, trust, max_bytes, me):
    sender, comp = unseal(blob, my_key, me, trust)
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
    msg = validate_message(msg, max_bytes, me)
    if msg['from'] != sender:
        raise Rejected('sender mismatch')
    return msg


def _b64(s, budget):
    if not isinstance(s, str) or len(s) > wire_cap(budget):
        raise Rejected('bad data field')
    try:
        b = base64.b64decode(s, validate=True)
    except (ValueError, TypeError):
        raise Rejected('bad base64') from None
    return b


def validate_message(msg, max_bytes, me):
    if not isinstance(msg, dict) or msg.get('v') != 3:
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


_WIN_RESERVED = re.compile(r'^(con|prn|aux|nul|conin\$|conout\$|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$', re.I)


def win_safe_component(part):
    """Windows: no ':' (alternate data streams), no reserved device names, no trailing dots/spaces."""
    part = re.sub(r'[<>:"|?*]', '_', part).rstrip(' .')
    if _WIN_RESERVED.match(part):
        part = '_' + part
    return part


def safe_component(part):
    part = unicodedata.normalize('NFC', _BAD_CHARS.sub('', part)).strip()
    part = part.replace('/', '_').replace('\\', '_')
    if WINDOWS:
        part = win_safe_component(part)
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


_O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
_O_BINARY = getattr(os, 'O_BINARY', 0)       # Windows: otherwise os.open() is in text mode


def mark_of_the_web(path):
    """Tag a received file as 'downloaded from the internet' so Windows (SmartScreen,
    Office Protected View) warns before opening or running it."""
    try:
        with open(path + ':Zone.Identifier', 'w') as z:
            z.write('[ZoneTransfer]\r\nZoneId=3\r\n')
    except OSError:
        pass        # e.g. FAT drives have no alternate data streams




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
        if os.path.normcase(os.path.realpath(parent)) != os.path.normcase(os.path.abspath(parent)):
            raise Rejected('symlink in destination path')
        stem, ext = os.path.splitext(parts[-1])
        for n in range(1, 1000):
            try:
                # O_EXCL + O_NOFOLLOW: never overwrite or follow anything; 0o644: never executable
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINARY, 0o644)
                break
            except FileExistsError:
                target = os.path.join(parent, f'{stem} ({n + 1}){ext}')
        else:
            raise OSError('too many name collisions')
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        if WINDOWS:
            mark_of_the_web(target)
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
                    # always '/' on the wire (Windows would use '\\', which receivers reject)
                    add(fp, '/'.join([name] + os.path.relpath(fp, p).split(os.sep)))
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

    def __init__(self, server_url, user, password):
        import requests
        self.requests = requests
        u = check_server_url(server_url)
        self.host = u.hostname
        self.server = f'{u.scheme}://{u.netloc}{u.path}'
        self.user = user
        self.auth = (user, password)
        self.root_path = f'{u.path}/remote.php/dav/files/{urllib.parse.quote(user, safe="")}'
        self.root = f'{u.scheme}://{u.netloc}{self.root_path}'
        self.trash_root = (f'{u.scheme}://{u.netloc}{u.path}/remote.php/dav/trashbin/'
                           f'{urllib.parse.quote(user, safe="")}/trash')
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

    def reset(self):
        """Drop this thread's pooled connections (they are dead after suspend / network change)."""
        s = getattr(self._local, 's', None)
        self._local.s = None
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    def url(self, path):
        return self.root + urllib.parse.quote(path)

    def _req(self, method, path, ok=(200, 201, 204, 207), stream=False, timeout=(10, 30), base=None, **kw):
        url = (base or self.root) + urllib.parse.quote(path)
        r = self.s.request(method, url, timeout=timeout, allow_redirects=False, stream=stream, **kw)
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

    def propfind(self, path, depth, base=None):
        body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop>'
                '<d:getetag/><d:getcontentlength/><d:resourcetype/></d:prop></d:propfind>')
        # short timeouts: a poll stuck on a dead connection would keep the state stale
        r = self._req('PROPFIND', path, ok=(207, 404), stream=True, data=body, timeout=(6, 10), base=base,
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
        r = self._req('GET', path, ok=(200, 404), stream=True)
        if r.status_code == 404:
            r.close()
            return None
        return self._read_capped(r, cap)

    def delete(self, path):
        self._req('DELETE', path, ok=(204, 200, 404)).close()

    def trash_names(self):
        """Names in this account's trash bin ([] if the trash bin app is off)."""
        try:
            res = self.propfind('', 1, base=self.trash_root) or []
        except DavError:
            return []
        return [e['name'] for e in res if not e['dir']]

    def trash_delete(self, name):
        self._req('DELETE', '/' + name, ok=(204, 200, 404), base=self.trash_root).close()

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
# transports: where the inboxes live (Nextcloud WebDAV or Firebase Realtime Database)
# --------------------------------------------------------------------------- #
class PushUnavailable(Exception):
    """The backend offers no push channel: poll only."""


TRASH_RE = re.compile(r'^\d{13}-[0-9a-f]{32}\.clipsend\.d\d+$')


class NextcloudTransport:
    """Inboxes are folders <remote_dir>/inbox/<device>/, items are files."""
    kind = 'nextcloud'

    def __init__(self, cfg):
        self.dav = WebDav(cfg['server_url'], cfg['user'], cfg['app_password'])
        self.requests = self.dav.requests
        self.root = f'{norm_remote_dir(cfg["remote_dir"])}/inbox'
        self.keys = f'{norm_remote_dir(cfg["remote_dir"])}/keys'
        self._endpoint = None
        self._ws = None

    def _dir(self, device):
        return f'{self.root}/{device}'

    def register(self, me, bundle):
        """Create my inbox and publish my public key record."""
        self.dav.makedirs(self._dir(me))
        self.dav.makedirs(self.keys)
        self.dav.put(f'{self.keys}/{me}.json', bundle.encode('utf-8'))

    def device_keys(self):
        """{device: published key record (text)}"""
        out = {}
        for e in self.dav.listdir(self.keys) or []:
            dev = e['name'][:-5] if e['name'].endswith('.json') else ''
            if e['dir'] or not DEVICE_RE.match(dev):
                continue
            try:
                data = self.dav.get(f'{self.keys}/{e["name"]}', MAX_BUNDLE)
            except Rejected:
                continue
            if data is not None:
                out[dev] = data.decode('utf-8', 'replace')
        return out

    def inbox_version(self, me):
        """Changes whenever the inbox changes; None if the inbox is missing."""
        return self.dav.etag(self._dir(me))

    def list_items(self, device):
        entries = self.dav.listdir(self._dir(device)) or []
        return [{'name': e['name'], 'size': e['size']} for e in entries
                if not e['dir'] and MSG_RE.match(e['name'])]

    def fetch(self, device, name, cap):
        """Item content, or None if it is gone."""
        return self.dav.get(f'{self._dir(device)}/{name}', cap)

    def put(self, device, name, blob):
        self.dav.put(f'{self._dir(device)}/{name}', blob)

    def delete(self, device, name):
        self.dav.delete(f'{self._dir(device)}/{name}')

    def devices(self):
        entries = self.dav.listdir(self.root) or []
        return [e['name'] for e in entries if e['dir'] and DEVICE_RE.match(e['name'])]

    def purge_trash(self):
        """Deleted files go to the Nextcloud trash bin (kept 30 days by default): remove ours."""
        for name in self.dav.trash_names():
            if TRASH_RE.match(name):
                self.dav.trash_delete(name)

    def reset(self):
        self.dav.reset()

    def test(self):
        self.dav.makedirs(self.root)
        devs = self.devices()
        try:
            push = bool((self.dav.capabilities().get('notify_push') or {}).get('endpoints'))
        except Exception:
            push = False
        return devs, push

    def watch(self, me, stop):
        """Nextcloud notify_push websocket. Yields 'connected', then 'change' events."""
        try:
            import websocket   # websocket-client
        except ImportError:
            raise PushUnavailable('websocket-client not installed') from None
        if self._endpoint is None:
            caps = self.dav.capabilities()
            endpoint = ((caps.get('notify_push') or {}).get('endpoints') or {}).get('websocket')
            if not endpoint:
                raise PushUnavailable('server has no notify_push app')
            u = urllib.parse.urlsplit(endpoint)
            if u.scheme != 'wss' and u.hostname not in ('localhost', '127.0.0.1'):
                raise PushUnavailable(f'refusing non-TLS push endpoint {endpoint}')
            if u.hostname != self.dav.host:
                raise PushUnavailable(f'push endpoint on foreign host {u.hostname}: not sending credentials')
            self._endpoint = endpoint
        ws = websocket.create_connection(self._endpoint, timeout=30)
        self._ws = ws
        ws.send(self.dav.auth[0])
        ws.send(self.dav.auth[1])
        reply = ws.recv()
        if reply != 'authenticated':
            raise PushUnavailable(f'push login failed: {str(reply)[:100]!r}')
        yield 'connected'
        while not stop.is_set():
            try:
                m = ws.recv()
            except websocket.WebSocketTimeoutException:
                ws.ping()
                continue
            if isinstance(m, str) and m.startswith('notify_file'):
                yield 'change'

    def close_watch(self):
        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass


# ---- Firebase Realtime Database (REST API + server-sent events) ----
FB_HOST_RE = re.compile(r'^[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)?\.(firebaseio\.com|firebasedatabase\.app)$')
FB_API_KEY_RE = re.compile(r'^[A-Za-z0-9_-]{20,80}$')
FB_UID_RE = re.compile(r'^[A-Za-z0-9]{1,128}$')
FB_MAX_VALUE = 10 * 1024 * 1024 - 4096       # Realtime Database limit for one string value
FB_MAX_MB = 6.0                              # transfer size that still fits after base64
FB_SIGNIN_URL = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword'
FB_TOKEN_URL = 'https://securetoken.googleapis.com/v1/token'


def check_firebase_url(url):
    u = urllib.parse.urlsplit((url or '').strip().rstrip('/'))
    if (u.scheme != 'https' or not u.hostname or not FB_HOST_RE.match(u.hostname)
            or u.path not in ('', '/') or u.query or u.port):
        raise ValueError('database URL must look like '
                         'https://<project>-default-rtdb.europe-west1.firebasedatabase.app')
    return f'https://{u.hostname}'


def check_firebase_api_key(key):
    if not FB_API_KEY_RE.match(key or ''):
        raise ValueError('the Web API key looks wrong (Firebase console → Project settings → General)')
    return key


def _fb_error(r):
    try:
        return r.json()['error']['message']
    except Exception:
        return f'HTTP {r.status_code}'


def firebase_sign_in(api_key, email, password):
    """Email/password sign-in. Returns uid and a refresh token (the password is not kept)."""
    import requests
    check_firebase_api_key(api_key)
    r = requests.post(FB_SIGNIN_URL, params={'key': api_key}, timeout=(10, 30), allow_redirects=False,
                      json={'email': email, 'password': password, 'returnSecureToken': True},
                      headers={'User-Agent': f'ClipSend/{VERSION}'})
    if r.status_code != 200:
        raise AuthError(f'Firebase sign-in failed: {_fb_error(r)}')
    d = r.json()
    if not FB_UID_RE.match(d.get('localId', '')) or not d.get('refreshToken'):
        raise AuthError('Firebase sign-in returned an unexpected answer')
    return {'uid': d['localId'], 'refresh_token': d['refreshToken']}


class FirebaseAuth:
    """Short-lived ID tokens (1 h) from the stored refresh token. Thread safe."""

    def __init__(self, api_key, refresh_token, requests):
        self.api_key = check_firebase_api_key(api_key)
        self.refresh_token = refresh_token
        self.requests = requests
        self._lock = threading.Lock()
        self._token = None
        self._expires = 0.0

    def token(self):
        with self._lock:
            if self._token is None or time.monotonic() > self._expires:
                r = self.requests.post(FB_TOKEN_URL, params={'key': self.api_key}, timeout=(10, 30),
                                       allow_redirects=False, headers={'User-Agent': f'ClipSend/{VERSION}'},
                                       data={'grant_type': 'refresh_token', 'refresh_token': self.refresh_token})
                if r.status_code in (400, 401, 403):
                    raise AuthError(f'Firebase login expired or revoked ({_fb_error(r)}): '
                                    'sign in again in the settings')
                r.raise_for_status()
                d = r.json()
                self._token = d['id_token']
                self._expires = time.monotonic() + int(d.get('expires_in', 3600)) - 300
            return self._token

    def invalidate(self):
        with self._lock:
            self._token = None


def fb_key(device):
    """Firebase keys must not contain '.', which device names may: use ',' (not allowed in names)."""
    return device.replace('.', ',')


def fb_unkey(key):
    return key.replace(',', '.')


class FirebaseTransport:
    """Layout under users/<uid>/:  devices/<dev> = {seen, key},  inbox/<dev>/<ts-id> = base64 item,
    signal/<dev> = time of the last item (the receiver streams this small node only)."""
    kind = 'firebase'

    def __init__(self, cfg):
        import requests
        self.requests = requests
        self.db = check_firebase_url(cfg['fb_db_url'])
        if not FB_UID_RE.match(cfg['fb_uid']):
            raise ValueError('not signed in to Firebase: open the settings and sign in')
        self.base = f'/users/{cfg["fb_uid"]}'
        self.auth = FirebaseAuth(cfg['fb_api_key'], cfg['fb_refresh_token'], requests)
        self._local = threading.local()
        self._watch_resp = None

    @property
    def s(self):
        s = getattr(self._local, 's', None)
        if s is None:
            s = self.requests.Session()
            s.headers['User-Agent'] = f'ClipSend/{VERSION}'
            s.max_redirects = 0
            self._local.s = s
        return s

    def reset(self):
        s = getattr(self._local, 's', None)
        self._local.s = None
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    def _req(self, method, path, params=None, stream=False, timeout=(6, 15), **kw):
        url = f'{self.db}{self.base}{path}.json'
        for attempt in (1, 2):
            p = dict(params or {}, auth=self.auth.token())
            r = self.s.request(method, url, params=p, timeout=timeout, allow_redirects=False,
                               stream=stream, **kw)
            if r.status_code in (401, 403):
                r.close()
                self.auth.invalidate()          # token may just have expired: retry once
                if attempt == 1:
                    continue
                raise AuthError('Firebase denied access: check the login and the database rules')
            if r.status_code != 200:
                r.close()
                raise DavError(f'{method} {path}: HTTP {r.status_code}')
            return r

    def _json(self, method, path, cap=MAX_PROPFIND_BYTES, **kw):
        r = self._req(method, path, stream=True, **kw)
        buf = bytearray()
        for chunk in r.iter_content(64 * 1024):
            buf += chunk
            if len(buf) > cap:
                r.close()
                raise Rejected(f'server response exceeds {human_size(cap)}')
        return json.loads(bytes(buf) or b'null')

    def _keys(self, path):
        d = self._json('GET', path, params={'shallow': 'true'})
        return sorted(d) if isinstance(d, dict) else []

    @staticmethod
    def _item_key(name):
        m = MSG_RE.match(name)
        if not m:
            raise ValueError(f'bad item name {name!r}')
        return f'{m.group(1)}-{m.group(2)}'

    def register(self, me, bundle):
        """Publish my public key record (the inbox node appears with the first item)."""
        self._req('PUT', f'/devices/{fb_key(me)}', json={'seen': {'.sv': 'timestamp'}, 'key': bundle}).close()

    def device_keys(self):
        d = self._json('GET', '/devices')
        out = {}
        for k, v in (d.items() if isinstance(d, dict) else ()):
            dev = fb_unkey(k)
            if DEVICE_RE.match(dev) and isinstance(v, dict) and isinstance(v.get('key'), str):
                out[dev] = v['key']
        return out

    def inbox_version(self, me):
        return ','.join(self._keys(f'/inbox/{fb_key(me)}'))

    def list_items(self, device):
        return [{'name': f'{k}.clipsend', 'size': 0} for k in self._keys(f'/inbox/{fb_key(device)}')
                if MSG_RE.match(f'{k}.clipsend')]

    def fetch(self, device, name, cap):
        v = self._json('GET', f'/inbox/{fb_key(device)}/{self._item_key(name)}', cap=cap * 4 // 3 + 64)
        if v is None:
            return None
        if not isinstance(v, str):
            raise Rejected('malformed item')
        try:
            return base64.b64decode(v, validate=True)
        except ValueError:
            raise Rejected('malformed item') from None

    def put(self, device, name, blob):
        value = base64.b64encode(blob).decode('ascii')
        if len(value) + 2 > FB_MAX_VALUE:
            raise Rejected(f'too large for Firebase (at most about {FB_MAX_MB:g} MB per item)')
        self._req('PUT', f'/inbox/{fb_key(device)}/{self._item_key(name)}', json=value,
                  timeout=(10, 120)).close()
        self._req('PUT', f'/signal/{fb_key(device)}', json={'.sv': 'timestamp'}).close()

    def delete(self, device, name):
        self._req('DELETE', f'/inbox/{fb_key(device)}/{self._item_key(name)}').close()

    def devices(self):
        return [d for d in map(fb_unkey, self._keys('/devices')) if DEVICE_RE.match(d)]

    def purge_trash(self):
        pass                                    # deleted Firebase data is gone

    def test(self):
        return self.devices(), True

    def watch(self, me, stop):
        """Server-sent events on signal/<me>. Yields 'connected', then 'change' events.
        Firebase sends keep-alive every ~30 s; the read timeout catches dead connections."""
        r = self._req('GET', f'/signal/{fb_key(me)}', stream=True, timeout=(10, 75),
                      headers={'Accept': 'text/event-stream'})
        self._watch_resp = r
        event, connected = None, False
        for raw in r.iter_lines(chunk_size=1):
            if stop.is_set():
                return
            line = raw.decode('utf-8', 'replace')
            if line.startswith('event:'):
                event = line[6:].strip()
            elif line.startswith('data:'):
                if event in ('put', 'patch'):
                    if not connected:
                        connected = True
                        yield 'connected'
                    yield 'change'
                elif event == 'auth_revoked':   # ID token expired (hourly): reconnect with a new one
                    self.auth.invalidate()
                    return
                elif event == 'cancel':
                    raise AuthError('Firebase cancelled the stream: check the database rules')

    def close_watch(self):
        r, self._watch_resp = self._watch_resp, None
        if r is not None:
            try:
                r.close()
            except Exception:
                pass


def make_transport(cfg):
    return FirebaseTransport(cfg) if cfg['backend'] == 'firebase' else NextcloudTransport(cfg)


# --------------------------------------------------------------------------- #
# clipboard access
# --------------------------------------------------------------------------- #
def is_wayland():
    return bool(os.environ.get('WAYLAND_DISPLAY')) or os.environ.get('XDG_SESSION_TYPE') == 'wayland'


class Clipboard:
    """Wayland: wl-clipboard (works without focus via data-control on KWin). X11: QClipboard."""

    def __init__(self):
        self.selection = False     # also write the primary selection (Linux, set by the tray app)
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

    def _read_qt(self, max_bytes):
        md = QtGui.QGuiApplication.clipboard().mimeData()
        if md is None:
            return {'kind': 'none'}
        if md.hasUrls():
            urls = list(md.urls())
            if urls and all(u.isLocalFile() for u in urls):
                paths = [u.toLocalFile() for u in urls]
                if all(os.path.exists(p) for p in paths):
                    return {'kind': 'files', 'paths': paths}
        formats = list(md.formats())
        images = [t for t in formats if t.lower() in IMAGE_MAGIC]
        if images:
            mime = 'image/png' if 'image/png' in images else images[0]
            data = self.get(mime, max_bytes)
            if data:
                return {'kind': 'image', 'mime': mime.lower(), 'data': data}
        if md.hasImage():           # image without an encoded format: convert to PNG
            img = md.imageData()
            if isinstance(img, QtGui.QImage) and not img.isNull():
                buf = QtCore.QBuffer()
                buf.open(qenum(QtCore.QIODevice, 'OpenModeFlag', 'WriteOnly'))
                img.save(buf, 'PNG')
                data = bytes(buf.data())
                if len(data) > max_bytes:
                    raise Rejected(f'image is larger than the limit ({human_size(max_bytes)})')
                return {'kind': 'image', 'mime': 'image/png', 'data': data}
        text = self.get_text(formats, max_bytes)
        if text:
            return {'kind': 'text', 'text': text}
        return {'kind': 'none'}

    def read(self, max_bytes):
        """Return a content dict describing the clipboard."""
        if not self.wl:
            return self._read_qt(max_bytes)
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
        for extra in (['--primary'] if self.selection else []) + [None]:
            p = subprocess.Popen(['wl-copy', '--type', mime] + ([extra] if extra else []),
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p.communicate(data, timeout=10)
            if p.returncode != 0:
                if extra:           # compositor without primary selection: the clipboard still counts
                    log.warning('wl-copy --primary failed (%s)', p.returncode)
                    continue
                raise OSError(f'wl-copy failed ({p.returncode})')

    @staticmethod
    def _qt_clipboard():
        return QtGui.QGuiApplication.clipboard()

    def _qt_set(self, make_mime):
        """make_mime() builds a fresh QMimeData for each buffer (Qt takes ownership)."""
        cb = self._qt_clipboard()
        if self.selection and cb.supportsSelection():
            cb.setMimeData(make_mime(), qenum(QtGui.QClipboard, 'Mode', 'Selection'))
        cb.setMimeData(make_mime(), qenum(QtGui.QClipboard, 'Mode', 'Clipboard'))

    def set_text(self, text):
        if self.wl:
            return self._wl_copy('text/plain;charset=utf-8', text.encode('utf-8', 'surrogatepass'))

        def make():
            md = QtCore.QMimeData()
            md.setText(text)
            return md
        self._qt_set(make)

    def set_image(self, mime, data):
        if self.wl:
            return self._wl_copy(mime, data)
        img = QtGui.QImage.fromData(data)

        def make():
            md = QtCore.QMimeData()
            md.setData(mime, QtCore.QByteArray(data))
            if not img.isNull():
                md.setImageData(img)
            return md
        self._qt_set(make)

    def set_files(self, paths):
        uris = [QtCore.QUrl.fromLocalFile(p) for p in paths]
        if self.wl:
            data = ''.join(bytes(u.toEncoded()).decode('ascii') + '\r\n' for u in uris)
            return self._wl_copy('text/uri-list', data.encode('ascii'))

        def make():
            md = QtCore.QMimeData()
            md.setUrls(uris)
            return md
        self._qt_set(make)


# --------------------------------------------------------------------------- #
# sync engine (network side, runs in background threads)
# --------------------------------------------------------------------------- #
CERT_HINT = ("The server's HTTPS certificate is not trusted, e.g. because a firewall inspects the "
             "connection. ClipSend never bypasses this. If the inspection is legitimate (e.g. your "
             "institute's firewall), its CA certificate must be in the system's certificate store and "
             "the Python package 'truststore' installed. ClipSend checks again in 10 minutes.")


_RETIRED = []       # stopped engines whose threads have not ended yet (see Engine.stop)


class Engine(QtCore.QObject):
    received = Signal(object)        # validated message dict
    receiving = Signal(bool)         # downloading incoming items (tray icon blinks)
    sent = Signal(str)               # summary
    error = Signal(str, str)         # title, message
    status = Signal(str)             # short status for the tooltip
    devices_changed = Signal(object)

    SWEEP_EVERY = 60.0               # s: delete expired items in all inboxes

    def __init__(self, cfg, my_key, trust):
        super().__init__()
        import requests
        self.cfg = cfg
        self.me = cfg['device_name']
        self.max_bytes = int(cfg['max_size_mb'] * 1024 * 1024)
        self.t = make_transport(cfg)
        self._ssl_error = requests.exceptions.SSLError
        self.my_key, self.trust = my_key, trust
        self.peers = {}                  # device -> published PeerKey (None if the record is invalid)
        self.devices = []
        self.push_ok = False
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._send_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._last_status = None
        self._threads = []

    # ---- lifecycle ----
    def _spawn(self, target, name, *args):
        self._threads = [t for t in self._threads if t.is_alive()]
        th = threading.Thread(target=target, args=args, name=name, daemon=True)
        self._threads.append(th)
        th.start()

    def start(self):
        self._spawn(self._poll_loop, 'clipsend-poll')
        if self.cfg['use_push'] and self.cfg['receive_enabled']:
            self._spawn(self._push_loop, 'clipsend-push')

    def stop(self):
        """Stop the threads. A request in progress can take a while to return, so the engine stays
        referenced until all its threads have ended: freeing the Qt object while a thread may
        still emit one of its signals crashes."""
        self._stop.set()
        self._wake.set()
        self.t.close_watch()
        _RETIRED[:] = [e for e in _RETIRED if e.alive()]
        if self.alive():
            _RETIRED.append(self)

    def alive(self):
        return any(t.is_alive() for t in self._threads)

    def join(self, timeout=10.0):
        end = time.monotonic() + timeout
        for t in list(self._threads):
            t.join(max(0.0, end - time.monotonic()))
        return not self.alive()

    def wake(self):
        self._wake.set()

    def _emit(self, sig, *args):
        if not self._stop.is_set():
            sig.emit(*args)

    # ---- connection state (one place, so the tray icon cannot get out of sync) ----
    def _set_status(self, s):
        with self._status_lock:
            if s == self._last_status:
                return
            self._last_status = s
        log.info('state: %s', s)
        self._emit(self.status, s)

    def _mark_ok(self):
        """Any successful request (poll, send, push) proves we are connected."""
        self._set_status('connected (push)' if self.push_ok else 'connected')

    def _mark_failed(self, e):
        self._set_status(f'offline ({type(e).__name__}), retrying')

    def _sleep(self, delay):
        """Wait for `delay` seconds, a wake() or a resume from suspend (returns True then).
        Waits in short slices: monotonic clocks stop during suspend, the wall clock does not."""
        end = time.monotonic() + delay
        resumed = False
        while not self._stop.is_set():
            left = end - time.monotonic()
            if left <= 0:
                break
            step = min(left, 2.0)
            wall = time.time()
            if self._wake.wait(step):
                break
            if time.time() - wall > step + 5:
                log.info('system resumed from suspend')
                resumed = True
                break
        self._wake.clear()
        return resumed

    # ---- receiving ----
    def _poll_loop(self):
        last_version, fails, next_dev_refresh, next_sweep = None, 0, 0.0, 0.0
        ready = False
        while not self._stop.is_set():
            delay = None
            try:
                if not ready:
                    self.t.register(self.me, self.my_key.bundle(self.me))
                    ready = True
                if self.cfg['receive_enabled']:
                    version = self.t.inbox_version(self.me)
                    if version is None:
                        ready = False
                    elif version != last_version:
                        self._process_inbox()
                        last_version = version
                now = time.monotonic()
                if now >= next_dev_refresh:
                    self.refresh_devices()
                    next_dev_refresh = now + 60
                if now >= next_sweep:
                    self._sweep()
                    next_sweep = now + self.SWEEP_EVERY
                fails = 0
                self._mark_ok()
            except AuthError as e:
                if self._last_status != 'login failed':
                    self._emit(self.error, 'ClipSend: login failed', str(e))
                self._set_status('login failed')
                delay = 600.0         # do not hammer the server (brute-force lockout)
            except self._ssl_error as e:
                # e.g. a firewall that intercepts HTTPS: never bypass, and do not retry every few seconds
                self.t.reset()
                if self._last_status != 'certificate error':
                    log.warning('TLS error, pausing for 10 min: %s', e)
                    self._emit(self.error, 'ClipSend: connection not trusted', CERT_HINT)
                self._set_status('certificate error')
                delay = 600.0
            except Exception as e:
                fails += 1
                log.warning('poll error: %s', e)
                # pooled keep-alive connections are dead after suspend / network change and
                # can stay broken: always reconnect from scratch
                self.t.reset()
                if fails == 1:
                    delay = 0.3       # usually just a stale connection: retry at once, keep the state
                else:
                    self._mark_failed(e)
                    delay = min(15.0, 2.0 * 2 ** (fails - 2))
            if delay is None:
                delay = 30.0 if self.push_ok else self.cfg['poll_interval']
            if self._sleep(delay):
                fails = min(fails, 1)  # resumed: retry quickly instead of waiting out the backoff
                self.t.reset()

    def _process_inbox(self):
        items = sorted(self.t.list_items(self.me), key=lambda e: e['name'])[:MAX_BATCH]
        if not items:
            return
        self._emit(self.receiving, True)
        try:
            self._process_items(items)
        finally:
            self._emit(self.receiving, False)

    def _process_items(self, items):
        cap = wire_cap(self.max_bytes)
        for e in items:
            if self._stop.is_set():
                return
            name = e['name']
            try:
                if e['size'] > cap:
                    raise Rejected(f'item too large ({human_size(e["size"])})')
                # network errors propagate to the poll loop (item stays for the next attempt)
                blob = self.t.fetch(self.me, name, cap)
            except Rejected as ex:
                log.warning('rejected %s: %s', name, ex)
                self._emit(self.error, 'ClipSend: rejected incoming item', clean_display(str(ex), 300))
                self._delete_quietly(self.me, name)
                continue
            if blob is None:            # already gone (e.g. expired and swept)
                continue
            self._delete_quietly(self.me, name)    # read successfully: remove it from the server
            try:
                msg = decode_message(blob, self.my_key, self.trust, self.max_bytes, self.me)
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
                log.warning('rejected %s: %s', name, ex)
                self._emit(self.error, 'ClipSend: rejected incoming item', clean_display(str(ex), 300))
            except OSError as ex:      # writing files failed
                log.warning('failed to process %s: %s', name, ex)
                self._emit(self.error, 'ClipSend: receive failed', clean_display(str(ex), 300))

    def _delete_quietly(self, device, name):
        try:
            self.t.delete(device, name)
        except Exception as ex:
            log.warning('could not delete %s/%s: %s', device, name, ex)

    def _sweep(self):
        """Delete items older than max_age from every inbox, also those of devices that are off,
        so nothing stays on the server for long even if the receiver never picks it up."""
        cutoff_ms = (time.time() - self.cfg['max_age_min'] * 60) * 1000
        for dev in sorted(set(self.t.devices()) | {self.me}):
            for e in self.t.list_items(dev):
                m = MSG_RE.match(e['name'])
                if m and int(m.group(1)) < cutoff_ms:
                    log.info('deleting expired item for %s', dev)
                    self._delete_quietly(dev, e['name'])
        self.t.purge_trash()

    def refresh_devices(self):
        """Read the published keys of all devices. Using one still needs your confirmation."""
        peers = {}
        for dev, text in self.t.device_keys().items():
            if dev == self.me:
                continue
            try:
                peers[dev] = parse_bundle(text, dev)
            except Rejected as e:
                log.warning('ignoring key record of %s: %s', dev, e)
                peers[dev] = None
        changed = peers != self.peers
        self.peers, self.devices = peers, sorted(peers)
        if changed:
            self._emit(self.devices_changed, dict(peers))
        return self.devices

    # ---- push (Nextcloud notify_push / Firebase event stream) ----
    def _push_loop(self):
        backoff = 5
        while not self._stop.is_set():
            clean_end = False
            try:
                for ev in self.t.watch(self.me, self._stop):
                    if ev == 'connected':
                        log.info('push connected (%s)', self.t.kind)
                        self.push_ok = True
                        self._mark_ok()
                        backoff = 5
                    self._wake.set()      # check the inbox now
                clean_end = True
            except PushUnavailable as e:
                log.info('%s: polling every %.1fs', e, self.cfg['poll_interval'])
                return
            except Exception as e:
                if self._stop.is_set():
                    break
                if isinstance(e, (AuthError, self._ssl_error)) or 'CERTIFICATE_VERIFY_FAILED' in str(e):
                    backoff = 600     # wrong login / untrusted certificate: no fast retries
                log.info('push connection lost (%s), reconnect in %ss', e, backoff)
            finally:
                if self.push_ok:
                    self.push_ok = False
                    self._wake.set()      # poll right away; it updates the state
                self.t.close_watch()
                self.t.reset()
            if clean_end:             # e.g. hourly token renewal: reconnect at once
                self._stop.wait(1)
                continue
            self._stop.wait(backoff)
            backoff = min(300, backoff * 2)

    # ---- sending ----
    def send_async(self, content, target):
        if not self._send_lock.acquire(blocking=False):
            self._emit(self.error, 'ClipSend', 'Still sending the previous item…')
            return
        self._spawn(self._send, 'clipsend-send', content, target)

    def _send(self, content, target):
        try:
            kind = content['kind']
            msg = {'v': 3, 'from': self.me, 'kind': kind}
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

            self.refresh_devices()
            if target and target != '*':
                candidates = [target]
            else:
                candidates = sorted(set(self.devices) | set(self.trust.devices()))
            targets, problems, unconfirmed = [], [], 0
            for t in candidates:
                pinned, published = self.trust.get(t), self.peers.get(t)
                if pinned is None:
                    unconfirmed += 1
                    problems.append(f'{t} is not confirmed yet (tray menu: Devices…)')
                elif published is not None and published != pinned:
                    problems.append(f'{t} has a new key: check and confirm it again under Devices…')
                elif t in self.devices or target == t:
                    targets.append(t)
            if not targets:
                raise Rejected('; '.join(problems) or 'no other device found - start ClipSend on the other '
                               'machine and confirm it under Devices…')
            if unconfirmed and target in (None, '', '*'):
                summary += f' ({unconfirmed} unconfirmed device{"s" if unconfirmed != 1 else ""} skipped)'
            for t in targets:
                msg.update(to=t, ts=time.time(), id=uuid.uuid4().hex)
                blob = encode_message(msg, self.my_key, self.trust.get(t), self.max_bytes)
                name = f'{int(msg["ts"] * 1000):013d}-{msg["id"]}.clipsend'
                self.t.put(t, name, blob)
                log.info('sent %s to %s (%s on the wire)', kind, t, human_size(len(blob)))
            self._mark_ok()
            self._emit(self.sent, f'{summary} → {", ".join(targets)}')
        except Rejected as e:
            self._emit(self.error, 'ClipSend: not sent', clean_display(str(e), 300))
        except AuthError as e:
            self._emit(self.error, 'ClipSend: login failed', str(e))
        except self._ssl_error as e:
            log.warning('send failed, TLS error: %s', e)
            self._emit(self.error, 'ClipSend: not sent', CERT_HINT)
        except Exception as e:
            log.exception('send failed')
            self._emit(self.error, 'ClipSend: send failed', clean_display(f'{type(e).__name__}: {e}', 300))
            self._wake.set()          # let the poll loop re-check the connection
        finally:
            self.t.reset()            # this thread ends; do not leak its connections
            self._send_lock.release()

    # ---- used by the settings dialog ----
    @staticmethod
    def test_connection(cfg):
        """Returns (registered devices, push available)."""
        return make_transport(cfg).test()


# --------------------------------------------------------------------------- #
# local control socket (`clipsend --send` etc.)
# --------------------------------------------------------------------------- #
COMMANDS = ('send', 'settings', 'quit', 'ping')


def sock_path():
    return os.path.join(runtime_dir(), f'{APP}.sock')


def pipe_name():
    import getpass
    return 'clipsend-' + re.sub(r'[^A-Za-z0-9_.-]', '_', getpass.getuser())


class WinControlServer(QtCore.QObject):
    """Windows: named pipe via QLocalServer, restricted to the current user."""
    command = Signal(str)

    def start(self):
        from importlib import import_module
        QtNetwork = import_module(f'{QT_API}.QtNetwork')
        self.server = QtNetwork.QLocalServer(self)
        self.server.setSocketOptions(qenum(QtNetwork.QLocalServer, 'SocketOption', 'UserAccessOption'))
        QtNetwork.QLocalServer.removeServer(pipe_name())
        if not self.server.listen(pipe_name()):
            raise OSError(f'cannot listen on control pipe: {self.server.errorString()}')
        self.server.newConnection.connect(self._new_connection)

    def _new_connection(self):
        while self.server.hasPendingConnections():
            conn = self.server.nextPendingConnection()
            conn.readyRead.connect(lambda c=conn: self._read(c))
            conn.disconnected.connect(conn.deleteLater)
            if conn.bytesAvailable():       # data may have arrived before readyRead was connected
                self._read(conn)

    def _read(self, conn):
        if not conn.canReadLine():
            if conn.bytesAvailable() > 64:
                conn.abort()
            return
        cmd = bytes(conn.readLine(64)).decode('ascii', 'ignore').strip()
        conn.write(b'ok\n' if cmd in COMMANDS else b'unknown command\n')
        conn.flush()
        if cmd in COMMANDS and cmd != 'ping':
            QtCore.QTimer.singleShot(50, lambda: self.command.emit(cmd))

    def close(self):
        self.server.close()


def win_send_command(cmd):
    from importlib import import_module
    QtNetwork = import_module(f'{QT_API}.QtNetwork')
    if QtCore.QCoreApplication.instance() is None:
        win_send_command._app = QtCore.QCoreApplication([])
    s = QtNetwork.QLocalSocket()
    s.connectToServer(pipe_name())
    if not s.waitForConnected(2000):
        return False
    s.write(cmd.encode() + b'\n')
    s.waitForBytesWritten(1000)
    if not s.waitForReadyRead(3000):
        return False
    return bytes(s.readAll()).strip() == b'ok'


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
                        conn.sendall(b'ok\n')       # reply first: 'quit' may end the process
                        if cmd != 'ping':
                            self.command.emit(cmd)
                    else:
                        conn.sendall(b'unknown command\n')
                except OSError:
                    pass

    def close(self):
        self.sock.close()
        try:
            os.unlink(sock_path())
        except OSError:
            pass


def send_command(cmd):
    if WINDOWS:
        return win_send_command(cmd)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(sock_path())
            s.sendall(cmd.encode() + b'\n')
            return s.recv(64).decode().strip() == 'ok'
    except OSError:
        return False


def wait_for_exit(timeout=15.0):
    """After 'quit': wait until the instance released its lock (X11 clipboard hand-over can take a while)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        fd = acquire_lock()
        if fd is not None:
            os.close(fd)
            return True
        time.sleep(0.2)
    return False


def acquire_lock():
    path = os.path.join(runtime_dir(), f'{APP}.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    if WINDOWS:
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            os.close(fd)
            return None
        return fd
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        os.close(fd)
        if e.errno in (errno.EAGAIN, errno.EACCES):
            return None
        raise
    return fd


# --------------------------------------------------------------------------- #
# devices dialog: confirm other devices by comparing fingerprints (manual)
# --------------------------------------------------------------------------- #
def device_status(dev, published, pinned):
    """(status text, usable) for a device, from its published key and the confirmed one."""
    if pinned is not None:
        if published is not None and published != pinned:
            return 'KEY CHANGED - blocked until confirmed again', False
        return 'confirmed', True
    if published is None:
        return 'invalid key record', False
    return 'new - not confirmed', False


def pending_devices(peers, trust):
    """Devices with a valid published key that is not (or no longer) confirmed."""
    return sorted(d for d, p in peers.items() if p is not None and trust.get(d) != p)


def device_prompt_text(dev, pub, pinned, me, my_pub):
    """Text of the popup that asks whether to accept a new (or changed) device key."""
    if pinned is not None:
        head = (f'The key of "{dev}" has CHANGED. Until you accept the new key, nothing is sent to or '
                f'accepted from "{dev}".\n\nAccept it only if you made a new key on "{dev}" yourself '
                '(or reinstalled it).')
    else:
        head = f'"{dev}" wants to exchange clipboards with this device.'
    return (f'{head}\n\n'
            f'Fingerprint of "{dev}":\n    {pub.fingerprint}\n\n'
            f'Fingerprint of this device ("{me}"):\n    {my_pub.fingerprint}\n\n'
            f'Check that "{dev}" shows the same two fingerprints, the other way round. Accept only if '
            'they match. You can also do this later under Devices… in the tray menu.')


class DevicesDialog(QtWidgets.QDialog):
    def __init__(self, me, my_key, peers, trust, parent=None):
        super().__init__(parent)
        W = QtWidgets
        self.setWindowTitle('ClipSend Devices')
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(640)
        self.peers, self.trust = peers, trust
        self.new_key_requested = False
        lay = W.QVBoxLayout(self)

        mine = W.QLabel(f'This device: <b>{html.escape(me)}</b><br>'
                        f'Fingerprint: <tt>{my_key.public.fingerprint if my_key else "(locked)"}</tt>')
        mine.setTextInteractionFlags(qenum(QtCore.Qt, 'TextInteractionFlag', 'TextSelectableByMouse'))
        lay.addWidget(mine)
        hint = W.QLabel('Confirm a device only after checking that the fingerprint shown here is exactly '
                        'the one that device shows for itself in its own Devices window. ClipSend sends '
                        'nothing to unconfirmed devices and rejects everything they send.')
        hint.setWordWrap(True)
        lay.addWidget(hint)

        self.table = W.QTreeWidget()
        self.table.setHeaderLabels(['Device', 'Fingerprint', 'Status'])
        self.table.setRootIsDecorated(False)
        lay.addWidget(self.table)

        row = W.QHBoxLayout()
        self.btn_confirm = W.QPushButton('Confirm…')
        self.btn_confirm.clicked.connect(self._confirm)
        self.btn_remove = W.QPushButton('Remove confirmation')
        self.btn_remove.clicked.connect(self._remove)
        newkey = W.QPushButton('New key for this device…')
        newkey.clicked.connect(self._new_key)
        close = W.QPushButton('Close')
        close.clicked.connect(self.accept)
        row.addWidget(self.btn_confirm)
        row.addWidget(self.btn_remove)
        row.addStretch(1)
        row.addWidget(newkey)
        row.addWidget(close)
        lay.addLayout(row)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self._fill()

    def _fill(self):
        self.table.clear()
        for dev in sorted(set(self.peers) | set(self.trust.devices())):
            pub, pinned = self.peers.get(dev), self.trust.get(dev)
            status, _ = device_status(dev, pub, pinned)
            if dev not in self.peers:
                status += ' (no key published right now)'
            fp = (pub or pinned).fingerprint if (pub or pinned) else ''
            item = QtWidgets.QTreeWidgetItem([dev, fp, status])
            item.setData(0, qenum(QtCore.Qt, 'ItemDataRole', 'UserRole'), dev)
            self.table.addTopLevelItem(item)
        for i in range(3):
            self.table.resizeColumnToContents(i)
        self._update_buttons()

    def _selected(self):
        items = self.table.selectedItems()
        return items[0].data(0, qenum(QtCore.Qt, 'ItemDataRole', 'UserRole')) if items else None

    def _update_buttons(self):
        dev = self._selected()
        pub = self.peers.get(dev) if dev else None
        self.btn_confirm.setEnabled(bool(dev) and pub is not None and self.trust.get(dev) != pub)
        self.btn_remove.setEnabled(bool(dev) and self.trust.get(dev) is not None)

    def _confirm(self):
        dev = self._selected()
        pub = self.peers.get(dev)
        if not dev or pub is None:
            return
        W = QtWidgets.QMessageBox
        ans = W.question(self, 'Confirm device',
                         f'On "{dev}", open Devices… and check that it shows exactly this fingerprint '
                         f'for itself:\n\n{pub.fingerprint}\n\nConfirm only if they match. Do they match?')
        if ans == qenum(W, 'StandardButton', 'Yes'):
            self.trust.set(dev, pub)
            log.info('confirmed device %s (%s)', dev, pub.fingerprint)
            self._fill()

    def _remove(self):
        dev = self._selected()
        if dev:
            self.trust.remove(dev)
            log.info('removed confirmation of %s', dev)
            self._fill()

    def _new_key(self):
        W = QtWidgets.QMessageBox
        ans = W.question(self, 'New key',
                         'Create a new key for this device?\n\nAll other devices will block this device '
                         'until you confirm it there again.')
        if ans == qenum(W, 'StandardButton', 'Yes'):
            self.new_key_requested = True
            self.accept()


def ask_password(parent, title, label):
    W = QtWidgets
    pw, ok = W.QInputDialog.getText(parent, title, label, qenum(W.QLineEdit, 'EchoMode', 'Password'))
    return pw if ok else None


def ask_new_password(parent, reason):
    while True:
        pw = ask_password(parent, 'ClipSend: protect the device key',
                          f'{reason}\n'
                          'Choose a password for this device\'s key. You will enter it when ClipSend starts.\n'
                          'At least 8 characters:')
        if pw is None:
            return None
        if len(pw) < 8:
            QtWidgets.QMessageBox.warning(parent, 'ClipSend', 'Use at least 8 characters.')
            continue
        if ask_password(parent, 'ClipSend: protect the device key', 'Repeat the password:') != pw:
            QtWidgets.QMessageBox.warning(parent, 'ClipSend', 'The passwords differ.')
            continue
        return pw


# --------------------------------------------------------------------------- #
# Windows: start at login via a visible launcher in the user's Startup folder
# (no registry changes, no installer; plain Python)
# --------------------------------------------------------------------------- #
def startup_launcher_path():
    return os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs',
                        'Startup', 'ClipSend.pyw')


def get_autostart():
    return WINDOWS and os.path.exists(startup_launcher_path())


def set_autostart(on):
    path = startup_launcher_path()
    if on:
        script = os.path.abspath(__file__)
        with open(path, 'w', encoding='utf-8') as f:
            f.write('# Starts ClipSend when you log in. Created by ClipSend (Settings: Start at login).\n'
                    '# Delete this file, or untick the setting, to stop that.\n'
                    'import runpy, sys\n'
                    f'sys.argv = [{script!r}]\n'
                    f'runpy.run_path({script!r}, run_name="__main__")\n')
    else:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


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

        # backend
        row = W.QHBoxLayout()
        self.backend = W.QComboBox()
        self.backend.addItem('Nextcloud (WebDAV)', 'nextcloud')
        self.backend.addItem('Google Firebase (Realtime Database)', 'firebase')
        self.backend.setCurrentIndex(max(0, self.backend.findData(cfg['backend'])))
        test = W.QPushButton('Test connection')
        test.clicked.connect(self._test)
        row.addWidget(W.QLabel('Storage'))
        row.addWidget(self.backend, 1)
        row.addWidget(test)
        lay.addLayout(row)

        # connection: Nextcloud
        g = self.nc_group = W.QGroupBox('Nextcloud connection')
        f = W.QFormLayout(g)
        self.url = W.QLineEdit(cfg['server_url'])
        self.url.setPlaceholderText('https://cloud.example.com')
        self.user = W.QLineEdit(cfg['user'])
        self.pw = W.QLineEdit(cfg['app_password'])
        self.pw.setEchoMode(qenum(W.QLineEdit, 'EchoMode', 'Password'))
        self.pw.setToolTip('Use an app password (Nextcloud → Settings → Security), ideally of a dedicated account.')
        self.rdir = W.QLineEdit(cfg['remote_dir'])
        f.addRow('Server URL', self.url)
        f.addRow('User', self.user)
        f.addRow('App password', self.pw)
        f.addRow('Remote folder', self.rdir)
        lay.addWidget(g)

        # connection: Firebase
        g = self.fb_group = W.QGroupBox('Firebase connection')
        f = W.QFormLayout(g)
        self.fb_url = W.QLineEdit(cfg['fb_db_url'])
        self.fb_url.setPlaceholderText('https://<project>-default-rtdb.europe-west1.firebasedatabase.app')
        self.fb_key = W.QLineEdit(cfg['fb_api_key'])
        self.fb_key.setToolTip('Firebase console → Project settings → General → Web API key')
        self.fb_email = W.QLineEdit(cfg['fb_email'])
        self.fb_pw = W.QLineEdit()
        self.fb_pw.setEchoMode(qenum(W.QLineEdit, 'EchoMode', 'Password'))
        self.fb_pw.setPlaceholderText('signed in - leave empty to keep' if cfg['fb_refresh_token']
                                      else 'needed once to sign in; it is not stored')
        f.addRow('Database URL', self.fb_url)
        f.addRow('Web API key', self.fb_key)
        f.addRow('Email', self.fb_email)
        f.addRow('Password', self.fb_pw)
        lay.addWidget(g)
        self.backend.currentIndexChanged.connect(self._show_backend)
        self._show_backend()

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
        self.selection = W.QCheckBox('Copy to clipboard and selection (replaces both; middle-click pastes it too)')
        self.selection.setChecked(cfg['set_selection'])
        self.selection.setEnabled(cfg['apply_to_clipboard'])
        self.apply.toggled.connect(self.selection.setEnabled)
        row = W.QHBoxLayout()
        self.ddir = W.QLineEdit(cfg['download_dir'])
        b = W.QPushButton('…')
        b.setMaximumWidth(32)
        b.clicked.connect(self._browse)
        row.addWidget(self.ddir)
        row.addWidget(b)
        self.push = W.QCheckBox('Use instant push when available (Firebase, or Nextcloud with notify_push)')
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
        if not WINDOWS:             # Windows has no primary selection
            f.addRow(self.selection)
        f.addRow('Save received files to', row)
        f.addRow(self.push)
        f.addRow('Poll interval (no push)', self.poll)
        f.addRow('Discard items older than', self.age)
        lay.addWidget(g)

        # security & startup
        g = W.QGroupBox('Security and startup')
        f = W.QFormLayout(g)
        store = 'Windows Credential Manager' if WINDOWS else 'KWallet (system keyring)'
        self.use_keyring = W.QCheckBox(f"Keep the password of this device's key in {store}")
        self.use_keyring.setToolTip('Then ClipSend starts without asking for a password. Otherwise you enter '
                                    'it each time ClipSend starts.')
        self.use_keyring.setChecked(cfg['use_keyring'])
        if not keyring_available():
            self.use_keyring.setEnabled(False)
            self.use_keyring.setToolTip('Not available: install the Python package "keyring".')
        f.addRow(self.use_keyring)
        self.autostart = None
        if WINDOWS:
            self.autostart = W.QCheckBox('Start ClipSend when I log in (puts ClipSend.pyw into the Startup folder)')
            self.autostart.setChecked(get_autostart())
            f.addRow(self.autostart)
        self.notif_sent = W.QCheckBox('Show a popup when something was sent')
        self.notif_sent.setChecked(cfg['notify_sent'])
        self.notif_recv = W.QCheckBox('Show a popup when something was received')
        self.notif_recv.setChecked(cfg['notify_received'])
        self.notif_recv.setToolTip('Errors and rejected items are always shown.')
        lay.addWidget(g)

        g = W.QGroupBox('Notifications')
        f = W.QFormLayout(g)
        f.addRow(self.notif_sent)
        f.addRow(self.notif_recv)
        lay.addWidget(g)

        bb = W.QDialogButtonBox(qenum(W.QDialogButtonBox, 'StandardButton', 'Save')
                                | qenum(W.QDialogButtonBox, 'StandardButton', 'Cancel'))
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _show_backend(self):
        fb = self.backend.currentData() == 'firebase'
        self.fb_group.setVisible(fb)
        self.nc_group.setVisible(not fb)
        self.adjustSize()

    def _browse(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, 'Save received files to', self.ddir.text())
        if d:
            self.ddir.setText(d)

    def _collect(self):
        c = dict(self.cfg)
        c.update(backend=self.backend.currentData(),
                 fb_db_url=self.fb_url.text().strip().rstrip('/'), fb_api_key=self.fb_key.text().strip(),
                 fb_email=self.fb_email.text().strip(),
                 server_url=self.url.text().strip(), user=self.user.text().strip(),
                 app_password=self.pw.text().strip(), remote_dir=self.rdir.text().strip(),
                 device_name=self.dev.text().strip(),
                 max_size_mb=self.maxsize.value(), receive_enabled=self.recv.isChecked(),
                 apply_to_clipboard=self.apply.isChecked(), set_selection=self.selection.isChecked(),
                 download_dir=os.path.expanduser(self.ddir.text().strip()) or DEFAULTS['download_dir'],
                 use_push=self.push.isChecked(), poll_interval=self.poll.value(),
                 max_age_min=self.age.value(), use_keyring=self.use_keyring.isChecked(),
                 notify_sent=self.notif_sent.isChecked(),
                 notify_received=self.notif_recv.isChecked())
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
            if c['backend'] == 'firebase':
                check_firebase_url(c['fb_db_url'])
                check_firebase_api_key(c['fb_api_key'])
                if not c['fb_email']:
                    return 'Enter the email of the Firebase user.'
                if c['max_size_mb'] > FB_MAX_MB:
                    return f'Firebase stores at most about {FB_MAX_MB:g} MB per item: lower the max. transfer size.'
            else:
                norm_remote_dir(c['remote_dir'])
                if c['server_url']:
                    check_server_url(c['server_url'])
        except ValueError as e:
            return str(e)
        return None

    def _firebase_login(self, c):
        """Sign in with the entered password (stores only uid + refresh token). Returns an error or None."""
        if c['backend'] != 'firebase':
            return None
        pw = self.fb_pw.text()
        same_account = (c['fb_email'] == self.cfg['fb_email'] and c['fb_api_key'] == self.cfg['fb_api_key'])
        if not pw:
            if c['fb_refresh_token'] and same_account:
                return None
            return 'Enter the Firebase password to sign in.'
        try:
            res = firebase_sign_in(c['fb_api_key'], c['fb_email'], pw)
        except Exception as e:
            return str(e)
        c['fb_uid'], c['fb_refresh_token'] = res['uid'], res['refresh_token']
        self.cfg.update(fb_uid=res['uid'], fb_refresh_token=res['refresh_token'],
                        fb_email=c['fb_email'], fb_api_key=c['fb_api_key'])
        self.fb_pw.clear()
        self.fb_pw.setPlaceholderText('signed in - leave empty to keep')
        return None

    def _checked_config(self):
        c = self._collect()
        err = self._validate(c)
        if not err:
            self._busy(True)
            try:
                err = self._firebase_login(c)
            finally:
                self._busy(False)
        if err:
            QtWidgets.QMessageBox.warning(self, 'ClipSend', err)
            return None
        return c

    @staticmethod
    def _busy(on):
        if on:
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(qenum(QtCore.Qt, 'CursorShape', 'WaitCursor')))
        else:
            QtWidgets.QApplication.restoreOverrideCursor()

    def _test(self):
        c = self._checked_config()
        if c is None:
            return
        self._busy(True)
        try:
            devs, push = Engine.test_connection(c)
            self._busy(False)
            msg = (f'Connection OK.\n\nRegistered devices: {", ".join(devs) or "none yet"}\n'
                   f'Instant push: {"available" if push else "not available, will poll"}')
            QtWidgets.QMessageBox.information(self, 'ClipSend', msg)
        except Exception as e:
            self._busy(False)
            QtWidgets.QMessageBox.warning(self, 'ClipSend', f'Connection failed:\n{e}')

    def _save(self):
        c = self._checked_config()
        if c is None:
            return
        if self.autostart is not None and self.autostart.isChecked() != get_autostart():
            try:
                set_autostart(self.autostart.isChecked())
            except OSError as e:
                QtWidgets.QMessageBox.warning(self, 'ClipSend', f'Could not change autostart:\n{e}')
        self.cfg = _coerce(c)
        self.accept()


# --------------------------------------------------------------------------- #
# tray application
# --------------------------------------------------------------------------- #
# Own icon (a paper plane on a coloured tile) so it can't be confused with
# Klipper's clipboard icon. The colour shows the state. Drawn with QPainter,
# so no SVG plugin is needed; clipsend.svg is the same design for launchers.
ICON_COLORS = {
    'app': ('#7b3fe4', '#00b4d8'),          # violet -> cyan (dialogs, launcher)
    'connected': ('#00a86b', '#2ed3a0'),    # green
    'busy': ('#ff6d00', '#ffb300'),         # orange (sending)
    'recv': ('#1565c0', '#42a5f5'),         # blue (receiving, blinks)
    'recv_dim': ('#1565c0', '#42a5f5', 0.3),
    'offline': ('#6b7280', '#9ca3af'),      # grey (not configured / connecting / offline)
}
_ICONS = {}


def _paint_icon(size, c1, c2, opacity=1.0):
    pm = QtGui.QPixmap(size, size)
    pm.fill(QtGui.QColor(0, 0, 0, 0))
    p = QtGui.QPainter(pm)
    p.setOpacity(opacity)
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


def app_icon(state='app'):
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
        self.clip.selection = self.cfg['set_selection'] and not WINDOWS
        self.engine = None
        self.trust = TrustStore()
        self.my_key = None
        self.peers = {}
        self.devices = []
        self._prompted = set()          # (device, fingerprint) already asked about in this session
        self._prompt = None
        self.state = 'not configured'
        self.dialog = None
        self._sending = False
        self._receiving = False
        self._blink_on = False
        self._blink_until = 0.0
        self._blink = QtCore.QTimer(self)
        self._blink.setInterval(350)
        self._blink.timeout.connect(self._blink_tick)
        self._icon_key = 'offline'
        self._clip_written = -1e9       # monotonic time of our last clipboard write

        self.tray = QtWidgets.QSystemTrayIcon(app_icon('offline'), self)
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
        self.act_devices = self.menu.addAction('Devices…')
        self.act_devices.triggered.connect(self.show_devices)
        self.menu.addAction('Settings…').triggered.connect(self.show_settings)
        self.menu.addSeparator()
        self.menu.addAction('Quit').triggered.connect(self.quit)
        self.menu.aboutToShow.connect(self._update_menu)
        self.tray.setContextMenu(self.menu)

        self.ctl = WinControlServer() if WINDOWS else ControlServer()
        self.ctl.command.connect(self._command)
        self.ctl.start()

        self._unlock()
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
        if self.my_key is None:
            self.state = 'locked: click to unlock'
            self._update_tooltip()
            return
        try:
            self.engine = Engine(self.cfg, self.my_key, self.trust)
        except Exception as e:
            self.state = 'configuration error'
            self.notify('ClipSend: configuration error', clean_display(str(e), 300), error=True)
            return
        self.engine.received.connect(self._on_received)
        self.engine.receiving.connect(self._on_receiving)
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

    def _on_devices(self, peers):
        self.peers = peers
        self.devices = sorted(peers)
        self._update_tooltip()
        self._prompt_new_device()

    def _prompt_new_device(self):
        """Ask (once per session and key) whether to accept a new or changed device key."""
        if self._prompt is not None or self.my_key is None:
            return
        for dev in pending_devices(self.peers, self.trust):
            pub = self.peers[dev]
            if (dev, pub.fingerprint) in self._prompted:
                continue
            self._prompted.add((dev, pub.fingerprint))
            W = QtWidgets.QMessageBox
            box = W(qenum(W, 'Icon', 'Warning' if self.trust.get(dev) else 'Question'), 'ClipSend: new device',
                    device_prompt_text(dev, pub, self.trust.get(dev), self.cfg['device_name'],
                                       self.my_key.public))
            box.setWindowIcon(app_icon())
            box.setTextInteractionFlags(qenum(QtCore.Qt, 'TextInteractionFlag', 'TextSelectableByMouse'))
            accept = box.addButton('Accept', qenum(W, 'ButtonRole', 'AcceptRole'))
            box.addButton('Not now', qenum(W, 'ButtonRole', 'RejectRole'))
            box.setWindowFlag(qenum(QtCore.Qt, 'WindowType', 'WindowStaysOnTopHint'))
            box.setModal(False)
            box.finished.connect(lambda _=0, b=box, a=accept, d=dev, k=pub: self._prompt_done(b, a, d, k))
            self._prompt = box
            box.show()
            box.raise_()
            box.activateWindow()
            return

    def _prompt_done(self, box, accept, dev, pub):
        self._prompt = None
        box.deleteLater()
        if box.clickedButton() is accept and self.peers.get(dev) == pub:
            self.trust.set(dev, pub)
            log.info('confirmed device %s (%s)', dev, pub.fingerprint)
            if self.engine:
                self.engine.wake()
        self._update_tooltip()
        QtCore.QTimer.singleShot(0, self._prompt_new_device)

    # ---- device key ----
    def _unlock(self):
        """Load (or create) this device's key. Its password comes from the system keyring
        (KWallet / Windows Credential Manager) if enabled, otherwise you are asked for it."""
        use_kr = self.cfg['use_keyring'] and keyring_available()
        if not os.path.exists(KEY_FILE):
            return self._create_key()
        pw = keyring_get() if use_kr else None
        if pw:
            try:
                self.my_key = load_device_key(pw)
                return True
            except ValueError as e:
                log.warning('key password from the system keyring does not fit: %s', e)
        while True:
            pw = ask_password(None, 'Unlock ClipSend',
                              f'Password of the device key of "{self.cfg["device_name"]}":')
            if pw is None:
                return False
            try:
                self.my_key = load_device_key(pw)
                break
            except ValueError as e:
                QtWidgets.QMessageBox.warning(None, 'ClipSend', f'Could not unlock the key: {e}')
        if use_kr:
            self._protect_key_with_keyring()
        return True

    def _protect_key_with_keyring(self):
        pw = secrets.token_urlsafe(32)
        if keyring_set(pw):
            save_device_key(self.my_key, pw)
            return True
        return False

    def _create_key(self):
        self.my_key = DeviceKey.generate()
        if self.cfg['use_keyring'] and keyring_available() and self._protect_key_with_keyring():
            log.info('created a device key (password kept in the system keyring)')
            return True
        pw = ask_new_password(None, 'No system keyring (KWallet / Credential Manager) is available.')
        if pw is None:
            self.my_key = None
            return False
        save_device_key(self.my_key, pw)
        log.info('created a device key (password protected)')
        return True

    def _apply_keyring_setting(self):
        """The keyring setting changed: protect the key the new way."""
        if self.my_key is None:
            return
        if self.cfg['use_keyring']:
            if not self._protect_key_with_keyring():
                self.notify('ClipSend', 'Could not use the system keyring; the key password stays as it is.',
                            error=True)
            return
        pw = ask_new_password(None, 'The key password will no longer be kept in the system keyring.')
        if pw is None:              # cancelled: keep using the keyring
            self.cfg['use_keyring'] = True
            save_config(self.cfg)
            return
        save_device_key(self.my_key, pw)
        keyring_delete()

    def show_devices(self):
        if self.my_key is None:
            if not self._unlock():
                return
            self._restart_engine()
        dlg = DevicesDialog(self.cfg['device_name'], self.my_key, dict(self.peers), self.trust)
        try:
            qexec(dlg)
            if dlg.new_key_requested:
                old = self.my_key
                if not self._create_key():
                    self.my_key = old
                self._restart_engine()          # publishes the new key
        finally:
            dlg.deleteLater()
        self._update_tooltip()
        if self.engine:
            self.engine.wake()

    # ---- tray icon: grey = offline, green = connected, orange = sending, blinking blue = receiving
    def _refresh_icon(self):
        if self._sending:
            key = 'busy'
        elif self._blink.isActive():
            key = 'recv' if self._blink_on else 'recv_dim'
        elif self.engine and self.state.startswith('connected'):
            key = 'connected'
        else:
            key = 'offline'
        if key != self._icon_key:
            self._icon_key = key
            self.tray.setIcon(app_icon(key))

    def _start_blink(self, min_seconds):
        self._blink_until = max(self._blink_until, time.monotonic() + min_seconds)
        if not self._blink.isActive():
            self._blink_on = True
            self._blink.start()
        self._refresh_icon()

    def _blink_tick(self):
        if not self._receiving and time.monotonic() >= self._blink_until:
            self._blink.stop()
        else:
            self._blink_on = not self._blink_on
        self._refresh_icon()

    def _on_receiving(self, active):
        self._receiving = active
        if active:
            self._start_blink(0.7)

    def _update_tooltip(self):
        self._refresh_icon()
        tgt = 'all other devices' if self.cfg['target'] == '*' else self.cfg['target']
        tip = (f'ClipSend – {self.cfg["device_name"]} ({self.state})\n'
               f'Left-click: send clipboard to {tgt}')
        if self.devices:
            tip += f'\nOther devices: {", ".join(self.devices)}'
        pending = pending_devices(self.peers, self.trust)
        if pending:
            tip += f'\nWaiting for your confirmation (Devices…): {", ".join(pending)}'
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
            _, usable = device_status(d, self.peers.get(d), self.trust.get(d))
            a = self.sendto.addAction(d if usable else f'{d} (not confirmed)')
            a.setEnabled(usable)
            a.triggered.connect(lambda _=False, d=d: self.send(d))
        n = len(pending_devices(self.peers, self.trust))
        self.act_devices.setText(f'Devices… ({n} new)' if n else 'Devices…')
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
        if self.my_key is None and config_complete(self.cfg):
            if not self._unlock():
                return
            self._restart_engine()
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
        self._refresh_icon()
        self.engine.send_async(content, target or self.cfg['target'])

    def _on_sent(self, summary):
        self._sending = False
        self._refresh_icon()
        self.notify('Clipboard sent', clean_display(summary, 200), kind='sent')

    def _on_error(self, title, msg):
        self._sending = False
        self._refresh_icon()
        self.notify(title, msg, error=True)

    def _on_received(self, msg):
        sender = msg['from']
        if msg['kind'] == 'text':
            body = f'Text from {sender}: “{clean_display(msg["text"], 60)}”'
            apply = lambda: self.clip.set_text(msg['text'])                     # noqa: E731
        elif msg['kind'] == 'image':
            body = f'Image from {sender} ({human_size(len(msg["data"]))})'
            apply = lambda: self.clip.set_image(msg['mime'], msg['data'])       # noqa: E731
        else:
            n = len(msg['paths'])
            body = (f'{n} item{"s" if n != 1 else ""} from {sender} ({human_size(msg["total"])}), '
                    f'saved to {clean_display(msg["dest"], 200)}')
            apply = lambda: self.clip.set_files(msg['paths'])                   # noqa: E731
        self._start_blink(2.5)
        self.notify('Clipboard received', body, kind='received')     # before the clipboard write, see _show
        if not self.cfg['apply_to_clipboard']:
            return
        try:
            apply()
        except Exception as e:
            log.exception('applying received item failed')
            self.notify('ClipSend: could not set clipboard', clean_display(str(e), 300), error=True)
        finally:
            self._clip_written = time.monotonic()

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
        old_keyring = self.cfg['use_keyring']
        try:
            if qexec(self.dialog):
                self.cfg = self.dialog.cfg
                if self.cfg['use_keyring'] != old_keyring:
                    self._apply_keyring_setting()
                self.clip.selection = self.cfg['set_selection'] and not WINDOWS
                save_config(self.cfg)
                self._restart_engine()
                self._update_tooltip()
        finally:
            self.dialog.deleteLater()
            self.dialog = None

    def notify(self, title, body, error=False, kind=None):
        if not error and kind and not self.cfg.get(f'notify_{kind}', True):
            return
        log.info('%s: %s', title, html.unescape(body))
        icon = qenum(QtWidgets.QSystemTrayIcon, 'MessageIcon', 'Warning' if error else 'Information')
        self._show(title, body, icon, 6000 if error else 3000)

    def _show(self, title, body, icon, ms):
        """Show a notification, but not within 2 s after we wrote the clipboard: Plasma's clipboard
        manager then reads the new content from us, and a notification is a blocking D-Bus call to
        that same Plasma process. Both would wait for each other until the 25 s D-Bus timeout."""
        wait = self._clip_written + 2.0 - time.monotonic()
        if wait > 0:
            QtCore.QTimer.singleShot(int(wait * 1000) + 50, lambda: self._show(title, body, icon, ms))
        elif self.tray.isVisible():
            self.tray.showMessage(title, body, icon, ms)

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
            self.ctl.close()
        except OSError:
            pass
        self.app.quit()


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def start_stall_watchdog(app, seconds=10):
    """Diagnostics: if the UI thread is stuck for `seconds`, write the stacks of all threads to the
    log. Runs in a C thread, so it works even if the stuck call holds Python's GIL."""
    try:
        f = open(LOG_FILE, 'a', encoding='utf-8')
    except OSError:
        return

    def arm():
        f.flush()
        faulthandler.dump_traceback_later(seconds, exit=False, file=f)

    timer = QtCore.QTimer(app)
    timer.timeout.connect(arm)
    timer.start(2000)
    arm()
    app._stall_watchdog = (timer, f)


def use_system_certificates():
    """Check HTTPS certificates against the operating system's store (Windows certificate store,
    /etc/ssl on Linux) instead of only Python's bundled list, if 'truststore' is installed. Then a CA
    that your IT installed (e.g. for a firewall that inspects HTTPS) is trusted as in the browser.
    Certificates are still always verified."""
    try:
        import truststore
    except ImportError:
        return 'Python bundle (install truststore to use the system store)'
    truststore.inject_into_ssl()
    return 'system store'


def setup_logging(verbose):
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%Y-%m-%d %H:%M:%S')
    fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1 << 20, backupCount=2)
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if sys.stderr is not None:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)


def main():
    if not (sys.platform.startswith('linux') or WINDOWS):
        print('ClipSend runs on Linux and Windows.', file=sys.stderr)
        return 1
    ap = argparse.ArgumentParser(prog='clipsend', description='Send your clipboard to your other machines.')
    g = ap.add_mutually_exclusive_group()
    g.add_argument('--send', action='store_true', help='tell the running instance to send the clipboard')
    g.add_argument('--settings', action='store_true', help='open the settings of the running instance')
    g.add_argument('--quit', action='store_true', help='quit the running instance')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    for cmd in ('send', 'settings', 'quit'):
        if getattr(args, cmd):
            if send_command(cmd):
                if cmd == 'quit' and not wait_for_exit():
                    print('ClipSend did not exit within 15 s.', file=sys.stderr)
                    return 1
                return 0
            print('ClipSend is not running.', file=sys.stderr)
            return 1

    setup_logging(args.verbose)
    certs = use_system_certificates()
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName('ClipSend')
    app.setDesktopFileName('clipsend')
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(app_icon())

    lock = acquire_lock()
    if lock is None:
        print('ClipSend is already running (use --settings / --send / --quit).', file=sys.stderr)
        if WINDOWS:     # started again by double-click: show something instead of silently exiting
            send_command('settings')
        return 0
    start_stall_watchdog(app)
    tray = TrayApp(app)
    tray.show_when_tray_ready()
    log.info('ClipSend %s started (Qt: %s, clipboard: %s, certificates: %s)', VERSION, QT_API,
             'wl-clipboard' if tray.clip.wl else 'Qt', certs)
    return qexec(app)


if __name__ == '__main__':
    sys.exit(main())
