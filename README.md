# ClipSend

Send your clipboard (text, images, or files copied in Dolphin) to
your other machine(s) with a single click on a tray icon. A Nextcloud account
acts as the relay, so the machines don't need to be on the same network.
Runs on Linux (KDE Plasma, X11 or Wayland).

| Action                            | Effect                                         |
|-----------------------------------|------------------------------------------------|
| **Left-click** on the tray icon   | send the current clipboard                     |
| **Right-click**                   | menu: send to a specific device, receive on/off, open received files, **Settings…**, quit |
| `clipsend --send`                 | same as left-click (bind to a KDE shortcut)    |
| `clipsend --settings` / `--quit`  | control the running instance                   |

Received text and images go straight into the clipboard. Received files are
saved to `~/Downloads/ClipSend/<date>_<sender>/` and put on the clipboard as
files, so you can paste them in Dolphin with Ctrl+V.

The tray icon's colour shows the state: **green** means connected, **grey**
means offline or not configured, **orange** means sending, and **blinking
blue** means receiving. After a suspend or a network change, ClipSend
reconnects within a few seconds.

## Install on Linux

```sh
# Wayland sessions also need wl-clipboard:  sudo apt install wl-clipboard
make install        # installs to ~/.local, adds autostart entry
make start
```

On first start the settings dialog opens. Enter the server URL, user and an
**app password**. Ideally use a dedicated Nextcloud account that is only used for
ClipSend. Give each machine a unique device name. If a `credentials.json` from
the old `sync-clip.py` is in this folder, `make install` imports it.

Requirements: Python 3, `requests`, one of PySide6 / PyQt6 / PyQt5.
Optional: `cryptography` (end-to-end encryption) and `websocket-client` (instant push).

Other targets: `make restart`, `make stop`, `make uninstall`, `make log`.

**Keyboard shortcut:** System Settings → Shortcuts → Add Application → ClipSend
→ assign a key to the *Send clipboard* action. You can also add a custom command
shortcut that runs `~/.local/bin/clipsend --send`.

## Settings

Open them with right-click → Settings…; they're stored in `~/.config/clipsend/config.json` (mode 600).

* Nextcloud URL / user / app password / remote folder
* device name, and the default target for left-click (all other devices or one)
* **max. transfer size** (default 5 MB), which applies to both sending and receiving
* receive on/off, put received items into the clipboard (clipboard and
  selection by default, so middle-click pastes them too), download folder
* instant push on/off, poll interval (default 0.5 s), discard items older than N minutes
* **shared passphrase** for end-to-end encryption
* popups for sent and for received items, switchable independently (errors are always shown)

## How it works

```
<remote folder>/inbox/<device>/<timestamp>-<id>.clipsend
```

Each device creates its own inbox folder. Sending does a single WebDAV `PUT` into
each target's inbox. The receiver downloads the item, deletes it, validates it,
and applies it. Each item is a zlib-compressed JSON envelope. If a passphrase is
set, the envelope is encrypted with AES-256-GCM (key derived with scrypt).

**Change detection:** if the server has the Nextcloud
[notify_push](https://github.com/nextcloud/notify_push) app, ClipSend keeps a
websocket open and gets notified instantly. Otherwise it polls the *ETag of its
own inbox folder*. That's a single tiny `PROPFIND` over a kept-alive HTTPS
connection. It only lists and downloads when the ETag changes.

## What ClipSend does on your machine and network

ClipSend is a plain Python script, with nothing compiled, packed or obfuscated.

* **Network:** HTTPS only, and only to the Nextcloud server in the settings.
  It uses normal system DNS, the standard WebDAV and OCS endpoints and, if the
  server offers it, the notify_push websocket on the same host. It
  identifies itself with the User-Agent `ClipSend/<version>`. While receiving is
  on, it checks its inbox at the poll interval (default 0.5 s). Turn
  *Receive* off in the menu to stop that.
* **Clipboard:** read only when you click the tray icon or run `--send`. Nothing
  is ever sent on its own.
* **Files:** settings in `~/.config/clipsend/`, the log in `~/.cache/clipsend/`,
  received files in `~/Downloads/ClipSend/`. `make install` writes only to
  `~/.local` and `~/.config/autostart`. No root rights are needed, and no system
  files are changed.
* **Processes:** it starts only `wl-copy` / `wl-paste` (Wayland), and your file
  manager when you choose *Open received files*.

## Security notes

* Received content is never executed. Files are written into a fresh directory
  with `O_EXCL|O_NOFOLLOW` and without executable bits. Path traversal
  (`..`, absolute paths), control characters and bidi-override characters in
  names are rejected or stripped. Symlinks inside copied folders aren't sent.
* There are size caps everywhere: on the clipboard read, on the download
  (streamed), and on decompression (zip bomb protection). There are also caps
  on the number of files and on server XML responses.
* Image types are allow-listed (png/jpeg/gif/bmp/webp) and their magic bytes are
  checked.
* With a passphrase set, unencrypted or tampered items are rejected. Someone who
  gets the Nextcloud credentials, or the server itself, can't read your
  clipboard or inject content into it. **Setting a passphrase is recommended.**
* HTTPS is enforced, redirects aren't followed, and credentials are only sent
  to the configured host. After a login failure ClipSend backs off for 10 min
  to avoid a brute-force lockout.
* The local control channel only accepts connections from the same user and
  knows four fixed commands. It's a socket in `$XDG_RUNTIME_DIR`.
* Notifications escape all remote text, because KDE renders notification
  markup.
