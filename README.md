# ClipSend

Click the tray icon to send your clipboard (text, images, or files copied in
Dolphin / Explorer) to your other machines. A free Google Firebase database or
a Nextcloud account is the relay. Everything is end-to-end encrypted with a key
pair per device. Linux (KDE, X11 or Wayland) and Windows, one plain Python
script.

* **Left-click:** send the clipboard. **Right-click:** send to one device,
  receive on/off, received files, Devices…, Settings…
* `clipsend --send | --settings | --quit` controls the running instance (e.g.
  bind `--send` to a keyboard shortcut).
* Received text and images go into the clipboard. Files are saved to
  `~/Downloads/ClipSend/` and put on the clipboard, ready to paste.
* Icon colour: **green** connected, **grey** offline / locked / not set up,
  **orange** sending, **blinking blue** receiving.

## Install

**Linux**
```sh
pip install --user PySide6 requests cryptography keyring   # Wayland: also install wl-clipboard
make install      # installs to ~/.local, enables autostart, (re)starts ClipSend
```
`make stop | start | restart | log | uninstall` also exist.

**Windows:** install Python from <https://www.python.org/downloads/> (not the
Microsoft Store version), run
`py -m pip install --user PySide6 requests cryptography keyring`, put
`clipsend.py` and `ClipSend.pyw` in a permanent folder and double-click
`ClipSend.pyw`. *Start at login* in Settings puts a launcher into the Startup
folder (no registry).

## Storage

**Google Firebase** (free, instant). At <https://console.firebase.google.com>:
1. Create a project. Then **Build → Realtime Database → Create database**
   (e.g. `europe-west1`, locked mode). Under **Rules**, publish:
   ```json
   { "rules": { "users": { "$uid": {
       ".read": "auth != null && auth.uid === $uid",
       ".write": "auth != null && auth.uid === $uid" } } } }
   ```
2. **Build → Authentication:** enable Email/Password and add one user.
3. **Project settings → General → Your apps → `</>`**: register a web app and
   copy `apiKey`.

In ClipSend, choose *Google Firebase* and enter the database URL, API key,
email and password (same on every machine). Only a login token is stored. Max.
about 6 MB per item.

**Nextcloud:** server URL, user and an app password, ideally of a separate
account. Instant with the notify_push app, otherwise it polls.

## Devices

Each device makes its own key pair (Ed25519 + X25519). Its password is kept in
KWallet / the Windows Credential Manager, so nothing is asked at start;
without a keyring you enter a password at each start.

Public keys are exchanged through the storage, but a key is only used after
you accept it. When a new device appears, a popup shows its fingerprint and
this device's. Accept only if the other device shows the same two. You can
also do it later under **Devices…**. Nothing is sent to or accepted from
unconfirmed devices; a changed key is blocked until accepted again.

## Privacy and security

* The receiver deletes an item right after reading it. Every running ClipSend
  also deletes items older than 5 minutes (setting) from all inboxes.
* Items are encrypted per recipient and signed by the sender, so the storage
  provider can neither read nor forge them.
* The clipboard is only read when you send. Received content is never executed;
  file names are sanitised, sizes are capped, and on Windows received files get
  the "downloaded from the internet" mark.
* HTTPS only, to the configured storage only. An untrusted certificate (e.g.
  firewall inspection) is never bypassed; ClipSend retries after 10 minutes.
* Files: settings and keys in `~/.config/clipsend/` (Windows `%APPDATA%\ClipSend`),
  log in `~/.cache/clipsend/` (Windows `%LOCALAPPDATA%\ClipSend`). No root/admin
  rights, no system files.
