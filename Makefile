# ClipSend - per-user install with autostart (KDE Plasma, X11 or Wayland)
#
#   make install      install to ~/.local, enable autostart, (re)start it
#   make start|stop|restart
#   make uninstall    remove program + autostart (keeps ~/.config/clipsend)
#
# The Python interpreter found now is baked into the launcher; override with
#   make install PYTHON=/usr/bin/python3

PREFIX    ?= $(HOME)/.local
PYTHON    ?= $(shell command -v python3)
APPDIR    := $(PREFIX)/share/clipsend
BINDIR    := $(PREFIX)/bin
APPSDIR   := $(PREFIX)/share/applications
AUTOSTART := $(or $(XDG_CONFIG_HOME),$(HOME)/.config)/autostart
LAUNCHER  := $(BINDIR)/clipsend
ICONDIR   := $(PREFIX)/share/icons/hicolor/scalable/apps

define DESKTOP
[Desktop Entry]
Type=Application
Name=ClipSend
GenericName=Clipboard sender
Comment=Send the clipboard (text, images, files) to your other machines
Exec=$(LAUNCHER)
Icon=clipsend
Terminal=false
StartupNotify=false
Categories=Utility;
X-KDE-autostart-phase=2
Actions=Send;Settings;

[Desktop Action Send]
Name=Send clipboard
Exec=$(LAUNCHER) --send

[Desktop Action Settings]
Name=Settings
Exec=$(LAUNCHER) --settings
endef
export DESKTOP

.PHONY: all install uninstall check start stop restart log

all: check

check:
	@test -n "$(PYTHON)" || { echo "python3 not found"; exit 1; }
	@echo "Python: $(PYTHON)"
	@$(PYTHON) -c "import requests" || { echo "ERROR: python package 'requests' missing"; exit 1; }
	@$(PYTHON) -c "import importlib.util as u, sys; sys.exit(not any(u.find_spec(m) for m in ('PySide6','PyQt6','PyQt5')))" \
		|| { echo "ERROR: need PySide6, PyQt6 or PyQt5"; exit 1; }
	@$(PYTHON) -c "import cryptography" 2>/dev/null \
		|| { echo "ERROR: python package 'cryptography' missing (needed for the device keys)"; exit 1; }
	@$(PYTHON) -c "import truststore" 2>/dev/null \
		|| echo "note: 'truststore' missing - HTTPS uses Python's CA list instead of the system's"
	@$(PYTHON) -c "import keyring" 2>/dev/null \
		|| echo "note: 'keyring' missing - the key password cannot be kept in KWallet, you will be asked at start"
	@$(PYTHON) -c "import websocket" 2>/dev/null \
		|| echo "note: 'websocket-client' missing - Nextcloud notify_push unavailable (Firebase does not need it)"
	@if [ "$$XDG_SESSION_TYPE" = wayland ] || [ -n "$$WAYLAND_DISPLAY" ]; then \
		command -v wl-copy >/dev/null && command -v wl-paste >/dev/null \
		|| { echo "ERROR: Wayland session needs wl-clipboard (apt/dnf/pacman install wl-clipboard)"; exit 1; }; \
	fi
	@echo "dependencies OK"

install: check
	@$(PYTHON) -c "compile(open('clipsend.py', encoding='utf-8').read(), 'clipsend.py', 'exec')" \
		|| { echo "ERROR: clipsend.py is incomplete or broken (still syncing?)"; exit 1; }
	@$(MAKE) --no-print-directory stop
	rm -rf $(APPDIR)
	install -d $(APPDIR) $(BINDIR) $(APPSDIR) $(AUTOSTART) $(ICONDIR)
	install -m 644 clipsend.py $(APPDIR)/clipsend.py
	install -m 644 clipsend.svg $(ICONDIR)/clipsend.svg
	printf '#!/bin/sh\nexec "%s" "%s" "$$@"\n' "$(PYTHON)" "$(APPDIR)/clipsend.py" > $(LAUNCHER)
	chmod 755 $(LAUNCHER)
	echo "$$DESKTOP" > $(APPSDIR)/clipsend.desktop
	echo "$$DESKTOP" > $(AUTOSTART)/clipsend.desktop
	@$(MAKE) --no-print-directory start
	@echo "Installed ClipSend $$(grep -m1 '^VERSION' $(APPDIR)/clipsend.py | tr -dc '0-9.'). It also starts automatically at login."

uninstall: stop
	rm -f $(LAUNCHER) $(APPSDIR)/clipsend.desktop $(AUTOSTART)/clipsend.desktop $(ICONDIR)/clipsend.svg
	rm -rf $(APPDIR)
	@echo "Removed. Settings are kept in ~/.config/clipsend (delete manually if wanted)."

start:
	@setsid -f $(LAUNCHER) >/dev/null 2>&1 < /dev/null; echo "started"

# --quit asks the running instance to exit; pkill catches one that does not answer
stop:
	@-$(LAUNCHER) --quit >/dev/null 2>&1 || true
	@-pkill -u "$$(id -u)" -f '$(APPDIR)/[^ ]*[.]py' && sleep 1 || true
	@echo "stopped"

restart: stop
	@$(MAKE) --no-print-directory start

log:
	@tail -n 50 -f $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/clipsend/clipsend.log
