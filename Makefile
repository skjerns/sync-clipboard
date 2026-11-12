# ClipSend - per-user install with autostart (KDE Plasma, X11 or Wayland)
#
#   make install      install to ~/.local and enable autostart
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
		|| echo "note: 'cryptography' missing - end-to-end encryption (passphrase) unavailable"
	@$(PYTHON) -c "import websocket" 2>/dev/null \
		|| echo "note: 'websocket-client' missing - instant push unavailable, will poll"
	@if [ "$$XDG_SESSION_TYPE" = wayland ] || [ -n "$$WAYLAND_DISPLAY" ]; then \
		command -v wl-copy >/dev/null && command -v wl-paste >/dev/null \
		|| { echo "ERROR: Wayland session needs wl-clipboard (apt/dnf/pacman install wl-clipboard)"; exit 1; }; \
	fi
	@echo "dependencies OK"

install: check
	install -d $(APPDIR) $(BINDIR) $(APPSDIR) $(AUTOSTART) $(ICONDIR)
	install -m 644 clipsend.py $(APPDIR)/clipsend.py
	install -m 644 clipsend.svg $(ICONDIR)/clipsend.svg
	printf '#!/bin/sh\nexec "%s" "%s" "$$@"\n' "$(PYTHON)" "$(APPDIR)/clipsend.py" > $(LAUNCHER)
	chmod 755 $(LAUNCHER)
	echo "$$DESKTOP" > $(APPSDIR)/clipsend.desktop
	echo "$$DESKTOP" > $(AUTOSTART)/clipsend.desktop
	@if [ -f credentials.json ]; then $(LAUNCHER) --import-legacy credentials.json; fi
	@echo
	@echo "Installed. ClipSend starts automatically at login."
	@echo "Start it now with 'make start' (or 'make restart' if an old version is running)."

uninstall: stop
	rm -f $(LAUNCHER) $(APPSDIR)/clipsend.desktop $(AUTOSTART)/clipsend.desktop $(ICONDIR)/clipsend.svg
	rm -rf $(APPDIR)
	@echo "Removed. Settings are kept in ~/.config/clipsend (delete manually if wanted)."

start:
	@setsid -f $(LAUNCHER) >/dev/null 2>&1 < /dev/null; echo "started"

stop:
	@-$(LAUNCHER) --quit 2>/dev/null && echo "stopped" || true

restart: stop
	@$(MAKE) --no-print-directory start

log:
	@tail -n 50 -f $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/clipsend/clipsend.log
