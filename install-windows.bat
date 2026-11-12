@echo off
rem Double-click to install ClipSend for the current user (needs Python 3; otherwise use ClipSend.exe).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1" %*
pause
