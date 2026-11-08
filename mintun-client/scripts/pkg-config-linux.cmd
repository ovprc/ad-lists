@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0pkg-config-linux.ps1" %*
exit /b %errorlevel%
