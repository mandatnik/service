@echo off
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0install-telehack.ps1" >> C:\Windows\Temp\telehack-gpo-wrapper.log 2>&1
exit /b %errorlevel%
