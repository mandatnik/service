@echo off
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0install-mandatnik.ps1" >> C:\Windows\Temp\mandatnik-gpo-wrapper.log 2>&1
exit /b %errorlevel%
