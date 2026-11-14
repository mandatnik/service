@echo off
set "PATH=C:\TelehackCI\tools\go\bin;C:\TelehackCI\tools\node-v22.22.3-win-x64;C:\TelehackCI\tools\git\cmd;C:\TelehackCI\tools\make\tools\install\bin;%PATH%"
set "GOPATH=C:\TelehackCI\cache\go"
set "GOCACHE=C:\TelehackCI\cache\go-build"
set "npm_config_cache=C:\TelehackCI\cache\npm"
cd /d C:\TelehackCI\runner
C:\TelehackCI\tools\gitea-runner-5.2.0-windows-amd64.exe daemon --config config.yaml >> daemon.log 2>&1
exit /b %ERRORLEVEL%
