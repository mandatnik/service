@echo off
set "PATH=C:\MandatnikCI\tools\go\bin;C:\MandatnikCI\tools\node-v22.22.3-win-x64;C:\MandatnikCI\tools\git\cmd;C:\MandatnikCI\tools\make\tools\install\bin;%PATH%"
set "GOPATH=C:\MandatnikCI\cache-system\go"
set "GOCACHE=C:\MandatnikCI\cache-system\go-build"
set "npm_config_cache=C:\MandatnikCI\cache-system\npm"
cd /d C:\MandatnikCI\runner
C:\MandatnikCI\tools\gitea-runner-5.2.0-windows-amd64.exe daemon --config config.yaml >> daemon.log 2>&1
exit /b %ERRORLEVEL%
