#!/bin/sh
set -eu
root=/home/mimbol/telehack-ci
export PATH="$root/tools/go/bin:$root/tools/node-v22.22.3-linux-x64/bin:$root/tools/make/usr/bin:$PATH"
export GOPATH="$root/cache/go" GOCACHE="$root/cache/go-build" npm_config_cache="$root/cache/npm"
cd "$root/runner"
exec /usr/bin/flock -n "$root/runner/daemon.lock" "$root/tools/gitea-runner-5.2.0-linux-amd64" daemon --config config.yaml >> "$root/runner/daemon.log" 2>&1
