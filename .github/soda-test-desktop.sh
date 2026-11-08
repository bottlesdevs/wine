#!/usr/bin/env bash
set -euo pipefail

log=$1
shift
xcompmgr -n > "$log" 2>&1 &
compositor_pid=$!
trap 'kill "$compositor_pid" 2>/dev/null || true; wait "$compositor_pid" 2>/dev/null || true' EXIT
sleep 1
kill -0 "$compositor_pid"
"$@"
