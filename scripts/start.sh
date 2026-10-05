#!/bin/sh
# Railway start entrypoint — the platform does not run startCommand through a
# shell, so `a && b` chains never execute `b`. This wrapper runs migrations
# then execs the server so node becomes PID 1 and gets signals directly.
set -e
node dist/migrate.js
exec node dist/index.js
