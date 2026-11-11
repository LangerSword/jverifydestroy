#!/usr/bin/env bash
# jvd-web — the evidence verification service.
#
# The service answers one question over HTTP: is this evidence log authentic? A
# hosted site can call it to let a visitor check a receipt for themselves.
#
#   jvd-web            # listen on 8080
#   jvd-web 9000       # listen on a different port
#   jvd-web 0          # bind any free port (a script can read it from the log)
#
# The service binds plain HTTP. Put it behind a TLS terminator — a reverse proxy
# or a load balancer — so that log content and public keys travel encrypted. The
# keys are public, but the log is the operator's data and does not need to travel
# in the clear.
#
# It serves:
#   GET  /          a page explaining the service
#   GET  /health    for uptime checks
#   GET  /schema    the JSON Schema of an evidence record
#   POST /verify    check a submitted log
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-$HOME/tools/jdk-25.0.5+8}"

# The shaded jar is the artifact a deployment wants: one file, no classpath to
# assemble. The classpath form is the fallback for a working copy.
JAR="$ROOT/web/target/web-1.0.0.jar"
if [ -f "$JAR" ]; then
  exec "$JAVA_HOME/bin/java" -jar "$JAR" "${1:-8080}"
fi

CP=$(find "$ROOT" -path '*/target/classes' -type d | paste -sd:)
if [ -z "$CP" ]; then
  echo "run 'mvn -q -DskipTests package' first" >&2
  exit 2
fi
exec "$JAVA_HOME/bin/java" -cp "$CP" io.jvd.web.Main "${1:-8080}"
