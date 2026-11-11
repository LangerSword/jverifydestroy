#!/usr/bin/env bash
# jvd-verify — the offline evidence verifier.
#
# The script locates the project so the classpath resolves, but it must not
# change the caller's working directory: a relative path to a log or a
# record has to mean the file in the directory the user ran the command from.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-$HOME/tools/jdk-25.0.5+8}"
CP=$(find "$ROOT" -path '*/target/classes' -type d | paste -sd:)
if [ -z "$CP" ]; then echo "run 'mvn -q -DskipTests package' first" >&2; exit 2; fi
exec "$JAVA_HOME/bin/java" -cp "$CP" io.jvd.verifycli.Main "$@"
