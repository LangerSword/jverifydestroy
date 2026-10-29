#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-$HOME/tools/jdk-25.0.5+8}"
CP=$(find . -path '*/target/classes' -type d | paste -sd:)
if [ -z "$CP" ]; then echo "run 'mvn -q -DskipTests package' first" >&2; exit 2; fi
exec "$JAVA_HOME/bin/java" -cp "$CP" io.jvd.ui.Main "$@"
