#!/usr/bin/env bash
# jvd-ui — the Swing desktop app.
#
# The script locates the project so the classpath resolves, but it must not
# change the caller's working directory: the app stores its work and its
# evidence log under the directory the user launched it from, and a relative
# path has to mean what the user meant by it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="${JAVA_HOME:-$HOME/tools/jdk-25.0.5+8}"
CP=$(find "$ROOT" -path '*/target/classes' -type d | paste -sd:)
if [ -z "$CP" ]; then echo "run 'mvn -q -DskipTests package' first" >&2; exit 2; fi
exec "$JAVA_HOME/bin/java" --enable-native-access=ALL-UNNAMED -cp "$CP" io.jvd.ui.Main "$@"
