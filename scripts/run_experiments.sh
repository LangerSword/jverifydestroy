#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export JAVA_HOME="${JAVA_HOME:-$HOME/tools/jdk-25.0.5+8}"
export PATH="$JAVA_HOME/bin:$HOME/tools/apache-maven-3.9.16/bin:$PATH"
mvn -q -DskipTests package
CP=$(find . -path '*/target/classes' -type d | paste -sd:)
exec "$JAVA_HOME/bin/java" -cp "$CP" io.jvd.experiments.Main "$@"
