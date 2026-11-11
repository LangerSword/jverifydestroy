#!/usr/bin/env bash
# Build the distributable artifacts for a release.
#
# The hosted site reads GitHub Releases and resolves an artifact by file
# extension: .jar for "any JVM", .tar.gz for Linux, .AppImage for a Linux
# binary. This script produces the two that the project can honestly produce:
#
#   jvd.jar     the command line tools, for any machine with a JDK 25
#   jvd-web.jar the verification service, for the hosted site to call
#
# It does NOT produce a Windows exe or a macOS dmg: this project needs JDK 25
# and a POSIX shell, and a claim of "native binary" that is really a jar with a
# different name is worse than saying so.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' pom.xml | head -1)}"
OUT="$ROOT/dist"
STAGE="$OUT/stage"

echo "==> building (version $VERSION)"
export JAVA_HOME="${JAVA_HOME:-$HOME/tools/jdk-25.0.5+8}"
export PATH="$JAVA_HOME/bin:$HOME/tools/apache-maven-3.9.16/bin:$PATH"
./mvnw -B -q clean package -DskipTests

rm -rf "$STAGE"
mkdir -p "$STAGE"

echo "==> staging the command line tools"
cp cli/target/cli-$VERSION.jar "$STAGE/jvd-$VERSION.jar"
cp verifier-cli/target/verifier-cli-$VERSION.jar "$STAGE/jvd-verify-$VERSION.jar"
cp web/target/web-$VERSION.jar "$STAGE/jvd-web-$VERSION.jar"
cp README.md "$STAGE/README.md"
cp LICENSE "$STAGE/LICENSE"

cat > "$STAGE/INSTALL.md" <<'EOF'
# jverifydestroy

Requires **JDK 25** and a POSIX shell. The memory verifier reads
`/proc/<pid>/mem`, so it does not run on Windows or macOS; the tool reports
`NOT_CHECKABLE` there rather than guessing.

    java -jar jvd-<version>.jar version
    java -jar jvd-<version>.jar shred FILE --work DIR
    java -jar jvd-verify-<version>.jar --log DIR --checkpoint FILE --pubkey B64
    java -jar jvd-web-<version>.jar 8080

The verification service is meant to run behind a TLS terminator.
EOF

echo "==> packaging"
tar -czf "$OUT/jvd-$VERSION.tar.gz" -C "$STAGE" .
cp "$STAGE/jvd-$VERSION.jar" "$OUT/jvd-$VERSION.jar"
cp "$STAGE/jvd-web-$VERSION.jar" "$OUT/jvd-web-$VERSION.jar"

echo "==> checksums"
cd "$OUT"
# No "./" prefix: `sha256sum -c` resolves each name against the current directory,
# and a leading "./" makes it work only when the file was checked out that way.
sha256sum ./*.jar ./*.tar.gz | sed 's: \./: :' | tee SHA256SUMS

echo
echo "artifacts in $OUT:"
ls -la "$OUT" | grep -vE '^total|stage'
