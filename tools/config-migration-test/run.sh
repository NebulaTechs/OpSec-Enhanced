#!/usr/bin/env bash
# Runs the config loader's migration and hostile-input checks against the
# production config classes.
#
# The checks live outside the Gradle build on purpose: they compile the config
# model on its own, with the loader and the logger stubbed out, so a change to
# the migration path can be verified without launching a client. Run this after
# touching OpsecConfig, SpoofSettings or ServerRule.
#
# Usage: tools/config-migration-test/run.sh [tree]
#   tree  the tree to test; defaults to the shared Fabric tree. Pass
#         "neoforge", "neoforge-1.21.11" or "neoforge-26.2" for the
#         standalone NeoForge trees.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL_DIR="$REPO_ROOT/tools/config-migration-test"
TREE="${1:-shared}"

case "$TREE" in
    shared)
        SRC="$REPO_ROOT/src/client/java/aurick/opsec/mod/config"
        ;;
    neoforge | neoforge-1.21.11 | neoforge-26.2)
        SRC="$REPO_ROOT/$TREE/src/main/java/aurick/opsec/mod/config"
        ;;
    *)
        echo "unknown tree: $TREE" >&2
        exit 2
        ;;
esac

JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-25-temurin}"
JAVAC="$JAVA_HOME/bin/javac"
JAVA="$JAVA_HOME/bin/java"

GSON="$(find "$HOME/.gradle/caches/modules-2/files-2.1/com.google.code.gson" -name 'gson-*.jar' | head -1)"
SLF4J="$(find "$HOME/.gradle/caches/modules-2/files-2.1/org.slf4j/slf4j-api" -name 'slf4j-api-*.jar' | head -1)"
if [[ -z "$GSON" || -z "$SLF4J" ]]; then
    echo "gson or slf4j-api not found in the Gradle cache" >&2
    exit 2
fi

WORK="$TOOL_DIR/build/$TREE"
rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/config"

"$JAVAC" -nowarn -cp "$GSON:$SLF4J" -d "$WORK/classes" \
    $(find "$TOOL_DIR/stub" -name '*.java')

"$JAVAC" -nowarn -cp "$GSON:$SLF4J:$WORK/classes" -d "$WORK/classes" \
    "$SRC/OpsecConfig.java" \
    "$SRC/SpoofSettings.java" \
    "$SRC/ServerRule.java" \
    "$SRC/OpsecConstants.java" \
    "$SRC/JsonSafe.java" \
    "$TOOL_DIR/src/aurick/opsec/mod/config/MigrationHarness.java" \
    "$TOOL_DIR/src/aurick/opsec/mod/config/HostileInputHarness.java"

status=0
for harness in MigrationHarness HostileInputHarness; do
    if ! "$JAVA" -cp "$WORK/classes:$GSON:$SLF4J" \
        -Dopsec.test.configDir="$WORK/config" \
        "aurick.opsec.mod.config.$harness"; then
        status=1
    fi
done

exit "$status"
