#!/usr/bin/env bash
set -euo pipefail

# Configure the runner's already-provisioned Java 25 runtime.
# This script never downloads, installs, upgrades, or modifies Ghidra.
if [ -n "${JAVA_HOME_25_X64:-}" ]; then
  export JAVA_HOME="$JAVA_HOME_25_X64"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

java -version
java -version 2>&1 | grep -Eq 'version "25([."]|$)'

if [ -n "${JAVA_HOME:-}" ]; then
  echo "JAVA_HOME=$JAVA_HOME" >> "$GITHUB_ENV"
  echo "$JAVA_HOME/bin" >> "$GITHUB_PATH"
fi
