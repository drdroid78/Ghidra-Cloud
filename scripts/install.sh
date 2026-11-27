#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$RUNNER_TEMP/ghidra-cloud"
cd "$RUNNER_TEMP/ghidra-cloud"
echo "CPU: $(nproc)"
free -h
df -h .
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
curl -fLsS --connect-timeout 15 --max-time 180 --max-filesize 800000000 -o ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip
printf '%s  ghidra.zip\n' 2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67 | sha256sum -c -
unzip -q ghidra.zip
rm ghidra.zip
test -x ghidra_12.2_PUBLIC/support/analyzeHeadless
echo 'Ghidra 12.2 archive verified'
