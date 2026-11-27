#!/usr/bin/env bash
set -euo pipefail

# Destructive installation is blocked unless the repository owner explicitly
# approves it through workflow_dispatch. Ordinary workflow/issue runs cannot
# provide this approval.
if [[ "${GHIDRA_INSTALL_APPROVAL:-}" != "PAVEL_CONFIRMED_GHIDRA_12_2_INSTALL" ]]; then
  echo "::error::Ghidra installation/reinstallation is blocked. Only drdroid78 may approve it via workflow_dispatch."
  exit 78
fi

bash scripts/prepare-java.sh
mkdir -p "$RUNNER_TEMP/ghidra-cloud"
cd "$RUNNER_TEMP/ghidra-cloud"
echo "CPU: $(nproc)"
free -h
df -h .
curl -fLsS --connect-timeout 15 --max-time 180 --max-filesize 800000000 -o ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip
printf '%s  ghidra.zip\n' 2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67 | sha256sum -c -
rm -rf ghidra_12.2_PUBLIC
unzip -q ghidra.zip
rm ghidra.zip
test -x ghidra_12.2_PUBLIC/support/analyzeHeadless
printf '%s\\n' '2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67' > ghidra_12.2_PUBLIC/.ghidra-cloud-verified
echo 'Ghidra 12.2 archive verified; owner-approved install complete'
