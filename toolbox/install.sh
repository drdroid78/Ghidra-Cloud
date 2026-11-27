#!/usr/bin/env bash
set -euo pipefail
base="$RUNNER_TEMP/toolbox"
mkdir -p "$base/bin"
cd "$base"
# Ubuntu-signed packages, versions recorded in report. No capture permissions.
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark yara binwalk python3-venv
python3 -m venv "$base/venv"
"$base/venv/bin/pip" install --disable-pip-version-check --only-binary=:all: 'capstone==5.0.6' 'lief==0.16.6'
download() {
  curl -fLsS --retry 2 --connect-timeout 15 --max-time 180 --max-filesize 200000000 -o "$1" "$2"
  printf '%s  %s\n' "$3" "$1" | sha256sum -c -
}
download jadx.zip https://github.com/skylot/jadx/releases/download/v1.5.7/jadx-1.5.7.zip 1755e4242ade71a077438723689f404079592ec7764a3a0572f98fef94ebcbf3
mkdir jadx
unzip -q jadx.zip -d jadx
chmod +x jadx/bin/jadx
ln -s "$base/jadx/bin/jadx" "$base/bin/jadx"
download apktool.jar https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
cat > "$base/bin/apktool" <<'SH'
#!/usr/bin/env bash
exec java -jar "$RUNNER_TEMP/toolbox/apktool.jar" "$@"
SH
chmod +x "$base/bin/apktool"
download radare2.deb https://github.com/radareorg/radare2/releases/download/6.2.6/radare2_6.2.6_amd64.deb 0dddf90e217e38a6a658881b9ec7e217198487c75b7f82a332b3cbd30834636f
sudo apt-get install -y ./radare2.deb
echo "$base/bin" >> "$GITHUB_PATH"
echo "$base/venv/bin" >> "$GITHUB_PATH"
echo "TOOLBOX_INSTALLED"
