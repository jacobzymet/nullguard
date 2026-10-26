#!/usr/bin/env bash
set -euo pipefail
target=${1:?usage: package-desktop.sh TARGET}
output=dist/desktop
mkdir -p "$output"
case "$target" in
  *apple-darwin)
    bundle="$output/Nullguard.app"
    mkdir -p "$bundle/Contents/MacOS"
    cp "target/$target/release/nullguard-desktop" "$bundle/Contents/MacOS/nullguard-desktop"
    cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Nullguard</string>
<key>CFBundleDisplayName</key><string>Nullguard</string>
<key>CFBundleIdentifier</key><string>com.nulliance.nullguard</string>
<key>CFBundleExecutable</key><string>nullguard-desktop</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.2.0</string>
<key>CFBundleVersion</key><string>0.2.0</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
    (cd "$output" && ditto -c -k --keepParent Nullguard.app Nullguard-macos.zip)
    rm -rf "$bundle"
    ;;
  *windows*) cp "target/$target/release/nullguard-desktop.exe" "$output/" ;;
  *linux*) tar -czf "$output/nullguard-desktop-linux.tar.gz" -C "target/$target/release" nullguard-desktop ;;
  *) echo "Unsupported desktop target: $target" >&2; exit 1 ;;
esac
cd "$output"
for file in *; do
  case "$file" in *.sha256) continue ;; esac
  if command -v sha256sum >/dev/null; then sha256sum "$file" > "$file.sha256";
  else shasum -a 256 "$file" > "$file.sha256"; fi
done
