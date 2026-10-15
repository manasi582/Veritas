#!/bin/bash
set -e
export COPYFILE_DISABLE=1   # keep macOS ._* metadata files out of the package
BINARY=${1:-dist/veritas-runtime}
VERSION=${2:-1.0.0}
ARCH=${3:-arm64}
PKG_NAME="veritas_${VERSION}_${ARCH}"

echo "Building $PKG_NAME.pkg ..."
mkdir -p /tmp/veritas-pkg-root/opt/veritas
mkdir -p /tmp/veritas-pkg-root/var/lib/veritas
mkdir -p /tmp/veritas-pkg-root/var/log/veritas
mkdir -p /tmp/veritas-pkg-scripts
mkdir -p /tmp/veritas-pkg-resources
mkdir -p dist

cp "$BINARY" /tmp/veritas-pkg-root/opt/veritas/veritas-runtime
chmod 755 /tmp/veritas-pkg-root/opt/veritas/veritas-runtime
cp package/macos/com.veritas.daemon.plist /tmp/veritas-pkg-root/opt/veritas/
cp package/macos/config.env /tmp/veritas-pkg-root/opt/veritas/config.env.example   # copied to /etc/veritas/config.env once, never replaced
cp package/macos/scripts/postinstall /tmp/veritas-pkg-scripts/
cp package/macos/scripts/preinstall /tmp/veritas-pkg-scripts/
chmod 755 /tmp/veritas-pkg-scripts/*
sed -i '' "s/@VERSION@/$VERSION/" /tmp/veritas-pkg-scripts/preinstall   # the release the script installs

# Install veritas CLI
mkdir -p /tmp/veritas-pkg-root/usr/local/bin
cp package/macos/veritas-cli /tmp/veritas-pkg-root/usr/local/bin/veritas
# the release version, read by "veritas version" and "veritas status"
echo "$VERSION" > /tmp/veritas-pkg-root/opt/veritas/VERSION
chmod 755 /tmp/veritas-pkg-root/usr/local/bin/veritas

pkgbuild \
  --root /tmp/veritas-pkg-root \
  --scripts /tmp/veritas-pkg-scripts \
  --identifier com.veritas.pkg \
  --version "$VERSION" \
  --install-location / \
  "dist/${PKG_NAME}.pkg"

echo "Built: dist/${PKG_NAME}.pkg"
