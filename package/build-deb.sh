#!/bin/bash
set -e

BINARY=${1:-dist/veritas-runtime}
VERSION=${2:-1.0.0}
ARCH=${3:-amd64}
PKG_NAME="veritas_${VERSION}_${ARCH}"

echo "Building $PKG_NAME.deb from $BINARY ..."

# Create staging directory
rm -rf /tmp/veritas-deb
mkdir -p /tmp/veritas-deb

# Copy package skeleton
cp -r package/deb/. /tmp/veritas-deb/

# Install binary
mkdir -p /tmp/veritas-deb/opt/veritas
cp "$BINARY" /tmp/veritas-deb/opt/veritas/veritas-runtime
chmod 755 /tmp/veritas-deb/opt/veritas/veritas-runtime

# Create runtime directories (dpkg creates them, owned by veritas post-install)
mkdir -p /tmp/veritas-deb/var/lib/veritas
mkdir -p /tmp/veritas-deb/var/log/veritas

# Set permissions on control scripts
chmod 755 /tmp/veritas-deb/DEBIAN/postinst
chmod 755 /tmp/veritas-deb/DEBIAN/preinst
sed -i "s/@VERSION@/$VERSION/" /tmp/veritas-deb/DEBIAN/preinst   # the release the script installs
chmod 755 /tmp/veritas-deb/DEBIAN/prerm
chmod 755 /tmp/veritas-deb/DEBIAN/postrm
chmod 755 /tmp/veritas-deb/usr/bin/veritas

# Update version in control file
sed -i "s/^Version:.*/Version: $VERSION/" /tmp/veritas-deb/DEBIAN/control
sed -i "s/^Architecture:.*/Architecture: $ARCH/" /tmp/veritas-deb/DEBIAN/control

# Calculate installed size (KB)
SIZE=$(du -sk /tmp/veritas-deb/opt /tmp/veritas-deb/usr /tmp/veritas-deb/etc 2>/dev/null | awk '{sum+=$1} END {print sum}')
echo "Installed-Size: $SIZE" >> /tmp/veritas-deb/DEBIAN/control

# Build the .deb
mkdir -p dist
dpkg-deb --build /tmp/veritas-deb "dist/${PKG_NAME}.deb"
echo "Built: dist/${PKG_NAME}.deb"
