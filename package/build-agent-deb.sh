#!/bin/bash
# Build veritas-agent .deb package
# Usage: bash package/build-agent-deb.sh [version] [arch]
set -e

VERSION=${1:-1.0.0}
ARCH=${2:-all}
PKG_NAME="veritas-agent_${VERSION}_${ARCH}"
AGENT_SRC="veritas-agent"

echo "Building $PKG_NAME.deb ..."

# Staging area
rm -rf /tmp/veritas-agent-deb
mkdir -p /tmp/veritas-agent-deb

# Copy package skeleton
cp -r package/agent-deb/. /tmp/veritas-agent-deb/

# Install agent source files
mkdir -p /tmp/veritas-agent-deb/opt/veritas-agent
cp "$AGENT_SRC/agent.py"   /tmp/veritas-agent-deb/opt/veritas-agent/
cp "$AGENT_SRC/veritas_recognizers.py" /tmp/veritas-agent-deb/opt/veritas-agent/
cp "$AGENT_SRC/manage.py"  /tmp/veritas-agent-deb/opt/veritas-agent/ 2>/dev/null || true

# The agent reports this version to the server in every heartbeat.
echo "$VERSION" > /tmp/veritas-agent-deb/opt/veritas-agent/VERSION

# Create log directory
mkdir -p /tmp/veritas-agent-deb/var/log/veritas-agent

# Fix permissions on control scripts
chmod 755 /tmp/veritas-agent-deb/DEBIAN/postinst
chmod 755 /tmp/veritas-agent-deb/DEBIAN/preinst
chmod 755 /tmp/veritas-agent-deb/DEBIAN/prerm
chmod 755 /tmp/veritas-agent-deb/DEBIAN/postrm
chmod 755 /tmp/veritas-agent-deb/usr/bin/veritas-agent

# Update version
sed -i "s/^Version:.*/Version: $VERSION/" /tmp/veritas-agent-deb/DEBIAN/control
sed -i "s/^Architecture:.*/Architecture: $ARCH/" /tmp/veritas-agent-deb/DEBIAN/control

# Build
mkdir -p dist
dpkg-deb --build /tmp/veritas-agent-deb "dist/${PKG_NAME}.deb"
echo "Built: dist/${PKG_NAME}.deb"
