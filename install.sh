#!/bin/bash
# Veritas One-Line Installer
# Usage: curl -sSL https://raw.githubusercontent.com/shreyaaassss/Veritas/main/install.sh | sudo bash

set -e

REPO="shreyaaassss/Veritas"
VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
VERSION=${VERSION:-v1.0.0}

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Installing Veritas ${VERSION} for ${OS}/${ARCH} ..."

BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

if [ "$OS" = "linux" ]; then
  DEB="veritas_${VERSION#v}_${ARCH}.deb"
  echo "Downloading $DEB ..."
  curl -sSL "${BASE_URL}/${DEB}" -o /tmp/veritas.deb
  dpkg -i /tmp/veritas.deb
  rm /tmp/veritas.deb
  echo ""
  echo "Veritas installed. Next:"
  echo "  1. veritas fingerprint                      (send the line it prints to your Veritas contact)"
  echo "  2. sudo veritas license /path/to/your.vlic  (installs the license and starts the service)"
  echo "  3. sudo veritas setup-code                  (then open https://localhost:8000/setup)"

elif [ "$OS" = "darwin" ]; then
  PKG="veritas_${VERSION#v}_${ARCH}.pkg"
  echo "Downloading $PKG ..."
  curl -sSL "${BASE_URL}/${PKG}" -o /tmp/veritas.pkg
  installer -pkg /tmp/veritas.pkg -target /
  rm /tmp/veritas.pkg
  echo ""
  echo "Veritas installed. Next:"
  echo "  1. veritas fingerprint                      (send the line it prints to your Veritas contact)"
  echo "  2. sudo veritas license /path/to/your.vlic  (installs the license and starts the service)"
  echo "  3. sudo veritas setup-code                  (then open https://localhost:8000/setup)"
  echo "More: https://github.com/${REPO}/blob/main/docs/MACOS.md"

else
  echo "Windows: download the installer from:"
  echo "  https://github.com/${REPO}/releases/latest"
  exit 1
fi
