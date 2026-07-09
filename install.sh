#!/bin/sh
# HaiveControl one-line installer (macOS/Linux). Detects the OS, downloads the right agent, registers it.
# Usage:  curl -fsSL https://raw.githubusercontent.com/gitayg/HaiveControl/main/install.sh | sh -s -- <mac-id> [password]
set -e
MAC_ID="${1:-$HIVE_MAC}"
PASSWORD="${2:-$HIVE_PW}"
if [ -z "$MAC_ID" ]; then echo "usage: install.sh <mac-id> [password]  (the id shown by HaiveHub)"; exit 1; fi
case "$(uname -s)" in
  Darwin) ASSET="HaiveControl-macos" ;;
  Linux)  ASSET="HaiveControl-linux" ;;
  *) echo "unsupported OS: $(uname -s)"; exit 1 ;;
esac
URL="https://github.com/gitayg/HaiveControl/releases/latest/download/$ASSET"
DIR="$HOME/.haive"; DEST="$DIR/HaiveControl"
mkdir -p "$DIR"
echo "Downloading $ASSET ..."
curl -fsSL "$URL" -o "$DEST"
chmod +x "$DEST"
echo "Registering to hub '$MAC_ID' ..."
exec "$DEST" "$MAC_ID" $PASSWORD
