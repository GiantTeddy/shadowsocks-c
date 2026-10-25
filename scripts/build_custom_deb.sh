#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build a self-contained "shadowsocks-c" .deb from an existing CMake build.
#
# The package installs the binaries under /opt/shadowsocks-c (symlinked into
# /usr/local/bin), the routing ACL files, a placeholder configuration and a
# shadowsocks-c.service client unit. Keeping the binaries outside /usr/bin
# avoids conflicting with a distribution shadowsocks-libev package.
#
# Usage:
#   bash scripts/build_custom_deb.sh [DEB_VERSION]
#
# Environment:
#   DEB_VERSION  Debian version (default: <PROJECT_VERSION>-1)
#   BIN_DIR      directory with the built binaries (default: build/bin)
#   ACL_DIR      directory with chn.acl/local.acl (default: acl)
#   OUT_DIR      output directory (default: dist)

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

BASE_VERSION="$(sed -n 's/^set(PROJECT_VERSION "\(.*\)")$/\1/p' CMakeLists.txt | head -n1)"
BASE_VERSION="${BASE_VERSION:-3.3.6}"

# Version scheme: <upstream base>+<tag marker>-<debian revision>, e.g.
#   tag v3.3.6-http-pac-routing -> 3.3.6+http.pac.routing-1
# The upstream base is preserved so the custom build sorts after the plain
# upstream version while remaining clearly identifiable.
VERSION="${1:-${DEB_VERSION:-}}"
if [ -z "$VERSION" ] && [ -n "${RELEASE_TAG:-}" ]; then
    tag="${RELEASE_TAG#v}"
    marker="${tag#"$BASE_VERSION"}"
    marker="${marker#-}"
    marker="$(printf '%s' "$marker" | tr '-' '.')"
    if [ -n "$marker" ]; then
        VERSION="${BASE_VERSION}+${marker}-1"
    else
        VERSION="${BASE_VERSION}+custom-1"
    fi
fi
if [ -z "$VERSION" ]; then
    VERSION="${BASE_VERSION}+custom-1"
fi

ARCH="$(dpkg --print-architecture)"
BIN_DIR="${BIN_DIR:-build/bin}"
ACL_DIR="${ACL_DIR:-acl}"
OUT_DIR="${OUT_DIR:-dist}"

BINARIES="ss-local ss-server ss-tunnel ss-redir ss-manager"

for b in $BINARIES; do
    if [ ! -x "$BIN_DIR/$b" ]; then
        echo "error: missing built binary: $BIN_DIR/$b" >&2
        exit 1
    fi
done
for a in chn.acl local.acl; do
    if [ ! -f "$ACL_DIR/$a" ]; then
        echo "error: missing ACL file: $ACL_DIR/$a" >&2
        exit 1
    fi
done

# Fully static binaries (musl build, docker/static/Dockerfile) must not declare libc6.
STATIC=1
for b in $BINARIES; do
    if readelf -l "$BIN_DIR/$b" 2>/dev/null | grep -q INTERP; then
        STATIC=0
    fi
    if readelf -d "$BIN_DIR/$b" 2>/dev/null | grep -q NEEDED; then
        STATIC=0
    fi
done
if [ "$STATIC" -eq 1 ]; then
    echo "static binaries detected: package will have no library dependencies"
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/pkg/shadowsocks-c"

mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/opt/shadowsocks-c/bin" "$ROOT/opt/shadowsocks-c/acl" \
         "$ROOT/etc/shadowsocks-c" "$ROOT/lib/systemd/system" \
         "$ROOT/usr/local/bin" "$ROOT/usr/share/doc/shadowsocks-c"

for b in $BINARIES; do
    install -m 0755 "$BIN_DIR/$b" "$ROOT/opt/shadowsocks-c/bin/$b"
    strip --strip-unneeded "$ROOT/opt/shadowsocks-c/bin/$b" 2>/dev/null || true
    ln -s "/opt/shadowsocks-c/bin/$b" "$ROOT/usr/local/bin/$b"
done

for a in chn.acl local.acl; do
    install -m 0644 "$ACL_DIR/$a" "$ROOT/opt/shadowsocks-c/acl/$a"
done

cat > "$ROOT/etc/shadowsocks-c/config.json" <<'JSON'
{
    "server": "CHANGE_ME.example.com",
    "server_port": 8388,
    "local_address": "127.0.0.1",
    "local_port": 1081,
    "password": "CHANGE_ME",
    "method": "aes-256-gcm",
    "timeout": 86400,
    "mode": "tcp_only",
    "route_mode": "bypass_chn",
    "chn_acl": "/opt/shadowsocks-c/acl/chn.acl",
    "local_acl": "/opt/shadowsocks-c/acl/local.acl"
}
JSON

cat > "$ROOT/lib/systemd/system/shadowsocks-c.service" <<'UNIT'
[Unit]
Description=shadowsocks-c client (ss-local)
Documentation=man:ss-local(1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=true
ExecStart=/opt/shadowsocks-c/bin/ss-local -c /etc/shadowsocks-c/config.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

cat > "$ROOT/usr/share/doc/shadowsocks-c/copyright" <<'CPR'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: shadowsocks-c
Source: https://github.com/GiantTeddy/shadowsocks-c
License: GPL-3+
 This package is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.
 .
 Bundled third-party components (Mbed TLS, libsodium, c-ares, PCRE2, libuv,
 duktape, BLAKE3, bloom) keep their own licenses.
CPR

cat > "$ROOT/usr/share/doc/shadowsocks-c/README.Debian" <<'RD'
shadowsocks-c (custom build: HTTP proxy + IP/PAC routing)
=========================================================
Binaries: /opt/shadowsocks-c/bin (symlinked into /usr/local/bin).
Config  : /etc/shadowsocks-c/config.json  (placeholder values).

  1. Edit server / server_port / password / method.
  2. Routing: "route_mode" = all | bypass_lan | bypass_local | bypass_chn |
     chn_only | pac, plus optional "pac_file".
  3. sudo systemctl restart shadowsocks-c.service
RD

cat > "$ROOT/DEBIAN/control" <<CTL
Package: shadowsocks-c
Version: $VERSION
Architecture: $ARCH
Maintainer: GiantTeddy <gianteddy@users.noreply.github.com>
Section: net
Priority: optional
Depends: @DEPENDS@
Description: lightweight SOCKS5/HTTP proxy with IP and PAC routing
 shadowsocks-c is a lightweight and secure SOCKS5 proxy (a port of
 shadowsocks-libev) with added features:
  - Native HTTP proxy on the same local port as SOCKS5 (CONNECT and plain
    HTTP forwarding, auto-detected);
  - IP-based routing modes: all, bypass_lan, bypass_local, bypass_chn,
    chn_only (uses the bundled China/local CIDR lists);
  - PAC routing (route_mode=pac) evaluated by an embedded duktape engine.
 .
 Installs ss-local, ss-server, ss-tunnel, ss-redir and ss-manager under
 /opt/shadowsocks-c (symlinked into /usr/local/bin) and provides a
 shadowsocks-c.service client unit.
CTL

if [ "$STATIC" -eq 1 ]; then
    sed -i '/^Depends: @DEPENDS@$/d' "$ROOT/DEBIAN/control"
else
    sed -i 's|^Depends: @DEPENDS@$|Depends: libc6 (>= 2.34)|' "$ROOT/DEBIAN/control"
fi

echo "/etc/shadowsocks-c/config.json" > "$ROOT/DEBIAN/conffiles"

cat > "$ROOT/DEBIAN/postinst" <<'PI'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable shadowsocks-c.service >/dev/null 2>&1 || true
    if grep -q "CHANGE_ME" /etc/shadowsocks-c/config.json 2>/dev/null; then
        echo "shadowsocks-c: edit /etc/shadowsocks-c/config.json, then: systemctl start shadowsocks-c.service"
    else
        systemctl restart shadowsocks-c.service >/dev/null 2>&1 || true
    fi
fi
exit 0
PI

cat > "$ROOT/DEBIAN/prerm" <<'PR'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop shadowsocks-c.service >/dev/null 2>&1 || true
    systemctl disable shadowsocks-c.service >/dev/null 2>&1 || true
fi
exit 0
PR

cat > "$ROOT/DEBIAN/postrm" <<'PO'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
PO

find "$ROOT" -type d -exec chmod 0755 {} +
chmod 0755 "$ROOT/opt/shadowsocks-c/bin/"* \
           "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/prerm" "$ROOT/DEBIAN/postrm"
chmod 0644 "$ROOT/opt/shadowsocks-c/acl/"* \
           "$ROOT/etc/shadowsocks-c/config.json" \
           "$ROOT/lib/systemd/system/shadowsocks-c.service" \
           "$ROOT/usr/share/doc/shadowsocks-c/"*

mkdir -p "$OUT_DIR"
DEB="$OUT_DIR/shadowsocks-c_${VERSION}_${ARCH}.deb"
# -Zxz keeps the package installable on old dpkg releases (dpkg >= 1.22
# defaults to zstd, which buster/bullseye dpkg cannot read).
dpkg-deb --build -Zxz --root-owner-group "$ROOT" "$DEB" >/dev/null

# Binary tarball (bin/ + acl/ + checksums), matching the release layout.
TF="$STAGE/tar"
mkdir -p "$TF/bin" "$TF/acl"
for b in $BINARIES; do
    install -m 0755 "$ROOT/opt/shadowsocks-c/bin/$b" "$TF/bin/$b"
done
for a in chn.acl local.acl; do
    install -m 0644 "$ROOT/opt/shadowsocks-c/acl/$a" "$TF/acl/$a"
done
( cd "$TF" && sha256sum bin/* acl/* > SHA256SUMS )
TARBALL="$OUT_DIR/shadowsocks-c-${VERSION}-linux-${ARCH}.tar.gz"
tar -C "$TF" -czf "$TARBALL" bin acl SHA256SUMS

( cd "$OUT_DIR" && sha256sum "$(basename "$DEB")" "$(basename "$TARBALL")" > SHA256SUMS )

echo "built: $DEB"
echo "built: $TARBALL"
echo "built: $OUT_DIR/SHA256SUMS"
