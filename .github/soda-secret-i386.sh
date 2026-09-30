#!/bin/bash

set -euo pipefail

headers="$1"
mkdir -p "$headers/packages" "$headers/root" "$headers/include" "$headers/lib"
cd "$headers/packages"
apt-get download \
  "libglib2.0-dev:i386=$(dpkg-query -W -f='${Version}' libglib2.0-dev:amd64)" \
  "libsecret-1-dev:i386=$(dpkg-query -W -f='${Version}' libsecret-1-dev:amd64)"
for package in ./*.deb; do
  dpkg-deb -x "$package" "$headers/root"
done
cp -a "$headers/root/usr/include/glib-2.0/." "$headers/include/"
cp -a "$headers/root/usr/include/libsecret-1/." "$headers/include/"
cp "$headers/root/usr/lib/i386-linux-gnu/glib-2.0/include/glibconfig.h" "$headers/include/"
ln -s /usr/lib/i386-linux-gnu/libsecret-1.so.0 "$headers/lib/libsecret-1.so"
