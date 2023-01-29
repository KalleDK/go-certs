#!/usr/bin/env sh

set -e

dpkg-buildpackage -b
mkdir _deb
cp ../*.deb _deb/