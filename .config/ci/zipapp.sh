#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# Build a zipapp for Scapy

DIR=$(realpath "$(dirname "$0")/../../")
cd $DIR

if [ ! -e "pyproject.toml" ]; then
    echo "zipapp.sh must be called from scapy root folder"
    exit 1
fi

if [ -z "$PYTHON" ]
then
  PYTHON=${PYTHON:-python3}
fi

# Get temp directory
TMPFLD="$(mktemp -d)"
if [ -z "$TMPFLD" ] || [ ! -d "$TMPFLD" ]; then
    echo "Error: 'mktemp -d' failed"
    exit 1
fi
ARCH="$TMPFLD/archive"
SCPY="$TMPFLD/scapy"
mkdir "$ARCH"
mkdir "$SCPY"

# Create git archive
git archive HEAD -o "$ARCH/scapy.tar.gz"

# Unpack the archive to a temporary directory
if [ ! -e "$ARCH/scapy.tar.gz" ]; then
    echo "ERROR: git archive failed"
    exit 1
fi
tar -xvf "$ARCH/scapy.tar.gz" -C "$SCPY"

# Remove unnecessary files
cd "$SCPY" && find . -not \( \
    -wholename "./scapy*" -o \
    -wholename "./pyproject.toml" -o \
    -wholename "./LICENSE" \
\) -print
cd $DIR

# Get DEST file
DEST="./dist/scapy.pyz"
if [ ! -d "./dist" ]; then
    mkdir dist
fi

echo "$SCPY"
# Build the zipapp
echo "Building zipapp"
$PYTHON -m zipapp \
    -o "$DEST" \
    -p "/usr/bin/env python3" \
    -m "scapy.main:interact" \
    -c \
    "$SCPY"

# Cleanup
rm -rf "$TMPFLD"
