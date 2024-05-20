#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# Build a zipapp for Scapy

DIR=$(realpath "$(dirname "$0")/../../")
cd $DIR

if [ ! -e "pyproject.toml" ]; then
    echo "zipapp.sh was not able to find scapy's root folder"
    exit 1
fi

MODE="$1"
if [ -z "$MODE" ] || ( [ "$MODE" != "full" ] && [ "$MODE" != "simple" ] ); then
    echo "Usage: zipapp.sh <simple/full>"
    exit 1
fi

if [ -z "$PYTHON" ]
then
  PYTHON=${PYTHON:-python3}
fi

# Get Scapy version
SCPY_VERSION=$(python3 -c "print(__import__('scapy').__version__)")

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
\) -delete
cd $DIR

# Depending on the mode, install dependencies and get DEST file
if [ "$MODE" == "full" ]; then
    $PYTHON -m pip install --target "$SCPY" IPython
    DEST="./dist/scapy-full-$SCPY_VERSION.pyz"
else
    DEST="./dist/scapy-$SCPY_VERSION.pyz"
fi

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

echo "Success. zipapp avaiable at $DEST"
