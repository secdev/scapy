#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# Check that all Scapy files have a SPDX

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_DIR=$SCRIPT_DIR/../..

function check_path() {
    cd $ROOT_DIR
    for ext in "${@:2}"; do
        find $1 -name "*.$ext" -exec bash -c '[[ -z $(grep "SPDX" {}) ]] && echo "{}"' \;
    done
}

check_path scapy py
