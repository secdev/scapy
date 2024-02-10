#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# Check that all Scapy files have a SPDX

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_DIR=$SCRIPT_DIR/../..

# http://mywiki.wooledge.org/BashFAQ/024
# This documents an absolutely WTF behavior of bash.
set +m
shopt -s lastpipe

function check_path() {
    cd $ROOT_DIR
    RCODE=0
    for ext in "${@:2}"; do
        find $1 -name "*.$ext" | while read f; do
            if [[ -z $(grep "SPDX" $f) ]]; then
                echo "$f"
                RCODE=1
            fi
        done
    done
    return $RCODE
}

check_path scapy py || exit $?
