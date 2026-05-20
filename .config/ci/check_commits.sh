#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only

# Check all commits in the PR have the "AI-Assisted" tag
# We copy Wireshark's contributing guide, thanks to them for the idea !
# This script is inspired by https://gitlab.com/wireshark/wireshark/-/blob/master/.gitlab-ci.yml

commits=$(git rev-list --no-merges --max-count=$((PR_FETCH_DEPTH - 1)) HEAD)
if [ -z "$commits" ]; then
    echo "No commit to check in PR. OK."
    exit 0
fi

missing=0
for c in $commits; do
    if ! git log -1 --format=%B "$c" | grep -qi '^AI-Assisted:'; then
        echo -e "ERROR: Commit \033[0;33m$c\033[0m is missing the 'AI-Assisted: yes|no [tool(s)]' trailer."
        missing=1
    else
        echo -e "OK: Commit \033[0;32m$c\033[0m is properly tagged."
    fi
done

if [ $missing -eq 1 ]; then
    echo
    echo -e "\033[0;31mPlease add the 'AI-Assisted' trailer to commit messages !\033[0m"
    echo "See the contribution guide at: https://github.com/secdev/scapy/blob/master/CONTRIBUTING.md"
    exit 1
else
    echo "All checked commits include the AI-Assisted trailer."
    exit 0
fi
