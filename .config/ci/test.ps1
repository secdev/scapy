# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# test.ps1
# Usage:
#   ./test.ps1 <python version>
# Examples:
#   ./test.sh 3.13

if ($args.Count -eq 0) {
    Write-Host "Usage: .\test.ps1 <pythonversion>"
    exit
}

# Set TOXENV
$PY_VERSION = "py" + ($args[0] -replace '\.', '')
$env:TOXENV = $PY_VERSION + "-windows-root"

if ($env:GITHUB_ACTIONS) {
    # Due to a security policy, the firewall of the Azure runner
    # (Standard_DS2_v2) that runs Github Actions on Linux blocks ICMP.
    $env:UT_FLAGS += " -K icmp_firewall"
}

# Launch Scapy unit tests
python -m tox -- @($env:UT_FLAGS.Trim() -split ' ')
