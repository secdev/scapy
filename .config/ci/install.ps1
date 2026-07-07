# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# Install packages needed for the CI on Windows

# Install npcap and windump
& "$PSScriptRoot\windows\InstallNpcap.ps1"
& "$PSScriptRoot\windows\InstallWindumpNpcap.ps1"

# Install wireshark
choco install -y wireshark

# Add to PATH
echo "C:\Program Files\Wireshark;C:\Program Files\Windump" | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append

# Update pip & setuptools & wheel (tox uses those)
python -m pip install --upgrade pip setuptools wheel --ignore-installed

# Make sure tox is installed and up to date
python -m pip install -U tox --ignore-installed
