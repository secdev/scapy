wget https://github.com/hsluoyz/WinDump/releases/download/v0.2/WinDump-for-Npcap-0.2.zip -UseBasicParsing -OutFile $PSScriptRoot"\npcap.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}
Unzip $PSScriptRoot"\npcap.zip" $PSScriptRoot"\npcap"
Remove-Item $PSScriptRoot"\npcap.zip"
Move-Item -Force $PSScriptRoot"\npcap\x64\WinDump.exe" "C:\Windows\System32\windump.exe"
Remove-Item $PSScriptRoot"\npcap" -recurse
