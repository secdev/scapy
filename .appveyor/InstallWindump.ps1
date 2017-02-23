wget https://github.com/hsluoyz/WinDump/releases/download/v0.1/WinDump-for-Npcap-0.1.zip -UseBasicParsing -OutFile .\npcap.zip
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}
Unzip $PSScriptRoot"\npcap.zip" $PSScriptRoot"\npcap"
Remove-Item ".\npcap.zip"
Move-Item -Force ".\npcap\x64\WinDump.exe" "C:\Windows\System32\windump.exe"
Remove-Item ".\npcap" -recurse