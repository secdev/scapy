# Config
$urlPath = "https://github.com/hsluoyz/WinDump/releases/download/v0.2/WinDump-for-Npcap-0.2.zip"
$checksum = "9182934bb822511236b4112ddaa006c95c86c864ecc5c2e3c355228463e43bf2"

############
############
# Download the file
wget $urlPath -UseBasicParsing -OutFile $PSScriptRoot"\npcap.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}
Unzip $PSScriptRoot"\npcap.zip" $PSScriptRoot"\npcap"
Remove-Item $PSScriptRoot"\npcap.zip"
# Now let's check its checksum
$_chksum = $(CertUtil -hashfile $PSScriptRoot"\npcap\x64\WinDump.exe" SHA256)[1] -replace " ",""
if ($_chksum -ne $checksum){
    echo "Checksums does NOT match !"
    exit
} else {
    echo "Checksums matches !"
}
# Finally, move it and remove tmp files
Move-Item -Force $PSScriptRoot"\npcap\x64\WinDump.exe" "C:\Windows\System32\windump.exe"
Remove-Item $PSScriptRoot"\npcap" -recurse
