# Config
$urlPath = "https://github.com/hsluoyz/WinDump/releases/download/v0.3/WinDump-for-Npcap-0.3.zip"
$checksum = "4253cbc494416c4917920e1f2424cdf039af8bc39f839a47aa4337bd28f4eb7e"

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
New-Item -Path "C:\Program Files\Windump" -ItemType directory
Move-Item -Force $PSScriptRoot"\npcap\x64\WinDump.exe" "C:\Program Files\Windump\windump.exe"
Remove-Item $PSScriptRoot"\npcap" -recurse
