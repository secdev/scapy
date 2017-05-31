# Config
$urlPath = "https://nmap.org/npcap/dist/npcap-0.90.exe"
$checksum = "0477a42a9c54f31a7799fb3ee0537826041730f462abfc066fe36d81c50721a7"

############
############
# Download the file
wget $urlPath -UseBasicParsing -OutFile $PSScriptRoot"\npcap.exe"
# Now let's check its checksum
$_chksum = $(CertUtil -hashfile $PSScriptRoot"\npcap.exe" SHA256)[1] -replace " ",""
if ($_chksum -ne $checksum){
    echo "Checksums does NOT match !"
    exit
} else {
    echo "Checksums matches !"
}
# Run installer
Start-Process $PSScriptRoot"\npcap.exe" -ArgumentList "/loopback_support=yes /S" -wait
echo "Npcap installation completed"