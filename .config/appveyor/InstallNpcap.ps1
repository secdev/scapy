# Install Npcap on the machine.

# Config:
$npcap_oem_file = "npcap-0.9997-oem.exe"

# Note: because we need the /S option (silent), this script has two cases:
#  - The script is runned from a master build, then use the secure variable 'npcap_oem_key' which will be available
#    to decode the very recent npcap install oem file and use it
#  - The script is runned from a PR, then use the provided archived 0.96 version, which is the last public one to
#    provide support for the /S option

if (Test-Path Env:npcap_oem_key){  # Key is here: on master
    echo "Using Npcap OEM version"
    # Unpack the key
    $user, $pass = (Get-ChildItem Env:npcap_oem_key).Value.replace("`"", "").split(",")
    if(!$user -Or !$pass){
        Throw (New-Object System.Exception)
    }
    $file = $PSScriptRoot+"\"+$npcap_oem_file
    # Download oem file using (super) secret credentials
    $pair = "${user}:${pass}"
    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
    $basicAuthValue = "Basic $encodedCreds"
    $headers = @{ Authorization = $basicAuthValue }
    $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($user, $secpasswd)
    Invoke-WebRequest -uri (-join("https://nmap.org/npcap/oem/dist/",$npcap_oem_file)) -OutFile $file -Headers $headers -Credential $credential
} else {  # No key: PRs
    echo "Using backup 0.96"
    $file = $PSScriptRoot+"\npcap-0.96.exe"
    # Download the 0.96 file from nmap servers
    wget "https://nmap.org/npcap/dist/npcap-0.96.exe" -UseBasicParsing -OutFile $file
    # Now let's check its checksum
    $_chksum = $(CertUtil -hashfile $file SHA256)[1] -replace " ",""
    if ($_chksum -ne "83667e1306fdcf7f9967c10277b36b87e50ee8812e1ee2bb9443bdd065dc04a1"){
        echo "Checksums does NOT match !"
        exit
    } else {
        echo "Checksums matches !"
    }
}
echo ('Installing: ' + $file)

# Run installer
Start-Process $file -ArgumentList "/loopback_support=yes /S" -wait
if($?) {
    echo "Npcap installation completed"
}
