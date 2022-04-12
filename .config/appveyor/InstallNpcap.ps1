# Install Npcap on the machine.

# Config:
$npcap_oem_file = "npcap-1.60-oem.exe"
$npcap_oem_hash = "91e076eb9a197d55ca5e05b240e8049cd97ced3455eb7e7cb0f06066b423eb77"

# Note: because we need the /S option (silent), this script has two cases:
#  - The script is runned from a master build, then use the secure variable 'npcap_oem_key' which will be available
#    to decode the very recent npcap install oem file and use it
#  - The script is runned from a PR, then use the provided archived 0.96 version, which is the last public one to
#    provide support for the /S option

function checkTheSum($file, $hash) {
    $_chksum = $(CertUtil -hashfile $file SHA256)[1] -replace " ",""
    if ($_chksum -ne $hash){
        Write-Error "Checksums do NOT match !"
        return 1, $file
    }
    return 0, $file
}

function DownloadNPCAP_free {
    $file = $PSScriptRoot+"\npcap-0.96.exe"
    $hash = "83667e1306fdcf7f9967c10277b36b87e50ee8812e1ee2bb9443bdd065dc04a1"
    # Download the 0.96 file from nmap servers
    wget "https://npcap.com/dist/npcap-0.96.exe" -UseBasicParsing -OutFile $file
    return checkTheSum $file $hash
}

function DownloadNPCAP_oem {
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
    try {
        Invoke-WebRequest -uri (-join("https://npcap.com/oem/dist/",$npcap_oem_file)) -OutFile $file -Headers $headers -Credential $credential
    } catch [System.Net.WebException],[System.IO.IOException] {
        Write-Error "Error while dowloading npcap oem!"
        Write-Warning $Error[0]
        return 1, $file
    }
    return checkTheSum $file $npcap_oem_hash
}

if (Test-Path Env:npcap_oem_key){  # Key is here: on master
    $success, $file = DownloadNPCAP_oem
    if ($success -ne 0){
        $success, $file = DownloadNPCAP_free
    }
} else {  # No key: PRs
    $success, $file = DownloadNPCAP_free
}

if ($success -ne 0){
    Write-Error ('Npcap installation of '+$file+' arborted !')
    exit 1
}

Write-Output ('Installing: ' + $file)

# Run installer
$process = Start-Process $file -ArgumentList "/loopback_support=yes /S" -PassThru -Wait
if($process.ExitCode -eq 0) {
    echo "Npcap installation completed !"
    exit 0
} else {
    Write-Error "Npcap installation failed !"
    exit 1
}
