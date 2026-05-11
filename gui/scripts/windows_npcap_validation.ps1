param(
    [string]$PythonExe = "python",
    [switch]$SkipAutomatedTests,
    [switch]$SkipGuiSmokeTests,
    [switch]$SkipManualChecklist
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step
{
    param(
        [string]$Title
    )

    Write-Host ""
    Write-Host "== $Title =="
}

function Test-IsAdministrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NpcapStatus
{
    $service = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    if ($null -ne $service)
    {
        return "installed, service status: $($service.Status)"
    }

    $registryPaths = @(
        "HKLM:\SOFTWARE\Npcap",
        "HKLM:\SOFTWARE\WOW6432Node\Npcap"
    )
    foreach ($path in $registryPaths)
    {
        if (Test-Path $path)
        {
            return "installed, registry key found"
        }
    }

    return "not detected"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$guiRoot = Split-Path -Parent $scriptDir

Push-Location $guiRoot
try
{
    $env:PYTHONPATH = "src;.."

    Write-Step "1. Check prerequisites"
    $pythonVersion = & $PythonExe --version
    Write-Host "Python: $pythonVersion"
    Write-Host "Administrator: $(if (Test-IsAdministrator) { 'yes' } else { 'no' })"
    Write-Host "Npcap: $(Get-NpcapStatus)"
    Write-Host "Working directory: $guiRoot"

    if (-not $SkipAutomatedTests)
    {
        Write-Step "2. Run focused automated tests"
        $automatedTests = @(
            "tests.test_scapy_packet_adapter",
            "tests.test_send_task_service",
            "tests.test_pcap_analysis_service",
            "tests.test_tool_registry_service",
            "tests.test_workspace_document_service"
        )
        & $PythonExe -m unittest @automatedTests
    }

    if (-not $SkipGuiSmokeTests)
    {
        Write-Step "3. Run offscreen GUI smoke tests"
        $env:QT_QPA_PLATFORM = "offscreen"
        & $PythonExe -m unittest tests.test_gui_smoke
        Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue
    }

    if (-not $SkipManualChecklist)
    {
        Write-Step "4. Launch GUI for manual validation"
        $process = Start-Process -FilePath $PythonExe -ArgumentList "-m", "packet_studio" -WorkingDirectory $guiRoot -PassThru
        Write-Host "Manual checklist:"
        Write-Host "1. Verify dependency summary, log directory and environment text on the welcome page."
        Write-Host "2. Open the interfaces page, refresh the list, and record whether the target adapter is discovered."
        Write-Host "3. In packet builder, add IP/ICMP or Ether/ARP and verify summary, structure and hex preview update together."
        Write-Host "4. In send task, load the current packet from builder and verify send, sendp or sr1 basic execution paths."
        Write-Host "5. In offline analysis, open a pcap or pcapng and verify list, search, details and copy back to builder."
        Write-Host "6. On a real Windows plus Npcap host, record admin status, Npcap version, adapter model and any failure symptom."
        Write-Host ""
        Write-Host "Close the GUI window, then return here and press Enter to finish the script."
        Read-Host | Out-Null
        if (-not $process.HasExited)
        {
            Write-Warning "GUI process is still running. Close it manually if needed."
        }
    }
}
finally
{
    Pop-Location
}
