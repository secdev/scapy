param(
    [string]$PythonExe = "python",
    [switch]$OneFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$guiRoot = Split-Path -Parent $scriptDir

Push-Location $guiRoot
try
{
    & $PythonExe -m PyInstaller --version 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0)
    {
        throw "PyInstaller not found. Run: $PythonExe -m pip install pyinstaller"
    }

    foreach ($legacyPath in @(
        "$guiRoot\dist\ScapyStudioValidation",
        "$guiRoot\build\ScapyStudioValidation",
        "$guiRoot\ScapyStudioValidation.spec"
    ))
    {
        if (Test-Path $legacyPath)
        {
            try
            {
                Remove-Item $legacyPath -Recurse -Force
            }
            catch
            {
                Write-Warning "Failed to remove legacy artifact: $legacyPath"
            }
        }
    }

    $distMode = if ($OneFile) { "--onefile" } else { "--onedir" }
    & $PythonExe -m PyInstaller `
        --noconfirm `
        --clean `
        $distMode `
        --windowed `
        --name ScapyStudio `
        --paths src `
        --paths .. `
        --collect-all PySide6 `
        --hidden-import scapy.all `
        src\packet_studio\__main__.py
    if ($LASTEXITCODE -ne 0)
    {
        throw "PyInstaller build failed with exit code $LASTEXITCODE"
    }

    Write-Host ""
    Write-Host "Build completed. Output path: $guiRoot\dist\ScapyStudio"
    if ($OneFile)
    {
        Write-Host "Single-file exe: $guiRoot\dist\ScapyStudio.exe"
    }
    else
    {
        Write-Host "Distribute the whole directory and launch ScapyStudio.exe."
    }
}
finally
{
    Pop-Location
}