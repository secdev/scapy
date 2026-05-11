param(
    [string]$PythonExe = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$guiRoot = Split-Path -Parent $scriptDir
$pyprojectPath = Join-Path $guiRoot "pyproject.toml"
$releaseDir = Join-Path $guiRoot "release"
$releaseNoteSource = Join-Path $guiRoot "release\ScapyStudio-Windows-Guide.txt"
$packageStageDir = Join-Path $releaseDir "ScapyStudio-package"

function Get-PackageVersion
{
    param(
        [string]$ProjectFilePath
    )

    $versionLine = Select-String -Path $ProjectFilePath -Pattern '^version = "([^"]+)"$' | Select-Object -First 1
    if (-not $versionLine)
    {
        throw "Failed to read version from $ProjectFilePath"
    }

    return $versionLine.Matches[0].Groups[1].Value
}

Push-Location $guiRoot
try
{
    $version = Get-PackageVersion -ProjectFilePath $pyprojectPath

    & (Join-Path $scriptDir "build_windows_validation_exe.ps1") -PythonExe $PythonExe
    if ($LASTEXITCODE -ne 0)
    {
        throw "Executable build failed."
    }

    if (-not (Test-Path $releaseDir))
    {
        New-Item -ItemType Directory -Path $releaseDir | Out-Null
    }

    $zipPath = Join-Path $releaseDir ("ScapyStudio-{0}-windows-x64.zip" -f $version)
    $hashPath = "$zipPath.sha256.txt"

    foreach ($path in @($zipPath, $hashPath, $packageStageDir))
    {
        if (Test-Path $path)
        {
            Remove-Item $path -Recurse -Force
        }
    }

    New-Item -ItemType Directory -Path $packageStageDir | Out-Null
    Copy-Item -Path ".\dist\ScapyStudio" -Destination $packageStageDir -Recurse
    Copy-Item -Path $releaseNoteSource -Destination $packageStageDir

    Compress-Archive -Path "$packageStageDir\*" -DestinationPath $zipPath -CompressionLevel Optimal

    $hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
    @(
        "SHA256  $(Split-Path -Leaf $zipPath)",
        $hash
    ) | Set-Content -Path $hashPath -Encoding utf8

    Write-Host ""
    Write-Host "Release package created: $zipPath"
    Write-Host "SHA256 file created: $hashPath"
    Write-Host "Bundled guide file: $(Join-Path $packageStageDir (Split-Path -Leaf $releaseNoteSource))"
    Write-Host "SHA256: $hash"
}
finally
{
    if (Test-Path $packageStageDir)
    {
        Remove-Item $packageStageDir -Recurse -Force
    }
    Pop-Location
}