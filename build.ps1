param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist'))
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    dotnet restore Gui/Gui.csproj --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Dependency restore failed.' }
    dotnet run --project Tests/Tests.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    dotnet publish Gui/Gui.csproj -c Release -r win-x64 --self-contained true --no-restore -o $OutputDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
    Write-Output "Portable executable: $OutputDirectory/SSLCertificateChecker.exe"
} finally { Pop-Location }
