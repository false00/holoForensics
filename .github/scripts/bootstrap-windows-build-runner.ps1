Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$visualStudioBuildToolsUrl = 'https://aka.ms/vs/17/release/vs_BuildTools.exe'

function Write-Section {
    param([string]$Message)

    Write-Host "`n==> $Message"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-VsWherePath {
    $defaultPath = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $defaultPath) {
        return $defaultPath
    }

    $command = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    return $null
}

function Test-MsvcBuildToolsInstalled {
    $vswhere = Get-VsWherePath
    if (-not $vswhere) {
        return $false
    }

    $installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Workload.VCTools -property installationPath 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    return -not [string]::IsNullOrWhiteSpace(($installationPath | Select-Object -First 1))
}

function Install-MsvcBuildTools {
    $installerPath = Join-Path ([IO.Path]::GetTempPath()) 'vs_BuildTools.exe'

    Write-Section 'Downloading Visual Studio 2022 Build Tools bootstrapper'
    Invoke-WebRequest -Uri $visualStudioBuildToolsUrl -OutFile $installerPath

    $arguments = @(
        '--wait',
        '--quiet',
        '--norestart',
        '--nocache',
        '--add', 'Microsoft.VisualStudio.Workload.VCTools',
        '--includeRecommended'
    )

    Write-Section 'Installing Visual Studio 2022 Build Tools with the C++ workload'
    $process = Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        throw "Visual Studio 2022 Build Tools installer failed with exit code $($process.ExitCode)."
    }
}

$isAdmin = Test-IsAdministrator
$msvcInstalled = Test-MsvcBuildToolsInstalled

if ($msvcInstalled) {
    Write-Section 'Windows runner prerequisites already installed'
    exit 0
}

if (-not $isAdmin) {
    throw 'The self-hosted runner is missing Visual Studio 2022 Build Tools with the C++ workload. The workflow can bootstrap that automatically, but the runner service account must already have administrator rights because GitHub Actions jobs cannot elevate through UAC.'
}

if (-not $msvcInstalled) {
    Install-MsvcBuildTools

    if (-not (Test-MsvcBuildToolsInstalled)) {
        throw 'Visual Studio 2022 Build Tools installation completed, but the C++ workload was not discoverable afterwards.'
    }
}

Write-Section 'Windows runner prerequisites are ready'