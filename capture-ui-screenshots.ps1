param(
    [string]$OutputDir = "output/ui-review-screenshots",
    [string[]]$States = @("main", "collection-progress", "settings", "about", "scope", "usn-settings"),
    [ValidateSet("system", "light", "dark")]
    [string]$Theme = "system",
    [int]$TrimMargin = 0,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Win32UiCapture {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool GetClientRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool ClientToScreen(IntPtr hWnd, ref POINT point);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

    [DllImport("user32.dll")]
    public static extern bool SetCursorPos(int X, int Y);

    [DllImport("user32.dll")]
    public static extern void mouse_event(uint dwFlags, uint dx, uint dy, int dwData, UIntPtr dwExtraInfo);
}
"@

[void][Win32UiCapture]::SetProcessDPIAware()

$repoRoot = Get-Location
$exe = Join-Path $repoRoot "target\debug\holo-forensics.exe"
$captureRoot = Join-Path $repoRoot $OutputDir
New-Item -ItemType Directory -Force -Path $captureRoot | Out-Null

if (-not $SkipBuild) {
    cargo build
} elseif (-not (Test-Path $exe)) {
    cargo build
}

function Get-WindowBounds([IntPtr]$Handle) {
    $rect = New-Object Win32UiCapture+RECT
    [void][Win32UiCapture]::GetWindowRect($Handle, [ref]$rect)

    [pscustomobject]@{
        X = $rect.Left
        Y = $rect.Top
        Width = $rect.Right - $rect.Left
        Height = $rect.Bottom - $rect.Top
    }
}

function Get-ClientBounds([IntPtr]$Handle) {
    $clientRect = New-Object Win32UiCapture+RECT
    if (-not [Win32UiCapture]::GetClientRect($Handle, [ref]$clientRect)) {
        throw "Failed to read client bounds."
    }

    $topLeft = New-Object Win32UiCapture+POINT
    $topLeft.X = 0
    $topLeft.Y = 0
    if (-not [Win32UiCapture]::ClientToScreen($Handle, [ref]$topLeft)) {
        throw "Failed to convert client origin to screen coordinates."
    }

    [pscustomobject]@{
        X = $topLeft.X
        Y = $topLeft.Y
        Width = $clientRect.Right - $clientRect.Left
        Height = $clientRect.Bottom - $clientRect.Top
    }
}

function Wait-LargeWindow($Process) {
    for ($i = 0; $i -lt 80; $i++) {
        Start-Sleep -Milliseconds 250
        $p = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
        if (-not $p) {
            break
        }
        if ($p.MainWindowHandle -eq 0) {
            continue
        }
        $bounds = Get-WindowBounds $p.MainWindowHandle
        if ($bounds.Width -ge 620 -and $bounds.Height -ge 540) {
            return $p
        }
    }
    throw "Timed out waiting for the main UI window."
}

function Move-WindowIntoView([IntPtr]$Handle) {
    $bounds = Get-WindowBounds $Handle
    $workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $targetWidth = $bounds.Width
    $targetHeight = $bounds.Height
    $targetX = $workArea.Left + [Math]::Max(20, [int](($workArea.Width - $targetWidth) / 2))
    $targetY = $workArea.Top + 20
    [void][Win32UiCapture]::MoveWindow($Handle, $targetX, $targetY, $targetWidth, $targetHeight, $true)
}

function Save-WindowScreenshot([IntPtr]$Handle, [string]$Name) {
    $bounds = Get-ClientBounds $Handle

    if ($TrimMargin -gt 0) {
        $maxHorizontalTrim = [Math]::Max(0, [int](($bounds.Width - 1) / 2))
        $maxVerticalTrim = [Math]::Max(0, [int](($bounds.Height - 1) / 2))
        $appliedTrim = [Math]::Min($TrimMargin, [Math]::Min($maxHorizontalTrim, $maxVerticalTrim))
        $bounds = [pscustomobject]@{
            X = $bounds.X + $appliedTrim
            Y = $bounds.Y + $appliedTrim
            Width = $bounds.Width - ($appliedTrim * 2)
            Height = $bounds.Height - ($appliedTrim * 2)
        }
    }

    if ($bounds.Width -le 0 -or $bounds.Height -le 0) {
        throw "Window bounds were empty for $Name."
    }

    $path = Join-Path $captureRoot ("$Name.png")
    if (Test-Path $path) {
        Remove-Item $path -Force
    }

    $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bitmap.Size)
        $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }

    Get-Item $path | Select-Object Name, Length, FullName
}

function Invoke-WindowScrollDown([IntPtr]$Handle) {
    $bounds = Get-WindowBounds $Handle
    $x = $bounds.X + [int]($bounds.Width / 2)
    $y = $bounds.Y + [int]($bounds.Height / 2)
    [void][Win32UiCapture]::SetCursorPos($x, $y)
    Start-Sleep -Milliseconds 100
    [Win32UiCapture]::mouse_event(0x0800, 0, 0, -720, [UIntPtr]::Zero)
}

function Invoke-Capture([string]$State) {
    $arguments = @("ui", "--screenshot-state", $State)
    if ($Theme -ne "system") {
        $arguments += @("--theme", $Theme)
    }

    $proc = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru
    try {
        $p = Wait-LargeWindow $proc
        $handle = $p.MainWindowHandle
        Move-WindowIntoView $handle
        [void][Win32UiCapture]::SetForegroundWindow($handle)
        Start-Sleep -Milliseconds 1200
        Save-WindowScreenshot $handle $State
        if ($State -eq "collection-progress") {
            Invoke-WindowScrollDown $handle
            Start-Sleep -Milliseconds 500
            Save-WindowScreenshot $handle "$State-details"
            Invoke-WindowScrollDown $handle
            Start-Sleep -Milliseconds 500
            Save-WindowScreenshot $handle "$State-detail-items"
        }
    }
    finally {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force
        }
    }
}

foreach ($state in $States) {
    Invoke-Capture $state
}
