$ErrorActionPreference = "Stop"

$patterns = @(
    @{ Name = "AWS access key"; Regex = "A[KS]IA[0-9A-Z]{16}" },
    @{ Name = "GitHub token"; Regex = "gh[pousr]_[A-Za-z0-9_]{36,}" },
    @{ Name = "GitHub fine-grained token"; Regex = "github_pat_[A-Za-z0-9_]{80,}" },
    @{ Name = "Google API key"; Regex = "AIza[0-9A-Za-z\-_]{35}" },
    @{ Name = "Slack token"; Regex = "xox[baprs]-[0-9A-Za-z-]{10,}" },
    @{ Name = "Private key"; Regex = "-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----" },
    @{ Name = "High confidence secret assignment"; Regex = "(?i)\b(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*['""][^'""]{24,}['""]" }
)

$skipExtensions = @(
    ".bmp", ".dll", ".exe", ".gif", ".ico", ".jpg", ".jpeg", ".pdb", ".png",
    ".rlib", ".ttf", ".wasm", ".webp", ".zip"
)

$matches = New-Object System.Collections.Generic.List[string]
$files = git ls-files -z
if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed"
}

foreach ($path in ($files -split "`0")) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        continue
    }

    $fullPath = Join-Path (Get-Location) $path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        continue
    }

    $extension = [System.IO.Path]::GetExtension($fullPath).ToLowerInvariant()
    if ($skipExtensions -contains $extension) {
        continue
    }

    $item = Get-Item -LiteralPath $fullPath
    if ($item.Length -gt 2MB) {
        continue
    }

    $bytes = [System.IO.File]::ReadAllBytes($fullPath)
    if ($bytes -contains 0) {
        continue
    }

    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    $lines = $text -split "`r?`n"

    for ($lineNumber = 0; $lineNumber -lt $lines.Count; $lineNumber++) {
        foreach ($pattern in $patterns) {
            if ([System.Text.RegularExpressions.Regex]::IsMatch($lines[$lineNumber], $pattern.Regex)) {
                $matches.Add(("{0}:{1}: {2}" -f $path, ($lineNumber + 1), $pattern.Name))
            }
        }
    }
}

if ($matches.Count -gt 0) {
    Write-Error ("Potential secrets found:`n{0}" -f ($matches -join "`n"))
    exit 1
}

Write-Host "No high-confidence secrets found in tracked text files."
