Set-StrictMode -Version Latest

function New-HookResponse {
    param(
        [string]$Decision = 'allow',
        [string]$Reason,
        [string]$SystemMessage,
        [string]$AdditionalContext
    )

    $hookOutput = @{
        hookEventName = 'PreToolUse'
        permissionDecision = $Decision
    }

    if ($Reason) {
        $hookOutput.permissionDecisionReason = $Reason
    }

    if ($AdditionalContext) {
        $hookOutput.additionalContext = $AdditionalContext
    }

    $response = @{ hookSpecificOutput = $hookOutput }

    if ($SystemMessage) {
        $response.systemMessage = $SystemMessage
    }

    return $response | ConvertTo-Json -Depth 10 -Compress
}

function Normalize-Path {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    return ($Path -replace '\\', '/').Trim()
}

function Get-CommandText {
    param($Payload)

    switch ([string]$Payload.tool_name) {
        'run_in_terminal' {
            return [string]$Payload.tool_input.command
        }
        'send_to_terminal' {
            return [string]$Payload.tool_input.command
        }
        'create_and_run_task' {
            $taskCommand = [string]$Payload.tool_input.task.command
            $taskArgs = @($Payload.tool_input.task.args | ForEach-Object { [string]$_ })

            if ($taskArgs.Count -gt 0) {
                return ($taskCommand + ' ' + ($taskArgs -join ' '))
            }

            return $taskCommand
        }
        default {
            return $null
        }
    }
}

function Test-GitCommitOrPushCommand {
    param([string]$CommandText)

    if ([string]::IsNullOrWhiteSpace($CommandText)) {
        return $false
    }

    return $CommandText -match '(^|[;&|\s])git\s+(commit|push)\b'
}

function Test-GitPushCommand {
    param([string]$CommandText)

    if ([string]::IsNullOrWhiteSpace($CommandText)) {
        return $false
    }

    return $CommandText -match '(^|[;&|\s])git\s+push\b'
}

function Get-CommandOutputLines {
    param(
        [string[]]$Arguments,
        [string]$OverrideVariableName
    )

    $override = [Environment]::GetEnvironmentVariable($OverrideVariableName)
    if (-not [string]::IsNullOrWhiteSpace($override)) {
        return @($override -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $output = & git @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        return @()
    }

    return @($output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Parse-StatusLines {
    param([string[]]$Lines)

    $changes = @()

    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.Length -lt 4) {
            continue
        }

        $status = $line.Substring(0, 2).Trim()
        $path = $line.Substring(3).Trim()

        if ($path -like '* -> *') {
            $path = ($path -split ' -> ', 2)[1].Trim()
        }

        $changes += [PSCustomObject]@{
            Path = Normalize-Path $path
            Status = $status
        }
    }

    return $changes
}

function Parse-NameStatusLines {
    param([string[]]$Lines)

    $changes = @()

    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $parts = @($line -split "`t")
        if ($parts.Count -lt 2) {
            continue
        }

        $changes += [PSCustomObject]@{
            Path = Normalize-Path $parts[-1]
            Status = [string]$parts[0]
        }
    }

    return $changes
}

function Merge-Changes {
    param([object[]]$Changes)

    $byPath = @{}

    foreach ($change in $Changes) {
        if (-not $change.Path) {
            continue
        }

        if ($byPath.ContainsKey($change.Path)) {
            if ($change.Status -and $byPath[$change.Path].Status -notlike "*$($change.Status)*") {
                $byPath[$change.Path].Status = "$($byPath[$change.Path].Status),$($change.Status)"
            }
            continue
        }

        $byPath[$change.Path] = [PSCustomObject]@{
            Path = $change.Path
            Status = [string]$change.Status
        }
    }

    return @($byPath.Values)
}

function Get-PendingChanges {
    $lines = Get-CommandOutputLines -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -OverrideVariableName 'HOLO_DOC_GUARD_STATUS_LINES'
    return Parse-StatusLines -Lines $lines
}

function Get-AheadChanges {
    $override = [Environment]::GetEnvironmentVariable('HOLO_DOC_GUARD_AHEAD_LINES')
    if (-not [string]::IsNullOrWhiteSpace($override)) {
        return Parse-NameStatusLines -Lines @($override -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $null = & git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>$null
    if ($LASTEXITCODE -ne 0) {
        return @()
    }

    $lines = Get-CommandOutputLines -Arguments @('diff', '--name-status', '@{upstream}..HEAD') -OverrideVariableName 'HOLO_DOC_GUARD_AHEAD_LINES'
    return Parse-NameStatusLines -Lines $lines
}

function Test-StatusRequiresReadme {
    param([string]$Status)

    if ([string]::IsNullOrWhiteSpace($Status)) {
        return $false
    }

    return $Status -match '(\?\?|A|D|R)'
}

$rawInput = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($rawInput)) {
    Write-Output (New-HookResponse)
    exit 0
}

try {
    $payload = $rawInput | ConvertFrom-Json -Depth 20
} catch {
    Write-Output (New-HookResponse -SystemMessage 'git-doc-sync hook ignored invalid JSON input.')
    exit 0
}

$commandText = Get-CommandText -Payload $payload
if (-not (Test-GitCommitOrPushCommand -CommandText $commandText)) {
    Write-Output (New-HookResponse)
    exit 0
}

$gitCommandAvailable = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCommandAvailable) {
    Write-Output (New-HookResponse -SystemMessage 'git-doc-sync hook skipped because Git is unavailable.')
    exit 0
}

$originalLocation = Get-Location

try {
    if ($payload.cwd -and (Test-Path -LiteralPath $payload.cwd)) {
        Set-Location -LiteralPath $payload.cwd
    }

    $changes = @()
    $changes += Get-PendingChanges

    if (Test-GitPushCommand -CommandText $commandText) {
        $changes += Get-AheadChanges
    }

    $changes = Merge-Changes -Changes $changes
    if ($changes.Count -eq 0) {
        Write-Output (New-HookResponse)
        exit 0
    }

    $parserChanges = @($changes | Where-Object {
        $_.Path -eq 'src/parser_catalog.rs' -or $_.Path.StartsWith('src/parsers/')
    })
    $collectionChanges = @($changes | Where-Object {
        $_.Path -eq 'src/collection_catalog.rs' -or $_.Path -eq 'src/collection_metadata.rs' -or $_.Path.StartsWith('src/collections/')
    })

    if ($parserChanges.Count -eq 0 -and $collectionChanges.Count -eq 0) {
        Write-Output (New-HookResponse)
        exit 0
    }

    $hasParserWikiChange = @($changes | Where-Object { $_.Path.StartsWith('holoForensics.wiki/parsers/') }).Count -gt 0
    $hasCollectionWikiChange = @($changes | Where-Object { $_.Path.StartsWith('holoForensics.wiki/collections/') }).Count -gt 0
    $hasReadmeChange = @($changes | Where-Object { $_.Path -eq 'README.md' }).Count -gt 0

    $newOrRenamedParserModule = @($parserChanges | Where-Object {
        $_.Path.StartsWith('src/parsers/') -and $_.Path.EndsWith('.rs') -and (Test-StatusRequiresReadme -Status $_.Status)
    }).Count -gt 0

    $newOrRenamedCollectionModule = @($collectionChanges | Where-Object {
        $_.Path.StartsWith('src/collections/') -and $_.Path.EndsWith('.rs') -and (Test-StatusRequiresReadme -Status $_.Status)
    }).Count -gt 0

    $catalogOrContractSurfaceChanged = @($changes | Where-Object {
        $_.Path -eq 'src/parser_catalog.rs' -or $_.Path -eq 'src/collection_catalog.rs' -or $_.Path -eq 'src/collection_metadata.rs'
    }).Count -gt 0

    $missing = @()

    if ($parserChanges.Count -gt 0 -and -not $hasParserWikiChange) {
        $missing += 'update the affected parser page or parser index under holoForensics.wiki/parsers/'
    }

    if ($collectionChanges.Count -gt 0 -and -not $hasCollectionWikiChange) {
        $missing += 'update the affected collection page or collection index under holoForensics.wiki/collections/'
    }

    if (($newOrRenamedParserModule -or $newOrRenamedCollectionModule -or $catalogOrContractSurfaceChanged) -and -not $hasReadmeChange) {
        $missing += 'update README.md for parser or collection coverage, contract, or architecture changes'
    }

    if ($missing.Count -eq 0) {
        Write-Output (New-HookResponse)
        exit 0
    }

    $relevantPaths = @($parserChanges + $collectionChanges | Select-Object -ExpandProperty Path -Unique)
    $additionalContext = 'Relevant parser or collection changes: ' + ($relevantPaths -join ', ')
    $reason = 'Parser and collector changes require synchronized docs before git commit or push: ' + ($missing -join '; ')

    Write-Output (New-HookResponse -Decision 'deny' -Reason $reason -AdditionalContext $additionalContext)
    exit 0
} finally {
    Set-Location -LiteralPath $originalLocation
}