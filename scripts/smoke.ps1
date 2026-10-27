param([string]$Binary = (Join-Path $PSScriptRoot '../bin/nullbot-emails-mcp.exe'))
$ErrorActionPreference = 'Stop'
$expected = @('email_accounts', 'email_list', 'email_get', 'email_send')
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = (Resolve-Path $Binary).Path
$psi.Arguments = '--transport stdio'
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
# Override inherited account configuration; never read credential files or contact providers.
$psi.EnvironmentVariables['NULLBOT_SERVICE_ACCOUNTS'] = '[]'
$psi.EnvironmentVariables['NULLBOT_MCP_AUTH_TOKEN'] = ''
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
try {
    if (-not $p.Start()) { throw 'Failed to start server' }
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    $requests = @(
        @{jsonrpc='2.0'; id=1; method='initialize'; params=@{protocolVersion='2024-11-05'; capabilities=@{}; clientInfo=@{name='offline-smoke'; version='1'}}},
        @{jsonrpc='2.0'; method='notifications/initialized'},
        @{jsonrpc='2.0'; id=2; method='tools/list'},
        @{jsonrpc='2.0'; id=3; method='tools/call'; params=@{name=$expected[0]; arguments=@{}}},
        @{jsonrpc='2.0'; id=4; method='tools/call'; params=@{name=$expected[0]; arguments=@{unexpected=$true}}}
    )
    foreach ($request in $requests) { $p.StandardInput.WriteLine(($request | ConvertTo-Json -Compress -Depth 10)) }
    $p.StandardInput.Close()
    if (-not $p.WaitForExit(15000)) { $p.Kill(); throw 'Stdio smoke timed out' }
    $out = $stdout.GetAwaiter().GetResult()
    $err = $stderr.GetAwaiter().GetResult()
    if ($p.ExitCode -ne 0 -or $err.Trim()) { throw "Unexpected exit/stderr: $($p.ExitCode) $err" }
    $responses = @($out -split '\r?\n' | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
    if ($responses.Count -ne 4) { throw "Expected four responses, got $($responses.Count)" }
    foreach ($response in $responses) { if ($response.error) { throw 'JSON-RPC error' } }
    $init = @($responses | Where-Object { $_.id -eq 1 })
    if ($init.Count -ne 1 -or -not $init[0].result.protocolVersion) { throw 'Missing initialization result' }
    $list = @($responses | Where-Object { $_.id -eq 2 })
    $tools = @($list[0].result.tools)
    if (Compare-Object ($expected | Sort-Object) (@($tools.name) | Sort-Object)) { throw 'Tool names differ from contract' }
    foreach ($tool in $tools) { if ($tool.inputSchema.type -ne 'object' -or $tool.inputSchema.additionalProperties -ne $false) { throw 'Non-strict tool schema' } }
    $status = @($responses | Where-Object { $_.id -eq 3 })
    if ($status[0].result.isError) { throw 'Empty account status failed' }
    $accounts = $status[0].result.content[0].text | ConvertFrom-Json
    if ($null -eq $accounts.accounts -or @($accounts.accounts).Count -ne 0) { throw 'Expected empty accounts' }
    $denied = @($responses | Where-Object { $_.id -eq 4 })
    if (-not $denied[0].result.isError) { throw 'Unknown argument was accepted' }
    Write-Output "PASS stdio initialize, tools/list ($($tools.Count): $($tools.name -join ', ')), empty account status, unknown-argument rejection; exit=0; stderr empty"
} finally {
    if ($p.Id -and -not $p.HasExited) { $p.Kill() }
    $p.Dispose()
}
