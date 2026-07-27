$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$results = [System.Collections.Generic.List[object]]::new()
function Gate([string]$Name, [scriptblock]$Action) {
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    try {
        & $Action
        if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { throw "exit code $LASTEXITCODE" }
        $results.Add([pscustomobject]@{Gate=$Name;Status='PASS';Detail=''})
    } catch {
        $results.Add([pscustomobject]@{Gate=$Name;Status='FAIL';Detail=$_.Exception.Message})
        Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    $global:LASTEXITCODE = 0
}

Gate 'Tool versions' {
    python --version; if ($LASTEXITCODE -ne 0) { throw 'python unavailable' }
    node --version; if ($LASTEXITCODE -ne 0) { throw 'node unavailable' }
    npm --version; if ($LASTEXITCODE -ne 0) { throw 'npm unavailable' }
}
Gate 'Python dependencies' { python -m pip install -r requirements.txt }
Gate 'Python compile' { python -m compileall -q backend tests }
Gate 'FastAPI import' { python -c "from backend.app.main import app; print(app.title)" }
Gate 'Alembic heads/current' { alembic heads; alembic current }
Gate 'Alembic upgrade head' { alembic upgrade head }
Gate 'Backend pytest' { python -m pytest -q }
Gate 'Frontend clean install' { Push-Location frontend; try { npm ci } finally { Pop-Location } }
Gate 'Frontend tests' { Push-Location frontend; try { npm test } finally { Pop-Location } }
Gate 'Frontend production build' { Push-Location frontend; try { npm run build } finally { Pop-Location } }

Write-Host "`n=== RELEASE VERIFICATION SUMMARY ===" -ForegroundColor Yellow
$results | Format-Table -AutoSize
$failed = @($results | Where-Object Status -eq 'FAIL')
if ($failed.Count -gt 0) {
    Write-Host "`nRELEASE_BLOCKED: $($failed.Count) required gate(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "`nRELEASE_VERIFICATION_OK" -ForegroundColor Green
exit 0
