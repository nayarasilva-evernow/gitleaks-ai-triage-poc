# Local secret scan + AI triage (Windows PowerShell)
# Pré-requisitos: gitleaks no PATH, Python 3.11+, GROQ_API_KEY (gratuito)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Error "gitleaks não encontrado no PATH. Instale: https://github.com/gitleaks/gitleaks#installing"
}

if (-not (Test-Path .venv)) {
    python -m venv .venv
}
.\.venv\Scripts\pip install -r requirements.txt | Out-Null

Write-Host "==> Gitleaks detect"
$gitleaksExit = 0
gitleaks detect --source . --config .gitleaks.toml --report-path findings.json --report-format json --verbose
if ($LASTEXITCODE -ne 0) { $gitleaksExit = $LASTEXITCODE }

if (-not (Test-Path findings.json)) {
    "[]" | Set-Content findings.json -Encoding utf8
}

Write-Host "==> AI triage"
.\.venv\Scripts\python -m triage --findings findings.json --out triage-report.json --fail-on true_positive
$triageExit = $LASTEXITCODE

Write-Host "Gitleaks exit: $gitleaksExit | Triage exit: $triageExit"
exit $triageExit
