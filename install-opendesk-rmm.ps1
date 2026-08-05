# Auto-elevação para Administrador
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Wait
    exit
}

Write-Host "Iniciando instalacao OpenDesk RMM..." -ForegroundColor Cyan

# Instalar Chocolatey se nao existir
if (-not (Test-Path "$env:ProgramData\chocolatey\bin\choco.exe")) {
    Write-Host "Instalando Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
} else {
    Write-Host "Chocolatey ja instalado." -ForegroundColor Green
}

# Criar diretorio
$dir = "$env:ProgramData\OpenDesk RMM"
Write-Host "Criando diretorio: $dir" -ForegroundColor Yellow
New-Item -Path $dir -ItemType Directory -Force | Out-Null

# Download do agente
$agentPath = "$dir\agent.exe"
Write-Host "Baixando agente..." -ForegroundColor Yellow
iwr "https://github.com/nextcoreti/opendesk-rmm-agent/releases/download/v2.10.14/OpenDesk-RMM-Agent.exe" -OutFile $agentPath

# Desbloquear e instalar
Write-Host "Instalando agente..." -ForegroundColor Yellow
Unblock-File $agentPath
& $agentPath -install -token e4e16c6fb4ac56c604fd6a0f0ecfdae1512a2dc59b3713dfa85e1fb9246d7702 -api-url https://rda.npsolucoesinfo.com.br

# Limpar
Remove-Item $agentPath -Force -ErrorAction SilentlyContinue

Write-Host "Instalacao concluida!" -ForegroundColor Green
