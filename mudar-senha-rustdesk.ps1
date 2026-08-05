# Mudar senha do custom_.txt do RustDesk
# Execute como Administrador

param(
    [Parameter(Mandatory=$true)]
    [string]$AppName,

    [Parameter(Mandatory=$true)]
    [string]$NovaSenha
)

$path = "C:\Program Files\$AppName\custom_.txt"

if (-not (Test-Path $path)) {
    Write-Host "ERRO: Arquivo nao encontrado em: $path" -ForegroundColor Red
    exit 1
}

# Decodificar
$base64 = Get-Content $path -Raw
$json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64.Trim()))
$obj = $json | ConvertFrom-Json

Write-Host "Senha atual: $($obj.password)" -ForegroundColor Yellow

# Alterar senha
$obj.password = $NovaSenha

# Re-encodar e salvar
$newJson = $obj | ConvertTo-Json -Compress -Depth 10
$newBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($newJson))
Set-Content $path $newBase64 -NoNewline

Write-Host "Senha alterada para: $NovaSenha" -ForegroundColor Green

# Reiniciar servico
Write-Host "Reiniciando servico RustDesk..." -ForegroundColor Cyan
net stop rustdesk 2>$null
Start-Sleep -Seconds 2
net start rustdesk 2>$null

Write-Host "Concluido!" -ForegroundColor Green
