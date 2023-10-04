#Requires -RunAsAdministrator
$sysmonProc = Get-Process -Name  Sysmon* -ErrorAction SilentlyContinue

if ($sysmonProc) {
    Write-Host "Sysmon is already installed! Quitting..."
    Start-Sleep -Seconds 2
} else {
    $Url = "https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_logs.ps1"
    $script = "$env:TMP\enable_logs.ps1"
    
    Invoke-WebRequest -Uri $Url -OutFile $script -UseBasicParsing
    $run = "$script -y" # -sysmononly 
    Invoke-Expression $run

    Start-Sleep -Seconds 2
    Remove-Item $script
}
