#Requires -RunAsAdministrator

$confirmation = $(Write-Host -f Yellow -NoNewLine "WARNING: This script will download and install Sysmon, and make GPO changes that will increase log volume on the host. Do you want to continue? (y/n): "; Read-Host)
if (-not($confirmation -eq 'y')) {
    Write-Host "`nBye!"
    Exit
}

$cm = [char]0x2713

# Download, install and configure Sysmon (uninstall and reinstall if present)
$sysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonOut = "$env:temp\Sysmon.zip"

$sysmonConf = "https://raw.githubusercontent.com/bobby-tablez/FT-Sysmon-Config/master/ft-sysmonconfig-export.xml"
$sysmonConfOut = "$env:temp\ft-sysmonconfig-export.xml"

Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Downloading Sysmon..."
Invoke-WebRequest -URI $sysmonURL -OutFile $sysmonOut

Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Downloading Sysmon config import file..."
Invoke-WebRequest -URI $sysmonConf -OutFile $sysmonConfOut

Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Extracting Sysmon archive..."
Expand-Archive $sysmonOut -Destination $env:temp -Force

Function b64{
    $b64test = [Environment]::Is64BitOperatingSystem
    return $b64test
}

if (b64) { 
    $service64 = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if ($service64.Length -gt 0) {
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Uninstalling Existing version of Sysmon64..."
        Start-Process "Sysmon64.exe" -ArgumentList "-u" -Wait
    }
    write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Installing Sysmon64..."
    Start-Process -FilePath "$env:temp\Sysmon64.exe" -ArgumentList "-accepteula -i $sysmonConfOut" -Wait
}
else {
    $service = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
    if ($service.Length -gt 0) {
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Uninstalling Existing version of Sysmon..."
        Start-Process "Sysmon.exe" -ArgumentList "-u" -Wait
    }
    write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Installing Sysmon..."
    Start-Process -FilePath "$env:temp\Sysmon.exe" -ArgumentList "-accepteula -i $sysmonConfOut" -Wait
}
Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Sysmon successfully installed!"
Write-Host ""


# PowerShell logging registry changes
Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling PowerShell scriptblock logging..."
$PSregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$PSregValName = "EnableScriptBlockLogging"
$PSregValDat = 1

if (-not (Test-Path $PSregPath)) {
    New-Item -Path $PSregPath -ItemType Directory -Force
}
Set-ItemProperty -Path $PSregPath -Name $PSregValName -Value $PSregValDat -Type DWord

Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] PowerShell Script Block Logging enabled!"


# Enabling EventID 4688 with command line logging
Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling process logging (EVID 4688) w/ commandline..."
$AuditSubcategory = "Process Creation"
$EnableAudit = "enable"
$DisableAudit = "disable"

Invoke-Expression -Command "auditpol /set /subcategory:`"$AuditSubcategory`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null

$AuditCmdPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$AuditCmdValName = "ProcessCreationIncludeCmdLine_Enabled"
$AuditCmdValDat = 1

if (-not (Test-Path $AuditCmdPath)) {
    New-Item -Path $AuditCmdPath -ItemType Directory -Force
}
Set-ItemProperty -Path $AuditCmdPath -Name $AuditCmdValName -Value $AuditCmdValDat -Type DWord

Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Event ID 4688 enabled with commandline!"


# Enabling other audit policies which might be useful (tune if required). Based on: https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=RecBaselineAudPol
Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling other useful audit policies..."

Invoke-Expression -Command "auditpol /set /subcategory:`"Security State Change`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Security System Extension`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"System Integrity`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"IPsec Driver`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Other System Events`" /success:$DisableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Logon`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Logoff`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Account Lockout`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"IPsec Main Mode`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"IPsec Quick Mode`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"IPsec Extended Mode`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Special Logon`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Other Logon/Logoff Events`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Network Policy Server`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"File System`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Registry`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Kernel Object`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"SAM`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Certification Services`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Application Generated`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Handle Manipulation`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"File Share`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Filtering Platform Packet Drop`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Filtering Platform Connection`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Other Object Access Events`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Sensitive Privilege Use`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Non Sensitive Privilege Use`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Other Privilege Use Events`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Process Termination`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"DPAPI Activity`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"RPC Events`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Audit Policy Change`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Authentication Policy Change`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Authorization Policy Change`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"MPSSVC Rule-Level Policy Change`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Filtering Platform Policy Change`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Other Policy Change Events`" /success:$DisableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"User Account Management`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Computer Account Management`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Security Group Management`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Distribution Group Management`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Application Group Management`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Other Account Management Events`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Directory Service Access`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Directory Service Changes`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Directory Service Replication`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Detailed Directory Service Replication`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Credential Validation`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Kerberos Service Ticket Operations`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Other Account Logon Events`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
Invoke-Expression -Command "auditpol /set /subcategory:`"Kerberos Authentication Service`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null

Write-Host -f green "`nDone!"
