<#PSScriptInfo
.VERSION 
    1.1
.AUTHOR
    bobby-tablez
.GUID
    a5d40ad0-297b-4269-80f9-934f6341367c
.SYNOPSIS
    Enables detailed logging telemetry for a host. 
.DESCRIPTION 
     This module provides a large amount of logging telemetry. This includes Sysinternals Sysmon, PowerShell module and scriptblock logging, and audit policies for key event IDs. This script can be modified to suit organizational needs, however it should be tested first as it can generate a huge amount of log data depending on the host.
.NOTES 
    Use at your own risk.
.LINK 
    https://raw.githubusercontent.com/bobby-tablez/Invoke-XORfuscation/main/Invoke-XORfuscation.ps1
    https://www.securonix.com/blog/improving-blue-team-threat-detection-with-enhanced-siem-telemetry/
.PARAMETER -sysmononly 
    This will ONLY download and install sysmon. If sysmon is already present, it will perform a reinstall using the provided XML import config file.    
.EXAMPLE 
    enable_logs.ps1 -sysmononly
.PARAMETER -y 
    This will skip the "are you sure?" prompt upon initial execution.
.EXAMPLE 
    enable_logs.ps1 -y
    enable_logs.ps1 -y -sysmononly
.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

#>

#Requires -RunAsAdministrator

param(
    [switch]$sysmononly,
    [switch]$y
)

if (-Not $y){
    if ($sysmononly){
        $confirmation = $(Write-Host -f Yellow -NoNewLine "WARNING: This script will download and install Sysmon. Do you want to continue? (y/n): "; Read-Host)
    }else {
        $confirmation = $(Write-Host -f Yellow -NoNewLine "WARNING: This script will download and install Sysmon, and make GPO changes that will increase log volume on the host. Do you want to continue? (y/n): "; Read-Host)
    }

    if (-not($confirmation -eq 'y')) {
        Write-Host "`nBye!"
        Exit
    }
}

$cm = [char]0x2713
$ex = [char]0x274C

$sysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonOut = "$env:temp\Sysmon.zip"

$sysmonConf = "https://raw.githubusercontent.com/bobby-tablez/FT-Sysmon-Config/master/ft-sysmonconfig-export.xml"
$sysmonConfOut = "$env:temp\ft-sysmonconfig-export.xml"

Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Downloading Sysmon..."
try { 
    Invoke-WebRequest -URI $sysmonURL -OutFile $sysmonOut
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Sysmon downloaded..."
} catch {
    $errorSysmon = $_.Exception.Message
    Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] Error occurred while downloading Sysmon: $errorSysmon"
}

Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Downloading Sysmon config import file..."
try { 
    Invoke-WebRequest -URI $sysmonConf -OutFile $sysmonConfOut
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Import config file downloaded..."
} catch {
    $errorXML = $_.Exception.Message
    Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] Error occurred while downloading the config import file: $errorXML"
}

Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Extracting Sysmon archive..."
try { 
    Expand-Archive $sysmonOut -Destination $env:temp -ErrorAction Stop -Force
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Sysmon archive extracted..."
} catch {
    $errorZIP = $_.Exception.Message
    Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] Error occurred while extracting the Sysmon archive: $errorZIP"
}

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

if (-Not $sysmononly){

    # PowerShell logging registry changes
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling PowerShell scriptblock logging..."
    $PSregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $PSregValName = "EnableScriptBlockLogging"
    $PSregValDat = 1

    if (-not (Test-Path $PSregPath)) {
        New-Item -Path $PSregPath -ItemType Directory -Force  | Out-Null
    }
    Set-ItemProperty -Path $PSregPath -Name $PSregValName -Value $PSregValDat -Type DWord  | Out-Null
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] PowerShell Script Block Logging enabled!"

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling PowerShell module logging..."
    $PSMregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $PSMregValName = "EnableModuleLogging"
    $PSMregValDat = 1

    if (-not (Test-Path $PSMregPath)) {
        New-Item -Path $PSMregPath -ItemType Directory -Force  | Out-Null
    }
    Set-ItemProperty -Path $PSMregPath -Name $PSMregValName -Value $PSMregValDat -Type DWord  | Out-Null

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] PowerShell Module Logging enabled!"


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

    Invoke-Expression -Command "auditpol /set /subcategory:`"Security State Change`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Security System Extension`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"System Integrity`" /success:$EnableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"IPsec Driver`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Other System Events`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Logon`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Logoff`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Account Lockout`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"IPsec Main Mode`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"IPsec Quick Mode`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"IPsec Extended Mode`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Special Logon`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Other Logon/Logoff Events`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Network Policy Server`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"File System`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Registry`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Kernel Object`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"SAM`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Certification Services`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Application Generated`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Handle Manipulation`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"File Share`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Filtering Platform Packet Drop`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Filtering Platform Connection`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Other Object Access Events`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Sensitive Privilege Use`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Non Sensitive Privilege Use`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Other Privilege Use Events`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Process Termination`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"DPAPI Activity`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
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
    Invoke-Expression -Command "auditpol /set /subcategory:`"Directory Service Replication`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Detailed Directory Service Replication`" /success:$DisableAudit /failure:$DisableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Credential Validation`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Kerberos Service Ticket Operations`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Other Account Logon Events`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null
    Invoke-Expression -Command "auditpol /set /subcategory:`"Kerberos Authentication Service`" /success:$EnableAudit /failure:$EnableAudit" | Out-Null

    # Upate GPOs
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Updating GPOs using gpupdate..."
    Invoke-Expression -Command "gpupdate /force" | Out-Null
};
Write-Host -f green "`nDone!"
