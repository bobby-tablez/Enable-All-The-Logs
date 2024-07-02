<#PSScriptInfo
.VERSION 
    1.2
.AUTHOR
    bobby-tablez (Tim Peck)
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
.PARAMETER -config
    Bring your own XML config file. When the -config argument is passed, supply a direct URL to a Sysmon config import file. When no argument is supplied it will download: "https://raw.githubusercontent.com/bobby-tablez/FT-Sysmon-Config/master/ft-sysmonconfig-export.xml"
.EXAMPLE 
    enable_logs.ps1 -y
    enable_logs.ps1 -y -sysmononly
    enable_logs.ps1 -y -sysmononly -config https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
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

param(
    [switch]$sysmononly,
    [switch]$y,
    [string]$config
)

# Check for administrator privs
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host -ForegroundColor Red "Enable All The Logs! requires Administrator privileges. Please rerun in an admin PowerShell console."
    exit
}

# Bypass the warning prompt when -y arguement is supplied
if (-Not $y){
    if ($sysmononly){
        $confirmation = $(Write-Host -f Yellow -NoNewLine "CAUTION: This script will download and install Sysmon. Do you want to continue? (y/n): "; Read-Host)
    }else {
        $confirmation = $(Write-Host -f Yellow -NoNewLine "CAUTION: This script will download and install Sysmon and make GPO and registry changes that will increase log volume. Continue? (y/n): "; Read-Host)
    }

    if (-not($confirmation -eq 'y')) {
        Write-Host "`nBye!"
        Exit
    }
}

# checkmark characters green/red
$cm = [char]0x2713
$ex = [char]0x274C

$sysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonOut = "$env:temp\Sysmon.zip"
$sysmonConfOut = "$env:temp\sysmon-config.xml"

# Use user-supplied config import file if -config arguement is supplied
if ($config) {
    $sysmonConf = $config
} else {
    $sysmonConf = "https://raw.githubusercontent.com/bobby-tablez/FT-Sysmon-Config/master/ft-sysmonconfig-export.xml"
}

# Begin actions
Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Downloading Sysmon"
try { 
    Invoke-WebRequest -URI $sysmonURL -OutFile $sysmonOut
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Sysmon downloaded"
} catch {
    $errorSysmon = $_.Exception.Message
    Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] Error occurred while downloading Sysmon: $errorSysmon"
    exit 1
}

# Sysmon XML file
Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Downloading Sysmon config import file"
try { 
    Invoke-WebRequest -URI $sysmonConf -OutFile $sysmonConfOut
    # Attempt to load the file as an XML to validate its content
    [xml]$xmlContent = Get-Content -Path $sysmonConfOut
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Import config file downloaded and validated as XML"
} catch {
    $errorXML = $_.Exception.Message
    if ($_ -is [System.Xml.XmlException]) {
        Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] The downloaded config import file is not valid XML: $errorXML"
        exit 1 
    } else {
        Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] Error occurred while downloading the config import file: $errorXML"
        exit 1
    }
}

# Extract Sysmon archive contents into %TEMP%
Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Extracting Sysmon archive"
try { 
    Expand-Archive $sysmonOut -Destination $env:temp -ErrorAction Stop -Force
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Sysmon archive extracted"
} catch {
    $errorZIP = $_.Exception.Message
    Write-Host "[ " -nonewline; Write-Host $ex -f red -nonewline; Write-Host " ] Error occurred while extracting the Sysmon archive: $errorZIP"
    exit 1
}

Function b64{
    $b64test = [Environment]::Is64BitOperatingSystem #Used to install x86/x64 Sysmon per OS architecture
    return $b64test
}

if (b64) { 
    # Uninstall if present (64-bit)
    $service64 = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if ($service64.Length -gt 0) {
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Uninstalling Existing version of Sysmon64"
        Start-Process "Sysmon64.exe" -ArgumentList "-u" -Wait
    }
    # Install Sysmon (64-bit)
    write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Installing Sysmon64"
    Start-Process -FilePath "$env:temp\Sysmon64.exe" -ArgumentList "-accepteula -i $sysmonConfOut" -Wait
}
else {
    # Uninstall if present (32-bit)
    $service = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
    if ($service.Length -gt 0) {
        Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Uninstalling Existing version of Sysmon"
        Start-Process "Sysmon.exe" -ArgumentList "-u" -Wait
    }
    # Install Sysmon (32-bit)
    write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Installing Sysmon"
    Start-Process -FilePath "$env:temp\Sysmon.exe" -ArgumentList "-accepteula -i $sysmonConfOut" -Wait
}
Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Sysmon successfully installed"
Write-Host ""

if (-Not $sysmononly){

    # PowerShell logging registry changes
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling PowerShell scriptblock logging"
    $PSregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $PSregValName = "EnableScriptBlockLogging"
    $PSregValDat = 1

    if (-not (Test-Path $PSregPath)) {
        New-Item -Path $PSregPath -ItemType Directory -Force  | Out-Null
    }
    Set-ItemProperty -Path $PSregPath -Name $PSregValName -Value $PSregValDat -Type DWord  | Out-Null
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] PowerShell Script Block Logging enabled"

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling PowerShell module logging"
    $PSMregPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $PSMregValName = "EnableModuleLogging"
    $PSMregValDat = 1

    if (-not (Test-Path $PSMregPath)) {
        New-Item -Path $PSMregPath -ItemType Directory -Force  | Out-Null
    }
    Set-ItemProperty -Path $PSMregPath -Name $PSMregValName -Value $PSMregValDat -Type DWord  | Out-Null

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] PowerShell Module Logging enabled"

    # Applies defined policies in $auditSettings
    function ApplyPolicy {
        param (
            [Parameter(Mandatory)]
            [string]$subcategory,

            [Parameter(Mandatory)]
            [string]$success,

            [Parameter(Mandatory)]
            [string]$failure
        )

        $invokeAudit = "auditpol /set /subcategory:`"$subcategory`" /success:$success /failure:$failure"
        Invoke-Expression -Command $invokeAudit | Out-Null
    }

    # Used to enable CommandLine w/4688
    function ProcStartCMD {
        $cmdRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        $cmdRegValue = "ProcessCreationIncludeCmdLine_Enabled"
        $cmdRegData = 1

        if (-not (Test-Path $cmdRegPath)) {
            New-Item -Path $cmdRegPath -ItemType Directory -Force
        }
        Set-ItemProperty -Path $cmdRegPath -Name $cmdRegValue -Value $cmdRegData -Type DWord
    }

    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Configuring Audit Policies"

    # Policy settings
    $auditSettings = @{

        # Account Logon
        "Credential Validation" =                    @{ Success="enable"; Failure="enable" }
        "Kerberos Authentication Service" =          @{ Success="enable"; Failure="enable" }
        "Kerberos Service Ticket Operations" =       @{ Success="enable"; Failure="enable" }
        "Other Account Logon Events" =               @{ Success="enable"; Failure="enable" }

        # Account Management
        "Application Group Management" =             @{ Success="enable"; Failure="enable" }
        "Computer Account Management" =              @{ Success="enable"; Failure="enable" }
        "Distribution Group Management" =            @{ Success="enable"; Failure="enable" }
        "Other Account Management Events" =          @{ Success="enable"; Failure="enable" }
        "Security Group Management" =                @{ Success="enable"; Failure="enable" }
        "User Account Management" =                  @{ Success="enable"; Failure="enable" }

        # Detailed Tracking
        "DPAPI Activity" =                           @{ Success="enable"; Failure="enable" }
        "Plug and Play Events" =                     @{ Success="enable"; Failure="disable"}
        "Process Creation" =                         @{ Success="enable"; Failure="enable" }
        "Process Termination" =                      @{ Success="enable"; Failure="enable" }
        "RPC Events" =                               @{ Success="enable"; Failure="enable" }

        # DS Access
        "Detailed Directory Service Replication" =   @{ Success="disable"; Failure="disable"}
        "Directory Service Access" =                 @{ Success="enable"; Failure="enable" }
        "Directory Service Changes" =                @{ Success="enable"; Failure="enable" }
        "Directory Service Replication" =            @{ Success="enable"; Failure="enable" }

        # Logon/Logoff
        "Account Lockout" =                          @{ Success="enable"; Failure="enable" }
        "User / Device Claims" =                     @{ Success="enable"; Failure="enable" }
        "Group Membership" =                         @{ Success="enable"; Failure="enable" }
        "IPsec Extended Mode" =                      @{ Success="disable"; Failure="disable"}
        "IPsec Main Mode" =                          @{ Success="disable"; Failure="disable"}
        "IPsec Quick Mode" =                         @{ Success="disable"; Failure="disable"}
        "Logoff" =                                   @{ Success="enable"; Failure="enable" }
        "Logon" =                                    @{ Success="enable"; Failure="enable" }
        "Network Policy Server" =                    @{ Success="disable"; Failure="disable"}
        "Other Logon/Logoff Events" =                @{ Success="enable"; Failure="enable" }
        "Special Logon" =                            @{ Success="disable"; Failure="disable"}

        # Object Access
        "Application Generated" =                    @{ Success="enable"; Failure="enable" }
        "Certification Services" =                   @{ Success="enable"; Failure="enable" }
        "Detailed File Share" =                      @{ Success="enable"; Failure="enable" }
        "File Share" =                               @{ Success="enable"; Failure="enable" }
        "File System" =                              @{ Success="enable"; Failure="enable" }
        "Filtering Platform Connection" =            @{ Success="enable"; Failure="enable" }
        "Filtering Platform Packet Drop" =           @{ Success="enable"; Failure="enable" }
        "Handle Manipulation" =                      @{ Success="enable"; Failure="enable" }
        "Kernel Object" =                            @{ Success="enable"; Failure="enable" }
        "Other Object Access Events" =               @{ Success="enable"; Failure="enable"}
        "Registry" =                                 @{ Success="enable"; Failure="enable" }
        "SAM" =                                      @{ Success="disable"; Failure="disable"}

        # Policy Change
        "Audit Policy Change" =                      @{ Success="enable"; Failure="enable" }
        "Authentication Policy Change" =             @{ Success="enable"; Failure="enable" }
        "Authorization Policy Change" =              @{ Success="enable"; Failure="enable" }
        "Filtering Platform Policy Change" =         @{ Success="enable"; Failure="enable" }
        "MPSSVC Rule-Level Policy Change" =          @{ Success="disable"; Failure="disable"}
        "Other Policy Change Events" =               @{ Success="disable"; Failure="disable"}

        # Privilege Use
        "Non Sensitive Privilege Use" =              @{ Success="disable"; Failure="disable"}
        "Other Privilege Use Events" =               @{ Success="disable"; Failure="disable"}
        "Sensitive Privilege Use" =                  @{ Success="disable"; Failure="disable"}

        # System
        "IPsec Driver" =                             @{ Success="disable"; Failure="disable"}
        "Other System Events" =                      @{ Success="disable"; Failure="disable"}
        "Security State Change" =                    @{ Success="disable"; Failure="disable"}
        "Security System Extension" =                @{ Success="enable"; Failure="enable" }
        "System Integrity" =                         @{ Success="enable"; Failure="enable" }
    }

    # Apply each policy
    foreach ($policy in $auditSettings.Keys) {
        $settings = $auditSettings[$policy]
        ApplyPolicy -subcategory $policy -success $settings.Success -failure $settings.Failure
    }
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Audit Policies Configured"

    # Enable command line w/ Process Creation
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Enabling command line logging w/ EVID: 4688"
    ProcStartCMD
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Event ID 4688 enabled with commandline"
    
    # Upate GPOs using gpupdate
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Updating GPOs using gpupdate"
    Invoke-Expression -Command "gpupdate /force" | Out-Null

    # Clean Up
    Write-Host "[ " -nonewline; Write-Host $cm -f green -nonewline; Write-Host " ] Cleaning up"
    Remove-Item $sysmonOut,$sysmonConfOut,$env:temp\Sysmon.exe,$env:temp\sysmon64.exe,$env:temp\sysmon64a.exe
};
Write-Host -f green "`nDone!"
