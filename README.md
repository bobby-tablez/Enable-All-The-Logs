# Enable All The Logs!
![enable_all_the_logs_banner](https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_all_the_logs.png?raw=true) 
This script automates enhancing logging telemetry on Windows hosts. It is designed specifically with threat detection in mind where logging is critical for detections in SIEM environments or in a lab setting for emulation, validation or for malware analysis. This can be used in production, however you may want to fork or clone the script to tune the GPO edits as needed as it will increase log volume significantly. 

Tested on Windows Server 2019/2022 and Windows 10/11

This script performs the following actions:
* Downloads Sysmon from: https://download.sysinternals.com/files/Sysmon.zip
* Downloads Sysmon config import file from: https://raw.githubusercontent.com/bobby-tablez/FT-Sysmon-Config/master/ft-sysmonconfig-export.xml
* Installs Sysmon (reinstalls if already present)
* Enables PowerShell script block logging (EVID 4104)
* Ebables PowerShell module logging (EVID 4103)
* Enables event ID 4688
* Enables command line logging into Process Start events (EVID 4688)
* Enables GPO audit policies based on https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=RecBaselineAudPol
* Updates GPOs
* Cleans up temporary downloaded files

### Usage

The ` -sysmononly` argument can be passed into the script if your goal is to only download and install Sysmon. Otherwise, running the script without any parameters will install Sysmon, enable PowerShell script block/module logging and make GPO changes.

The ` -y` argument can also be used to skip the prompt message.

The ` -config` argument is used to supply your own Sysmon XML config file, rather than the default mentioned above.

### Execute via PowerShell:
```powershell
irm https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_logs.ps1|iex
```
![enable_all_the_logs_run](https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_all_the_logs_run.png?raw=true) 

### Script to check for Sysmon install. Deploy it if not present:
```powershell
#Requires -RunAsAdministrator
$sysmonProc = Get-Process -Name  Sysmon* -ErrorAction SilentlyContinue

if ($sysmonProc) {
    Write-Host "Sysmon is already installed! Quitting..."
    Start-Sleep -Seconds 2
} else {
    $Url = "https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_logs.ps1"
    $script = "$env:TMP\enable_logs.ps1"
    
    Invoke-WebRequest -Uri $Url -OutFile $script -UseBasicParsing
    $run = "$script -sysmononly -y"
    Invoke-Expression $run

    Start-Sleep -Seconds 2
    Remove-Item $script
}
```
Additional reference: https://www.securonix.com/blog/improving-blue-team-threat-detection-with-enhanced-siem-telemetry/

### Disclaimer: Feel free to fork and use at your own risk!
