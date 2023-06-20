# Enable All The Logs!
![example image](https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_all_the_logs.png?raw=true) 
This script is designed to be used in lab environments (or production if you are careful) where logging is critical for building detections or malware analysis. This can be used in production, however you might want to tune the GPO edits as needed. This was mostly designed to save time when spinning up new hosts in a lab environment. 

Tested on Windows Server 2019/2022 and Windows 10/11

This script performs the following actions:
* Downloads Sysmon from: https://download.sysinternals.com/files/Sysmon.zip
* Downloads Sysmon config import file from: https://raw.githubusercontent.com/bobby-tablez/FT-Sysmon-Config/master/ft-sysmonconfig-export.xml
* Enables PowerShell script block logging (EVID 4104)
* Ebables PowerShell module logging (EVID 4103)
* Enables event ID 4688
* Enables command line logging into Process Start events (EVID 4688)
* Enables GPO audit policies based on https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=RecBaselineAudPol

### Usage

The ` -sysmononly` parameter can be passed into the script if your goal is to only download and install Sysmon. Otherwise, running the script without any parameters will install Sysmon, enable PowerShell script block/module logging and make GPO changes.

The ` -y` parameter can also be used to skip the prompt message.

### Quick 'n easy:
```powershell
iex(iwr https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_logs.ps1 -UseBasicParsing)
```
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

Disclaimer: Feel free to fork and use at your own risk!
