# Complete Lateral Movement & Mimikatz Investigation Script
# Detects WinRM lateral movement, Mimikatz execution, credential dumping, and SAM database access
# All timestamps are displayed in UTC

param(
    [int]$HoursBack = 24,
    [string]$OutputPath = "C:\Complete_Investigation.html"
)

Write-Host "[*] Starting Complete Threat Investigation..." -ForegroundColor Cyan
Write-Host "[*] Analyzing last $HoursBack hours of logs..." -ForegroundColor Cyan
Write-Host "[*] All timestamps are in UTC" -ForegroundColor Gray

$startTime = (Get-Date).AddHours(-$HoursBack)
$findings = @()

# Get the current script name dynamically to exclude self-detection
$scriptName = if ($PSCommandPath) { 
    [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
} elseif ($MyInvocation.MyCommand.Name) {
    [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
} else {
    "lateral-Detector"  # Fallback default
}
Write-Host "[*] Script self-exclusion filter: $scriptName" -ForegroundColor Gray

# Helper function to get UTC timestamp from event
function Get-EventTimeUTC {
    param($Event)
    return $Event.TimeCreated.ToUniversalTime()
}

function New-Finding {
    param($Category, $Severity, $Time, $Description, $EventID, $Source, $Details, $RawLog = "")
    [PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Timestamp = $Time
        Description = $Description
        EventID = $EventID
        Source = $Source
        Details = $Details
        RawLog = $RawLog
    }
}

# Statistics
$stats = @{
    MimikatzExecutions = 0
    LSASSAccess = 0
    SAMAccess = 0
    CredentialDumping = 0
    PassTheHash = 0
    WinRMConnections = 0
    RemoteLogons = 0
    PSSessionCreations = 0
    FileTransfers = 0
    SuspiciousCommands = 0
}

Write-Host "`n[PHASE 1: MIMIKATZ DETECTION]" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Gray

Write-Host "`n[1/32] Detecting Mimikatz process execution..." -ForegroundColor Yellow

# Sysmon Event 1 - Mimikatz Process Creation (handles renamed executables)
try {
    $mimikatzProcs = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
        StartTime = $startTime
    } -MaxEvents 2000 -ErrorAction SilentlyContinue
    
    if ($mimikatzProcs) {
        foreach ($event in $mimikatzProcs) {
            $msg = $event.Message
            
            # Extract all relevant fields
            $image = if ($msg -match "Image:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
            $commandLine = if ($msg -match "CommandLine:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            $user = if ($msg -match "User:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
            $originalFileName = if ($msg -match "OriginalFileName:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            $description = if ($msg -match "Description:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            $product = if ($msg -match "Product:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            $company = if ($msg -match "Company:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            
            $imageFileName = [System.IO.Path]::GetFileName($image).ToLower()
            $isMimikatz = $false
            $detectionReason = ""
            
            # Detection Method 1: OriginalFileName contains mimikatz
            if ($originalFileName -match "mimikatz|mimilib|mimidrv") {
                $isMimikatz = $true
                $detectionReason = "OriginalFileName: $originalFileName"
            }
            # Detection Method 2: Description/Product contains mimikatz indicators
            elseif ($description -match "mimikatz|mimilib|mimidrv|gentilkiwi" -or $product -match "mimikatz|mimilib") {
                $isMimikatz = $true
                $detectionReason = "PE Metadata: $description"
            }
            # Detection Method 3: Company is gentilkiwi (mimikatz author)
            elseif ($company -match "gentilkiwi") {
                $isMimikatz = $true
                $detectionReason = "Company: $company"
            }
            # Detection Method 4: Image name is mimikatz
            elseif ($imageFileName -match "mimikatz|mimilib|mimidrv") {
                $isMimikatz = $true
                $detectionReason = "ImageName: $imageFileName"
            }
            # Detection Method 5: Command line contains mimikatz commands
            elseif ($commandLine -match "sekurlsa::|lsadump::|kerberos::|crypto::|dpapi::|token::|privilege::debug|vault::|misc::|Invoke-Mimikatz") {
                $isMimikatz = $true
                $detectionReason = "CommandLine contains mimikatz commands"
            }
            
            if ($isMimikatz) {
                $stats.MimikatzExecutions++
                
                # Check if renamed
                $wasRenamed = $originalFileName -and ($originalFileName -match "mimikatz") -and ($imageFileName -notmatch "mimikatz")
                $desc = if ($wasRenamed) { 
                    "RENAMED Mimikatz (was: $originalFileName, now: $imageFileName)" 
                } else { 
                    "Mimikatz detected: $imageFileName" 
                }
                
                $findings += New-Finding -Category "Mimikatz Execution" -Severity "CRITICAL" `
                    -Time (Get-EventTimeUTC $event) -Description $desc `
                    -EventID "1" -Source "Sysmon" `
                    -Details "User: $user | Detection: $detectionReason | CMD: $commandLine" `
                    -RawLog $event.Message
                
                Write-Host "  [!] CRITICAL: $desc by $user at $((Get-EventTimeUTC $event))" -ForegroundColor Red
            }
        }
    }
    
    if ($stats.MimikatzExecutions -eq 0) {
        Write-Host "  [-] No Mimikatz process events found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [-] Error checking Sysmon: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host "`n[2/32] Detecting LSASS memory access (Credential Dumping)..." -ForegroundColor Yellow

# Sysmon Event 10 - LSASS Access
try {
    $lsassAccess = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 10
        StartTime = $startTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "TargetImage:.*lsass\.exe"
    }
    
    if ($lsassAccess) {
        $stats.LSASSAccess = $lsassAccess.Count
        
        foreach ($event in $lsassAccess) {
            $msg = $event.Message
            $sourceImage = if ($msg -match "SourceImage:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
            $grantedAccess = if ($msg -match "GrantedAccess:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
            
            # Whitelist legitimate processes that access LSASS
            $isLegitimate = $sourceImage -match "\\(svchost\.exe|csrss\.exe|wininit\.exe|services\.exe|lsass\.exe|MsMpEng\.exe|NisSrv\.exe|Sysmon\.exe|Sysmon64\.exe|WmiPrvSE\.exe|taskhostw\.exe|SecurityHealthService\.exe|SgrmBroker\.exe|vmtoolsd\.exe|vm3dservice\.exe)$"
            
            if (-not $isLegitimate) {
                $severity = if ($sourceImage -match "mimikatz|powershell|cmd|procdump|rundll32") { "CRITICAL" } else { "HIGH" }
                $stats.CredentialDumping++
                
                $findings += New-Finding -Category "LSASS Access" -Severity $severity `
                    -Time (Get-EventTimeUTC $event) -Description "Suspicious LSASS memory access" `
                    -EventID "10" -Source "Sysmon" `
                    -Details "Source: $sourceImage | Access: $grantedAccess" `
                    -RawLog $event.Message
                
                Write-Host "  [!] $severity : LSASS accessed by $sourceImage at $((Get-EventTimeUTC $event))" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  [-] No LSASS access events found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [-] Error checking LSASS access: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host "`n[3/32] Detecting SAM database access..." -ForegroundColor Yellow

# SAM Registry Access - Sysmon Event 12, 13 (limited for performance)
try {
    $samAccess = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 12,13
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "SAM\\SAM\\Domains\\Account\\Users|SECURITY\\Policy\\Secrets"
    }
    
    if ($samAccess) {
        $stats.SAMAccess = $samAccess.Count
        
        foreach ($event in $samAccess) {
            $msg = $event.Message -split "`n"
            $imageLine = $msg | Select-String "^Image:" | Select-Object -First 1
            $image = if ($imageLine -match "Image:\s*(.+)$") { $matches[1].Trim() } else { "Unknown" }
            $targetLine = $msg | Select-String "^TargetObject:" | Select-Object -First 1
            $targetObject = if ($targetLine -match "TargetObject:\s*(.+)$") { $matches[1].Trim() } else { "Unknown" }
            
            if ($image -notmatch "services\.exe|svchost\.exe|lsass\.exe|System") {
                $stats.CredentialDumping++
                
                $findings += New-Finding -Category "SAM Database Access" -Severity "CRITICAL" `
                    -Time (Get-EventTimeUTC $event) -Description "SAM registry access detected" `
                    -EventID "$($event.Id)" -Source "Sysmon" `
                    -Details "Process: $image | Target: $targetObject" `
                    -RawLog $event.Message
                
                Write-Host "  [!] CRITICAL: SAM accessed by $image at $((Get-EventTimeUTC $event))" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "  [-] No SAM access events" -ForegroundColor Gray
}

Write-Host "`n[4/32] Detecting SAM/SYSTEM file copying..." -ForegroundColor Yellow

# File Access - Sysmon Event 11
try {
    $samFileAccess = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 11
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {
        $_.Message -match "\\System32\\config\\SAM|\\System32\\config\\SYSTEM|\\System32\\config\\SECURITY|ntds.dit"
    }
    
    foreach ($event in $samFileAccess) {
        $msg = $event.Message -split "`n"
        $image = ($msg | Select-String "Image:").ToString().Split(":")[-1].Trim()
        $targetFilename = ($msg | Select-String "TargetFilename:").ToString().Split(":")[-1].Trim()
        
        if ($image -notmatch "services.exe|svchost.exe|System") {
            $findings += New-Finding -Category "SAM File Copy" -Severity "CRITICAL" `
                -Time (Get-EventTimeUTC $event) -Description "SAM/SYSTEM file copied" `
                -EventID "11" -Source "Sysmon" `
                -Details "Process: $image | File: $targetFilename" `
                -RawLog $event.Message
            
            Write-Host "  [!] CRITICAL: SAM file copied by $image at $((Get-EventTimeUTC $event))" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "  [-] No SAM file access events" -ForegroundColor Gray
}

Write-Host "`n[5/32] Detecting credential dumping via PowerShell..." -ForegroundColor Yellow

# PowerShell Mimikatz/Credential Dumping patterns
$psMimikatzPatterns = @(
    "Invoke-Mimikatz",
    "sekurlsa::",
    "lsadump::",
    "kerberos::",
    "crypto::",
    "dpapi::",
    "Get-GPPPassword",
    "DumpCreds",
    "DumpCerts",
    "logonpasswords",
    "privilege::debug",
    "token::elevate",
    "vault::cred",
    "dcsync",
    "Out-Minidump",
    "comsvcs\.dll.*MiniDump",
    "procdump.*lsass",
    "rundll32.*comsvcs",
    "Get-Process.*lsass",
    "ReadProcessMemory.*lsass"
) -join "|"

# PowerShell Script Block Logging
try {
    $psCredDump = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        ID = 4104
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {
        $_.Message -match $psMimikatzPatterns -and
        $_.Message -notmatch [regex]::Escape($scriptName)
    }
    
    foreach ($event in $psCredDump) {
        $scriptBlock = if ($event.Message -match "ScriptBlockText = (.+)") {
            $matches[1].Substring(0, [Math]::Min(200, $matches[1].Length))
        } else {
            "PowerShell credential dumping detected"
        }
        
        $findings += New-Finding -Category "PowerShell Credential Dump" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Credential dumping via PowerShell" `
            -EventID "4104" -Source "PowerShell" `
            -Details $scriptBlock `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: PowerShell credential dumping at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No PowerShell credential dumping detected" -ForegroundColor Gray
}

Write-Host "`n[PHASE 2: PASS-THE-HASH DETECTION]" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Gray

Write-Host "`n[6/32] Detecting Pass-the-Hash (Logon Type 9)..." -ForegroundColor Yellow

# Event 4624 - Logon Type 9
try {
    $pthLogons = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4624
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {
        $_.Properties[8].Value -eq 9
    }
    
    $stats.PassTheHash = $pthLogons.Count
    
    foreach ($event in $pthLogons) {
        $user = $event.Properties[5].Value
        $domain = $event.Properties[6].Value
        $authPkg = $event.Properties[10].Value
        
        $findings += New-Finding -Category "Pass-the-Hash" -Severity "HIGH" `
            -Time (Get-EventTimeUTC $event) -Description "Logon Type 9 (NewCredentials)" `
            -EventID "4624" -Source "Security" `
            -Details "User: $domain\$user | Auth: $authPkg" `
            -RawLog $event.Message
        
        Write-Host "  [!] HIGH: Pass-the-Hash indicator - $domain\$user at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No Logon Type 9 events" -ForegroundColor Gray
}

Write-Host "`n[7/32] Detecting explicit credential usage..." -ForegroundColor Yellow

# Event 4648
try {
    $explicitCreds = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4648
        StartTime = $startTime
    } -ErrorAction Stop
    
    foreach ($event in $explicitCreds) {
        $account = $event.Properties[5].Value
        $targetServer = $event.Properties[8].Value
        $process = $event.Properties[11].Value
        
        # Exclude legitimate processes and accounts
        $isLegitProcess = $process -match "\\consent\.exe$|\\svchost\.exe$|\\lsass\.exe$|\\services\.exe$"
        $isLegitAccount = $account -match "^DWM-\d+$|^UMFD-\d+$|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$"
        
        if ($isLegitProcess -or $isLegitAccount) {
            continue
        }
        
        $severity = if ($process -match "mimikatz|wsmprovhost") { "HIGH" } else { "MEDIUM" }
        
        $findings += New-Finding -Category "Explicit Credentials" -Severity $severity `
            -Time (Get-EventTimeUTC $event) -Description "Explicit credential usage" `
            -EventID "4648" -Source "Security" `
            -Details "Account: $account | Target: $targetServer | Process: $process" `
            -RawLog $event.Message
        
        Write-Host "  [!] $severity : Explicit creds - $account to $targetServer at $((Get-EventTimeUTC $event))" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] No explicit credential events" -ForegroundColor Gray
}

Write-Host "`n[8/32] Detecting SeDebugPrivilege usage..." -ForegroundColor Yellow

# Event 4672 - Special privileges assigned
try {
    $specialPrivs = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4672
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "SeDebugPrivilege"
    }
    
    foreach ($event in $specialPrivs) {
        $msg = $event.Message
        $account = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $domain = if ($msg -match "Account Domain:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        # Skip machine/service accounts (containing $) and Window Manager accounts (DWM-*, UMFD-*)
        if ($account -match "\$" -or $account -match "^(DWM-|UMFD-)") {
            continue
        }
        
        $findings += New-Finding -Category "Privilege Escalation" -Severity "HIGH" `
            -Time (Get-EventTimeUTC $event) -Description "SeDebugPrivilege assigned" `
            -EventID "4672" -Source "Security" `
            -Details "Account: $domain\$account" `
            -RawLog $event.Message
        
        Write-Host "  [!] HIGH: SeDebugPrivilege to $domain\$account at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No special privilege events" -ForegroundColor Gray
}

Write-Host "`n[PHASE 3: WINRM LATERAL MOVEMENT]" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Gray

Write-Host "`n[9/32] Detecting WinRM service activity..." -ForegroundColor Yellow

try {
    $winrmSessions = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-WinRM/Operational'
        ID = 6,33,91,142
        StartTime = $startTime
    } -ErrorAction Stop
    
    $stats.WinRMConnections = $winrmSessions.Count
    
    foreach ($event in $winrmSessions) {
        $eventMsg = switch ($event.Id) {
            6 { "WSMan session created" }
            33 { "Remote connection established" }
            91 { "WinRM client connecting" }
            142 { "WSMan operation completed" }
        }
        
        $findings += New-Finding -Category "WinRM Activity" -Severity "MEDIUM" `
            -Time (Get-EventTimeUTC $event) -Description $eventMsg `
            -EventID $event.Id -Source "WinRM Operational" `
            -Details $event.Message.Substring(0, [Math]::Min(150, $event.Message.Length)) `
            -RawLog $event.Message
        
        Write-Host "  [!] MEDIUM: $eventMsg at $((Get-EventTimeUTC $event))" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] WinRM Operational log not available" -ForegroundColor Gray
}

Write-Host "`n[10/32] Detecting remote logons..." -ForegroundColor Yellow

try {
    $remoteLogons = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4624
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {
        $_.Properties[8].Value -eq 3 -and
        $_.Properties[18].Value -notmatch "^(127\.|::1|fe80::|-)"
    }
    
    $stats.RemoteLogons = $remoteLogons.Count
    
    foreach ($event in $remoteLogons) {
        $user = $event.Properties[5].Value
        $sourceIP = $event.Properties[18].Value
        $logonProcess = $event.Properties[9].Value
        
        $severity = if ($logonProcess -match "NTLM") { "HIGH" } else { "MEDIUM" }
        
        $findings += New-Finding -Category "Remote Logon" -Severity $severity `
            -Time (Get-EventTimeUTC $event) -Description "Network logon from $sourceIP" `
            -EventID "4624" -Source "Security" `
            -Details "User: $user | Process: $logonProcess" `
            -RawLog $event.Message
        
        Write-Host "  [!] $severity : Remote logon - $user from $sourceIP at $((Get-EventTimeUTC $event))" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] No remote logon events" -ForegroundColor Gray
}

Write-Host "`n[11/32] Detecting wsmprovhost.exe processes..." -ForegroundColor Yellow

try {
    $wsmprovProcs = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {$_.Message -match "wsmprovhost.exe"}
    
    $stats.PSSessionCreations = $wsmprovProcs.Count
    
    foreach ($event in $wsmprovProcs) {
        $msg = $event.Message -split "`n"
        $userLine = $msg | Select-String "^User:" | Select-Object -First 1
        $user = if ($userLine) { $userLine.ToString().Split(":")[-1].Trim() } else { "Unknown" }
        
        $findings += New-Finding -Category "PS Remoting" -Severity "HIGH" `
            -Time (Get-EventTimeUTC $event) -Description "PowerShell remoting session" `
            -EventID "1" -Source "Sysmon" `
            -Details "User: $user" `
            -RawLog $event.Message
        
        Write-Host "  [!] HIGH: PS Remoting by $user at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No wsmprovhost processes" -ForegroundColor Gray
}

Write-Host "`n[12/32] Detecting WinRM network connections..." -ForegroundColor Yellow

try {
    $winrmNetwork = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 3
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {
        $_.Message -match ":5985|:5986" -or $_.Message -match "wsmprovhost.exe"
    }
    
    foreach ($event in $winrmNetwork) {
        $msg = $event.Message -split "`n"
        $image = ($msg | Select-String "Image:").ToString().Split(":")[-1].Trim()
        $destIP = ($msg | Select-String "DestinationIp:").ToString().Split(":")[-1].Trim()
        $destPort = ($msg | Select-String "DestinationPort:").ToString().Split(":")[-1].Trim()
        
        $findings += New-Finding -Category "WinRM Network" -Severity "MEDIUM" `
            -Time (Get-EventTimeUTC $event) -Description "WinRM network connection" `
            -EventID "3" -Source "Sysmon" `
            -Details "$image to $destIP`:$destPort" `
            -RawLog $event.Message
        
        Write-Host "  [!] MEDIUM: WinRM connection to $destIP`:$destPort at $((Get-EventTimeUTC $event))" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] No WinRM network connections" -ForegroundColor Gray
}

Write-Host "`n[13/32] Detecting remote PowerShell commands..." -ForegroundColor Yellow

try {
    $psRemoting = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        ID = 4103,4104
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {
        $_.Message -match "Enter-PSSession|Invoke-Command|New-PSSession|Copy-Item.*-ToSession|Copy-Item.*-FromSession" -and
        $_.Message -notmatch [regex]::Escape($scriptName)
    }
    
    $stats.SuspiciousCommands += $psRemoting.Count
    
    foreach ($event in $psRemoting) {
        $command = if ($event.Message -match "ScriptBlockText = (.+)") {
            $matches[1].Substring(0, [Math]::Min(150, $matches[1].Length))
        } else {
            "Remote PowerShell command"
        }
        
        $severity = if ($command -match "mimikatz|Copy-Item.*-ToSession|IEX|DownloadString") {
            "CRITICAL"
        } else {
            "HIGH"
        }
        
        $findings += New-Finding -Category "PS Remote Command" -Severity $severity `
            -Time (Get-EventTimeUTC $event) -Description "Remote PowerShell command" `
            -EventID $event.Id -Source "PowerShell" `
            -Details $command `
            -RawLog $event.Message
        
        Write-Host "  [!] $severity : Remote PS command at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No remote PowerShell commands" -ForegroundColor Gray
}

Write-Host "`n[14/32] Detecting file transfers via PSSession..." -ForegroundColor Yellow

try {
    $fileTransfers = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        ID = 4103,4104
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {
        $_.Message -match "Copy-Item.*(-ToSession|-FromSession)" -and
        $_.Message -notmatch [regex]::Escape($scriptName)
    }
    
    $stats.FileTransfers = $fileTransfers.Count
    
    foreach ($event in $fileTransfers) {
        $direction = if ($event.Message -match "-ToSession") { "Upload" } else { "Download" }
        
        $findings += New-Finding -Category "File Transfer" -Severity "HIGH" `
            -Time (Get-EventTimeUTC $event) -Description "File $direction via PSSession" `
            -EventID $event.Id -Source "PowerShell" `
            -Details $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length)) `
            -RawLog $event.Message
        
        Write-Host "  [!] HIGH: File $direction via PSSession at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No file transfer activity" -ForegroundColor Gray
}

Write-Host "`n[15/32] Detecting remote process access..." -ForegroundColor Yellow

try {
    $remoteProcAccess = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 10
        StartTime = $startTime
    } -ErrorAction Stop | Where-Object {
        $_.Message -match "wsmprovhost.exe|powershell.exe.*ServerRemoteHost" -and
        $_.Message -match "lsass.exe|services.exe|winlogon.exe"
    }
    
    foreach ($event in $remoteProcAccess) {
        $msg = $event.Message -split "`n"
        $sourceImage = ($msg | Select-String "SourceImage:").ToString().Split(":")[-1].Trim()
        $targetImage = ($msg | Select-String "TargetImage:").ToString().Split(":")[-1].Trim()
        
        $findings += New-Finding -Category "Remote Credential Access" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Remote session accessed $targetImage" `
            -EventID "10" -Source "Sysmon" `
            -Details "Source: $sourceImage" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: Remote session accessed $targetImage at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No remote process access" -ForegroundColor Gray
}

# ============================================
# NEW DETECTION CATEGORIES
# ============================================

Write-Host "`n[16/32] Detecting DPAPI activity (Master Key access)..." -ForegroundColor Yellow

try {
    # Event 4692 - DPAPI Master Key Backup
    $dpapiBackup = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4692
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    foreach ($event in $dpapiBackup) {
        $msg = $event.Message
        $subjectUser = if ($msg -match "Subject:.*?Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        $findings += New-Finding -Category "DPAPI Activity" -Severity "HIGH" `
            -Time (Get-EventTimeUTC $event) -Description "DPAPI Master Key backup attempted" `
            -EventID "4692" -Source "Security" `
            -Details "User: $subjectUser" `
            -RawLog $event.Message
        
        Write-Host "  [!] HIGH: DPAPI Master Key backup by $subjectUser at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
    
    # Event 4693 - DPAPI Master Key Recovery
    $dpapiRecovery = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4693
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    foreach ($event in $dpapiRecovery) {
        $msg = $event.Message
        $subjectUser = if ($msg -match "Subject:.*?Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $recoveryServer = if ($msg -match "Recovery Server:\s*(.+?)(?:\r|\n|$)") { $matches[1].Trim() } else { "Local" }
        
        $findings += New-Finding -Category "DPAPI Activity" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "DPAPI Master Key recovery" `
            -EventID "4693" -Source "Security" `
            -Details "User: $subjectUser | Recovery Server: $recoveryServer" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: DPAPI Master Key recovery by $subjectUser at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No DPAPI events" -ForegroundColor Gray
}

Write-Host "`n[17/32] Detecting Kerberos ticket attacks (Golden/Silver ticket)..." -ForegroundColor Yellow

try {
    # Event 4768 - Kerberos TGT Request (looking for anomalies)
    $kerbTGT = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4768
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        # Look for encryption downgrade (RC4 = 0x17 = 23) which is common in attacks
        $_.Message -match "Ticket Encryption Type:\s*(0x17|0x18|23|24)" -or
        # Or pre-authentication type 0 (no pre-auth) which is suspicious
        $_.Message -match "Pre-Authentication Type:\s*0[^\d]"
    }
    
    foreach ($event in $kerbTGT) {
        $msg = $event.Message
        $targetUser = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $clientIP = if ($msg -match "Client Address:\s*::ffff:(\d+\.\d+\.\d+\.\d+)") { $matches[1] } elseif ($msg -match "Client Address:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $encType = if ($msg -match "Ticket Encryption Type:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        $findings += New-Finding -Category "Kerberos Anomaly" -Severity "HIGH" `
            -Time (Get-EventTimeUTC $event) -Description "Suspicious Kerberos TGT request (weak encryption or no pre-auth)" `
            -EventID "4768" -Source "Security" `
            -Details "User: $targetUser | Client: $clientIP | Encryption: $encType" `
            -RawLog $event.Message
        
        Write-Host "  [!] HIGH: Suspicious Kerberos TGT for $targetUser from $clientIP at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
    
    # Event 4769 - Kerberos Service Ticket (TGS) - looking for suspicious patterns
    $kerbTGS = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4769
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        # RC4 encryption downgrade
        $_.Message -match "Ticket Encryption Type:\s*(0x17|0x18|23|24)"
    }
    
    foreach ($event in $kerbTGS) {
        $msg = $event.Message
        $targetUser = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $serviceName = if ($msg -match "Service Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $clientIP = if ($msg -match "Client Address:\s*::ffff:(\d+\.\d+\.\d+\.\d+)") { $matches[1] } elseif ($msg -match "Client Address:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        $findings += New-Finding -Category "Kerberos Anomaly" -Severity "MEDIUM" `
            -Time (Get-EventTimeUTC $event) -Description "Kerberos TGS with weak encryption (possible Kerberoasting)" `
            -EventID "4769" -Source "Security" `
            -Details "User: $targetUser | Service: $serviceName | Client: $clientIP" `
            -RawLog $event.Message
        
        Write-Host "  [!] MEDIUM: Weak encryption TGS for $serviceName by $targetUser at $((Get-EventTimeUTC $event))" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] No suspicious Kerberos events" -ForegroundColor Gray
}

Write-Host "`n[18/32] Detecting NTLM authentication (Pass-the-Hash indicators)..." -ForegroundColor Yellow

try {
    # Event 4776 - NTLM credential validation
    $ntlmAuth = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4776
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        # Failed NTLM auth or from suspicious workstations
        $_.Message -match "Error Code:\s*0x[^0]" -or  # Non-zero error codes
        $_.Message -match "Source Workstation:\s*$" -or  # Empty workstation (common in PtH)
        $_.Message -notmatch "Source Workstation:\s*\S+"  # Missing workstation
    }
    
    foreach ($event in $ntlmAuth) {
        $msg = $event.Message
        $logonAccount = if ($msg -match "Logon Account:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $sourceWorkstation = if ($msg -match "Source Workstation:\s*(\S+)") { $matches[1] } else { "Empty/Unknown" }
        $errorCode = if ($msg -match "Error Code:\s*(\S+)") { $matches[1] } else { "0x0" }
        
        $severity = if ($errorCode -eq "0x0") { "MEDIUM" } else { "HIGH" }
        $description = if ($sourceWorkstation -eq "Empty/Unknown") { 
            "NTLM auth with missing workstation (PtH indicator)" 
        } else { 
            "NTLM authentication failure" 
        }
        
        $findings += New-Finding -Category "NTLM Authentication" -Severity $severity `
            -Time (Get-EventTimeUTC $event) -Description $description `
            -EventID "4776" -Source "Security" `
            -Details "Account: $logonAccount | Workstation: $sourceWorkstation | Error: $errorCode" `
            -RawLog $event.Message
        
        Write-Host "  [!] $severity`: NTLM auth for $logonAccount from $sourceWorkstation at $((Get-EventTimeUTC $event))" -ForegroundColor $(if ($severity -eq "HIGH") { "Red" } else { "Yellow" })
    }
} catch {
    Write-Host "  [-] No suspicious NTLM events" -ForegroundColor Gray
}

Write-Host "`n[19/32] Detecting DCSync attacks (Directory Replication)..." -ForegroundColor Yellow

try {
    $dcsyncFound = $false
    
    # Get the local computer name to exclude if this is a DC
    $localComputerName = $env:COMPUTERNAME
    $localComputerAccount = "$localComputerName$"
    
    # Get list of all Domain Controllers in the domain
    $domainControllers = @()
    try {
        # Method 1: Try to get DCs from AD
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainControllers = $domain.DomainControllers | ForEach-Object { $_.Name.Split('.')[0] + "$" }
        Write-Host "  [*] Found $($domainControllers.Count) Domain Controllers in domain" -ForegroundColor Gray
    } catch {
        # Method 2: Fallback - at minimum exclude local computer if it's a DC
        try {
            $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
            if ($isDC) {
                $domainControllers = @($localComputerAccount)
                Write-Host "  [*] Running on DC: $localComputerName" -ForegroundColor Gray
            }
        } catch {
            # Method 3: Last resort - just use local computer name
            $domainControllers = @($localComputerAccount)
        }
    }
    
    # Create regex pattern for all DC accounts
    $dcAccountPattern = ($domainControllers | ForEach-Object { [regex]::Escape($_) }) -join "|"
    if (-not $dcAccountPattern) { $dcAccountPattern = "^$" }  # Match nothing if empty
    
    # Method 1: Sysmon Event 1 - lsadump::dcsync command
    $dcsyncCmdEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
        StartTime = $startTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "lsadump::dcsync|dcsync|lsadump::lsa\s*/patch"
    }
    
    foreach ($event in $dcsyncCmdEvents) {
        $msg = $event.Message
        $user = if ($msg -match "User:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
        $cmdLine = if ($msg -match "CommandLine:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
        
        $findings += New-Finding -Category "DCSync Attack" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "DCSync command detected" `
            -EventID "1" -Source "Sysmon" `
            -Details "User: $user | CMD: $cmdLine" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: DCSync command by $user at $((Get-EventTimeUTC $event))" -ForegroundColor Red
        $dcsyncFound = $true
    }
    
    # Method 2: Event 4662 - Directory replication (on DC)
    $dcsyncEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4662
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c"
    }
    
    foreach ($event in $dcsyncEvents) {
        $msg = $event.Message
        $subjectUser = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $subjectDomain = if ($msg -match "Account Domain:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        # Skip Domain Controller computer accounts (legitimate replication)
        if ($subjectUser -match "^($dcAccountPattern)$") {
            continue
        }
        
        # Also skip any machine account ending with $ that contains DC naming patterns
        if ($subjectUser -match "\$$" -and $subjectUser -match "DC\d*\$|PDC|BDC|PSYCHDC") {
            continue
        }
        
        $findings += New-Finding -Category "DCSync Attack" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "DCSync - Directory replication by non-DC account" `
            -EventID "4662" -Source "Security" `
            -Details "User: $subjectDomain\$subjectUser" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: DCSync attack by $subjectDomain\$subjectUser at $((Get-EventTimeUTC $event))" -ForegroundColor Red
        $dcsyncFound = $true
    }
    
    if (-not $dcsyncFound) {
        Write-Host "  [-] No DCSync events found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [-] Error checking DCSync: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host "`n[20/32] Detecting Process Injection (CreateRemoteThread)..." -ForegroundColor Yellow

try {
    # Sysmon Event 8 - CreateRemoteThread
    $remoteThreadEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 8
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        # Exclude common legitimate remote thread creators
        $_.Message -notmatch "SourceImage:.*\\(csrss\.exe|wininit\.exe|services\.exe|svchost\.exe|MsMpEng\.exe|NisSrv\.exe)"
    }
    
    foreach ($event in $remoteThreadEvents) {
        $msg = $event.Message -split "`n"
        $sourceImage = ($msg | Select-String "^SourceImage:" | Select-Object -First 1)
        $sourceImage = if ($sourceImage -match "SourceImage:\s*(.+)$") { $matches[1].Trim() } else { "Unknown" }
        $targetImage = ($msg | Select-String "^TargetImage:" | Select-Object -First 1)
        $targetImage = if ($targetImage -match "TargetImage:\s*(.+)$") { $matches[1].Trim() } else { "Unknown" }
        
        # Skip VirtualBox VBoxTray.exe injecting into csrss.exe (legitimate behavior)
        if ($sourceImage -match "\\VBoxTray\.exe$" -and $targetImage -match "\\csrss\.exe$") {
            continue
        }
        
        $severity = if ($targetImage -match "lsass\.exe") { "CRITICAL" } else { "HIGH" }
        
        $findings += New-Finding -Category "Process Injection" -Severity $severity `
            -Time (Get-EventTimeUTC $event) -Description "CreateRemoteThread into $($targetImage.Split('\')[-1])" `
            -EventID "8" -Source "Sysmon" `
            -Details "Source: $sourceImage | Target: $targetImage" `
            -RawLog $event.Message
        
        Write-Host "  [!] $severity`: Remote thread from $($sourceImage.Split('\')[-1]) into $($targetImage.Split('\')[-1]) at $((Get-EventTimeUTC $event))" -ForegroundColor $(if ($severity -eq "CRITICAL") { "Red" } else { "Red" })
    }
} catch {
    Write-Host "  [-] No CreateRemoteThread events" -ForegroundColor Gray
}

Write-Host "`n[21/32] Detecting Process Tampering..." -ForegroundColor Yellow

try {
    # Sysmon Event 25 - Process Tampering
    $processTamperEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 25
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    foreach ($event in $processTamperEvents) {
        $msg = $event.Message -split "`n"
        $image = ($msg | Select-String "^Image:" | Select-Object -First 1)
        $image = if ($image -match "Image:\s*(.+)$") { $matches[1].Trim() } else { "Unknown" }
        $type = ($msg | Select-String "^Type:" | Select-Object -First 1)
        $type = if ($type -match "Type:\s*(.+)$") { $matches[1].Trim() } else { "Unknown" }
        
        $findings += New-Finding -Category "Process Tampering" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Process tampering detected: $type" `
            -EventID "25" -Source "Sysmon" `
            -Details "Image: $image | Type: $type" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: Process tampering ($type) on $($image.Split('\')[-1]) at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No process tampering events" -ForegroundColor Gray
}

Write-Host "`n[22/32] Detecting Security Log Cleared..." -ForegroundColor Yellow

try {
    # Event 1102 - Security log cleared
    $logClearedEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 1102
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    foreach ($event in $logClearedEvents) {
        $msg = $event.Message
        $subjectUser = if ($msg -match "Subject:.*?Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $subjectDomain = if ($msg -match "Subject:.*?Account Domain:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        $findings += New-Finding -Category "Log Cleared" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Security event log was cleared" `
            -EventID "1102" -Source "Security" `
            -Details "Cleared by: $subjectDomain\$subjectUser" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: Security log cleared by $subjectDomain\$subjectUser at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
    
    # Also check System log for event log service events
    $sysLogClearedEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ID = 104
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "Security|Microsoft-Windows-Sysmon"
    }
    
    foreach ($event in $sysLogClearedEvents) {
        $msg = $event.Message
        $logName = if ($msg -match "(.+?) log") { $matches[1] } else { "Unknown" }
        
        $findings += New-Finding -Category "Log Cleared" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "$logName log was cleared" `
            -EventID "104" -Source "System" `
            -Details "Log: $logName" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: $logName log cleared at $((Get-EventTimeUTC $event))" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No log clearing events" -ForegroundColor Gray
}

# ============================================
# RUBEUS & ADVANCED KERBEROS ATTACK DETECTIONS
# ============================================

Write-Host "`n[23/32] Detecting Rubeus Execution..." -ForegroundColor Yellow

try {
    $rubeusFound = $false
    
    $rubeusEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
        StartTime = $startTime
    } -MaxEvents 2000 -ErrorAction SilentlyContinue
    
    if ($rubeusEvents) {
        foreach ($event in $rubeusEvents) {
            $msg = $event.Message
            
            # Extract all relevant fields
            $image = if ($msg -match "Image:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
            $commandLine = if ($msg -match "CommandLine:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            $user = if ($msg -match "User:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
            $originalFileName = if ($msg -match "OriginalFileName:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            $description = if ($msg -match "Description:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            $product = if ($msg -match "Product:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "" }
            
            $imageFileName = [System.IO.Path]::GetFileName($image).ToLower()
            
            # Skip legitimate Windows processes
            if ($image -match "\\(rdpclip|svchost|csrss|lsass|services|wininit|winlogon|explorer|taskhostw|RuntimeBroker|SearchHost|dllhost|conhost|cmd|powershell)\.exe$" -and $commandLine -notmatch "rubeus") {
                continue
            }
            
            $isRubeus = $false
            $detectionReason = ""
            
            # Detection Method 1: OriginalFileName contains Rubeus
            if ($originalFileName -match "^Rubeus\.exe$|^Rubeus$") {
                $isRubeus = $true
                $detectionReason = "OriginalFileName: $originalFileName"
            }
            # Detection Method 2: Description contains Rubeus
            elseif ($description -match "Rubeus" -or $product -match "Rubeus") {
                $isRubeus = $true
                $detectionReason = "PE Metadata: $description"
            }
            # Detection Method 3: Image name is Rubeus
            elseif ($imageFileName -match "^rubeus\.exe$|^rubeus$") {
                $isRubeus = $true
                $detectionReason = "ImageName: $imageFileName"
            }
            # Detection Method 4: Command line contains Rubeus or specific Rubeus commands
            elseif ($commandLine -match "rubeus|\.exe\s+(asktgt|asktgs|kerberoast|asreproast|s4u|golden|silver|ptt|harvest|triage|brute|dump|monitor|renew|describe)") {
                $isRubeus = $true
                $detectionReason = "CommandLine contains Rubeus commands"
            }
            
            if ($isRubeus) {
                # Determine attack type from command line
                $attackType = "Rubeus Execution"
                if ($commandLine -match "kerberoast") { $attackType = "Kerberoasting (Rubeus)" }
                elseif ($commandLine -match "asreproast") { $attackType = "AS-REP Roasting (Rubeus)" }
                elseif ($commandLine -match "asktgt") { $attackType = "TGT Request (Rubeus)" }
                elseif ($commandLine -match "asktgs") { $attackType = "TGS Request (Rubeus)" }
                elseif ($commandLine -match "s4u") { $attackType = "S4U Delegation Abuse (Rubeus)" }
                elseif ($commandLine -match "golden") { $attackType = "Golden Ticket (Rubeus)" }
                elseif ($commandLine -match "silver") { $attackType = "Silver Ticket (Rubeus)" }
                elseif ($commandLine -match "ptt") { $attackType = "Pass-the-Ticket (Rubeus)" }
                elseif ($commandLine -match "harvest|triage|dump") { $attackType = "Ticket Harvesting (Rubeus)" }
                elseif ($commandLine -match "brute") { $attackType = "Password Spraying (Rubeus)" }
                
                # Check if renamed
                $wasRenamed = $originalFileName -match "Rubeus" -and $imageFileName -notmatch "rubeus"
                $desc = if ($wasRenamed) { 
                    "RENAMED Rubeus (was: $originalFileName, now: $imageFileName)" 
                } else { 
                    "$attackType" 
                }
                
                $findings += New-Finding -Category $attackType -Severity "CRITICAL" `
                    -Time (Get-EventTimeUTC $event) -Description $desc `
                    -EventID "1" -Source "Sysmon" `
                    -Details "User: $user | Detection: $detectionReason | CMD: $commandLine" `
                -RawLog $event.Message
            
                Write-Host "  [!] CRITICAL: $desc by $user at $((Get-EventTimeUTC $event))" -ForegroundColor Red
                $rubeusFound = $true
            }
        }
    }
    
    if (-not $rubeusFound) {
        Write-Host "  [-] No Rubeus execution events" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [-] Error checking Rubeus: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host "`n[24/32] Detecting Kerberoasting (TGS-REQ with RC4)..." -ForegroundColor Yellow

try {
    $kerberoastEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4769
        StartTime = $startTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "Ticket Encryption Type:\s*(0x17|0x18|23|24)"
    }
    
    $kerberoastGrouped = $kerberoastEvents | Group-Object { 
        if ($_.Message -match "Client Address:\s*::ffff:(\d+\.\d+\.\d+\.\d+)") { $matches[1] }
        elseif ($_.Message -match "Client Address:\s*(\S+)") { $matches[1] }
        else { "Unknown" }
    } | Where-Object { $_.Count -ge 3 }
    
    foreach ($group in $kerberoastGrouped) {
        $sampleEvent = $group.Group[0]
        $clientIP = $group.Name
        $count = $group.Count
        
        $findings += New-Finding -Category "Kerberoasting" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $sampleEvent) -Description "Kerberoasting - $count TGS requests with RC4" `
            -EventID "4769" -Source "Security" `
            -Details "Client: $clientIP | Requests: $count" `
            -RawLog $sampleEvent.Message
        
        Write-Host "  [!] CRITICAL: Kerberoasting from $clientIP ($count requests)" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No Kerberoasting events" -ForegroundColor Gray
}

Write-Host "`n[25/32] Detecting AS-REP Roasting..." -ForegroundColor Yellow

try {
    $asrepEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4768
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "Pre-Authentication Type:\s*0[^\d]"
    }
    
    foreach ($event in $asrepEvents) {
        $msg = $event.Message
        $targetUser = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $clientIP = if ($msg -match "Client Address:\s*::ffff:(\d+\.\d+\.\d+\.\d+)") { $matches[1] } 
                    elseif ($msg -match "Client Address:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        $findings += New-Finding -Category "AS-REP Roasting" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "AS-REP Roasting - No Pre-Auth" `
            -EventID "4768" -Source "Security" `
            -Details "Target: $targetUser | Client: $clientIP" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: AS-REP Roasting targeting $targetUser from $clientIP" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No AS-REP Roasting events" -ForegroundColor Gray
}

Write-Host "`n[26/32] Detecting Golden Ticket indicators..." -ForegroundColor Yellow

try {
    $goldenFound = $false
    
    # Method 1: Sysmon - kerberos::golden command
    $goldenCmdEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
        StartTime = $startTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "kerberos::golden|golden.*ticket|/krbtgt:"
    }
    
    foreach ($event in $goldenCmdEvents) {
        $msg = $event.Message
        $user = if ($msg -match "User:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
        $cmdLine = if ($msg -match "CommandLine:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
        
        $findings += New-Finding -Category "Golden Ticket Attack" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Golden Ticket command detected" `
            -EventID "1" -Source "Sysmon" `
            -Details "User: $user | CMD: $cmdLine" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: Golden Ticket command by $user" -ForegroundColor Red
        $goldenFound = $true
    }
    
    # Method 2: Event 4768 - TGT with RC4 for admin (on DC)
    $goldenEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4768
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "Ticket Encryption Type:\s*(0x17|23)"
    }
    
    foreach ($event in $goldenEvents) {
        $msg = $event.Message
        $userName = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $clientIP = if ($msg -match "Client Address:\s*::ffff:(\d+\.\d+\.\d+\.\d+)") { $matches[1] }
                    elseif ($msg -match "Client Address:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        $findings += New-Finding -Category "Golden Ticket Suspected" -Severity "HIGH" `
            -Time (Get-EventTimeUTC $event) -Description "TGT with RC4 encryption (downgrade)" `
            -EventID "4768" -Source "Security" `
            -Details "User: $userName | Client: $clientIP" `
            -RawLog $event.Message
        
        Write-Host "  [!] HIGH: TGT with RC4 for $userName from $clientIP" -ForegroundColor Red
        $goldenFound = $true
    }
    
    if (-not $goldenFound) {
        Write-Host "  [-] No Golden Ticket events" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [-] Error checking Golden Ticket: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host "`n[27/32] Detecting Skeleton Key Attack..." -ForegroundColor Yellow

try {
    $skeletonEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "misc::skeleton|skeleton.*key"
    }
    
    foreach ($event in $skeletonEvents) {
        $msg = $event.Message -split "`n"
        $userMatch = $msg | Select-String "^User:" | Select-Object -First 1
        $user = if ($userMatch -and $userMatch.Line -match "^User:\s*(.+)$") { $matches[1].Trim() } else { "Unknown" }
        
        $findings += New-Finding -Category "Skeleton Key Attack" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Skeleton Key attack detected" `
            -EventID "1" -Source "Sysmon" `
            -Details "User: $user" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: Skeleton Key attack by $user" -ForegroundColor Red
    }
    
    # Check for mimidrv service
    $mimiDrvEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ID = 7045
        StartTime = $startTime
    } -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "mimidrv|mimikatz"
    }
    
    foreach ($event in $mimiDrvEvents) {
        $findings += New-Finding -Category "Skeleton Key Attack" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Mimikatz driver service installed" `
            -EventID "7045" -Source "System" `
            -Details "Service installation" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: Mimikatz driver installed" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No Skeleton Key events" -ForegroundColor Gray
}

Write-Host "`n[28/32] Detecting S4U Delegation Abuse..." -ForegroundColor Yellow

try {
    $s4uEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4769
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "Transited Services:\s*[^-\s\r\n]"
    }
    
    foreach ($event in $s4uEvents) {
        $msg = $event.Message
        $targetUser = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $serviceName = if ($msg -match "Service Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        $findings += New-Finding -Category "S4U Delegation Abuse" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "S4U delegation abuse detected" `
            -EventID "4769" -Source "Security" `
            -Details "User: $targetUser | Service: $serviceName" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: S4U abuse - $targetUser to $serviceName" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No S4U delegation events" -ForegroundColor Gray
}

Write-Host "`n[29/32] Detecting Mimikatz Credential Commands in Logs..." -ForegroundColor Yellow

try {
    $mimikatzCmdsFound = $false
    $mimikatzCmds = "sekurlsa::|lsadump::|kerberos::|token::|vault::|dpapi::|crypto::|misc::"
    
    # Method 1: Check Sysmon Event 1 for mimikatz commands in command line
    $sysmonCmdEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
        StartTime = $startTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match $mimikatzCmds
    }
    
    foreach ($event in $sysmonCmdEvents) {
        $msg = $event.Message
        $cmdLine = if ($msg -match "CommandLine:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
        $user = if ($msg -match "User:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
        $detectedCmd = if ($msg -match "(sekurlsa::\w+|lsadump::\w+|kerberos::\w+|token::\w+|vault::\w+|dpapi::\w+|misc::\w+)") { $matches[1] } else { "mimikatz command" }
        
        $category = "Mimikatz Command"
        if ($detectedCmd -match "sekurlsa::") { $category = "Credential Dumping (sekurlsa)" }
        elseif ($detectedCmd -match "lsadump::") { $category = "Credential Dumping (lsadump)" }
        elseif ($detectedCmd -match "kerberos::") { $category = "Kerberos Manipulation" }
        elseif ($detectedCmd -match "token::") { $category = "Token Manipulation" }
        
        $findings += New-Finding -Category $category -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Mimikatz: $detectedCmd" `
            -EventID "1" -Source "Sysmon" `
            -Details "User: $user | Command: $detectedCmd" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: $category - $detectedCmd by $user" -ForegroundColor Red
        $mimikatzCmdsFound = $true
    }
    
    # Method 2: Check PowerShell Script Block logs
    $psCmdEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        ID = 4104
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match $mimikatzCmds -and $_.Message -notmatch [regex]::Escape($scriptName)
    }
    
    foreach ($event in $psCmdEvents) {
        $msg = $event.Message
        $detectedCmd = if ($msg -match "(sekurlsa::\w+|lsadump::\w+|kerberos::\w+|token::\w+|vault::\w+|misc::\w+)") { $matches[1] } else { "Unknown" }
        
        $category = "Mimikatz Command"
        if ($detectedCmd -match "sekurlsa::") { $category = "Credential Dumping (sekurlsa)" }
        elseif ($detectedCmd -match "lsadump::") { $category = "Credential Dumping (lsadump)" }
        elseif ($detectedCmd -match "kerberos::") { $category = "Kerberos Manipulation" }
        elseif ($detectedCmd -match "token::") { $category = "Token Manipulation" }
        
        $findings += New-Finding -Category $category -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Mimikatz (PowerShell): $detectedCmd" `
            -EventID "4104" -Source "PowerShell" `
            -Details "Command: $detectedCmd" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: $category - $detectedCmd (PowerShell)" -ForegroundColor Red
        $mimikatzCmdsFound = $true
    }
    
    if (-not $mimikatzCmdsFound) {
        Write-Host "  [-] No Mimikatz command events" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [-] Error checking Mimikatz commands: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host "`n[30/32] Detecting Overpass-the-Hash (Type 9 Logon)..." -ForegroundColor Yellow

try {
    $opthEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4624
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "Logon Type:\s*9"
    }
    
    foreach ($event in $opthEvents) {
        $msg = $event.Message
        $targetUser = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $processName = if ($msg -match "Process Name:\s*(.+?)(?:\r|\n|$)") { $matches[1].Trim() } else { "Unknown" }
        
        if ($processName -match "\\(consent\.exe|svchost\.exe)$") { continue }
        
        $findings += New-Finding -Category "Overpass-the-Hash" -Severity "HIGH" `
            -Time (Get-EventTimeUTC $event) -Description "Overpass-the-Hash (Logon Type 9)" `
            -EventID "4624" -Source "Security" `
            -Details "User: $targetUser | Process: $processName" `
            -RawLog $event.Message
        
        Write-Host "  [!] HIGH: Overpass-the-Hash for $targetUser" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] No Overpass-the-Hash events" -ForegroundColor Gray
}

Write-Host "`n[31/32] Detecting Password Spraying..." -ForegroundColor Yellow

try {
    $sprayEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4771
        StartTime = $startTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue
    
    $sprayGrouped = $sprayEvents | Group-Object {
        if ($_.Message -match "Client Address:\s*::ffff:(\d+\.\d+\.\d+\.\d+)") { $matches[1] }
        elseif ($_.Message -match "Client Address:\s*(\S+)") { $matches[1] }
        else { "Unknown" }
    } | Where-Object { $_.Count -ge 5 }
    
    foreach ($group in $sprayGrouped) {
        $sampleEvent = $group.Group[0]
        $clientIP = $group.Name
        $failCount = $group.Count
        $targetAccounts = ($group.Group | ForEach-Object {
            if ($_.Message -match "Account Name:\s*(\S+)") { $matches[1] }
        } | Select-Object -Unique).Count
        
        if ($targetAccounts -ge 3) {
            $findings += New-Finding -Category "Password Spraying" -Severity "HIGH" `
                -Time (Get-EventTimeUTC $sampleEvent) -Description "Password spraying - $failCount failures to $targetAccounts accounts" `
                -EventID "4771" -Source "Security" `
                -Details "Source: $clientIP | Failures: $failCount | Targets: $targetAccounts" `
                -RawLog $sampleEvent.Message
            
            Write-Host "  [!] HIGH: Password spraying from $clientIP ($failCount failures)" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "  [-] No Password Spraying events" -ForegroundColor Gray
}

Write-Host "`n[32/32] Detecting Pass-the-Ticket patterns..." -ForegroundColor Yellow

try {
    $pttFound = $false
    
    # Method 1: Sysmon - kerberos::ptt command
    $pttCmdEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
        StartTime = $startTime
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "kerberos::ptt|ptt\s|/ticket:"
    }
    
    foreach ($event in $pttCmdEvents) {
        $msg = $event.Message
        $user = if ($msg -match "User:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
        $cmdLine = if ($msg -match "CommandLine:\s*(.+?)[\r\n]") { $matches[1].Trim() } else { "Unknown" }
        
        $findings += New-Finding -Category "Pass-the-Ticket" -Severity "CRITICAL" `
            -Time (Get-EventTimeUTC $event) -Description "Pass-the-Ticket command detected" `
            -EventID "1" -Source "Sysmon" `
            -Details "User: $user | CMD: $cmdLine" `
            -RawLog $event.Message
        
        Write-Host "  [!] CRITICAL: Pass-the-Ticket command by $user" -ForegroundColor Red
        $pttFound = $true
    }
    
    # Method 2: Network logons with Kerberos from multiple IPs
    $pttEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4624
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "Logon Type:\s*3" -and $_.Message -match "Authentication Package:\s*Kerberos"
    }
    
    if ($pttEvents) {
        $pttGrouped = $pttEvents | Group-Object {
            if ($_.Message -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        } | Where-Object { 
            $ips = $_.Group | ForEach-Object {
                if ($_.Message -match "Source Network Address:\s*(\d+\.\d+\.\d+\.\d+)") { $matches[1] }
            } | Select-Object -Unique
            $ips.Count -gt 1
        }
        
        foreach ($group in $pttGrouped) {
            $sampleEvent = $group.Group[0]
            $userName = $group.Name
            
            $findings += New-Finding -Category "Pass-the-Ticket" -Severity "HIGH" `
                -Time (Get-EventTimeUTC $sampleEvent) -Description "User authenticated from multiple IPs" `
                -EventID "4624" -Source "Security" `
                -Details "User: $userName" `
                -RawLog $sampleEvent.Message
            
            Write-Host "  [!] HIGH: Pass-the-Ticket suspected for $userName (multiple IPs)" -ForegroundColor Red
            $pttFound = $true
        }
    }
    
    if (-not $pttFound) {
        Write-Host "  [-] No Pass-the-Ticket events" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [-] Error checking Pass-the-Ticket: $($_.Exception.Message)" -ForegroundColor Gray
}

# ============================================
# RDP TO DC DETECTION (BONUS)
# ============================================

Write-Host "`n[BONUS] Detecting RDP to Domain Controller..." -ForegroundColor Yellow

try {
    # Event 4624 Logon Type 10 = RemoteInteractive (RDP)
    $rdpEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4624
        StartTime = $startTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -match "Logon Type:\s*10"
    }
    
    foreach ($event in $rdpEvents) {
        $msg = $event.Message
        $targetUser = if ($msg -match "Account Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $sourceIP = if ($msg -match "Source Network Address:\s*(\S+)") { $matches[1] } else { "Unknown" }
        $workstation = if ($msg -match "Workstation Name:\s*(\S+)") { $matches[1] } else { "Unknown" }
        
        # Skip machine accounts
        if ($targetUser -match "\$$") { continue }
        
        $findings += New-Finding -Category "RDP Session" -Severity "MEDIUM" `
            -Time (Get-EventTimeUTC $event) -Description "RDP logon detected" `
            -EventID "4624" -Source "Security" `
            -Details "User: $targetUser | Source: $sourceIP | Workstation: $workstation" `
            -RawLog $event.Message
        
        Write-Host "  [!] MEDIUM: RDP session by $targetUser from $sourceIP" -ForegroundColor Yellow
    }
    
    if (-not $rdpEvents -or $rdpEvents.Count -eq 0) {
        Write-Host "  [-] No RDP events" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [-] Error checking RDP: $($_.Exception.Message)" -ForegroundColor Gray
}

# Generate Summary
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "INVESTIGATION SUMMARY" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Cyan

$criticalCount = ($findings | Where-Object {$_.Severity -eq "CRITICAL"}).Count
$highCount = ($findings | Where-Object {$_.Severity -eq "HIGH"}).Count
$mediumCount = ($findings | Where-Object {$_.Severity -eq "MEDIUM"}).Count

Write-Host "`nActivity Statistics:" -ForegroundColor White
Write-Host "  Mimikatz Executions:    $($stats.MimikatzExecutions)" -ForegroundColor Cyan
Write-Host "  LSASS Access:           $($stats.LSASSAccess)" -ForegroundColor Cyan
Write-Host "  SAM Access:             $($stats.SAMAccess)" -ForegroundColor Cyan
Write-Host "  Credential Dumping:     $($stats.CredentialDumping)" -ForegroundColor Cyan
Write-Host "  Pass-the-Hash:          $($stats.PassTheHash)" -ForegroundColor Cyan
Write-Host "  WinRM Connections:      $($stats.WinRMConnections)" -ForegroundColor Cyan
Write-Host "  Remote Logons:          $($stats.RemoteLogons)" -ForegroundColor Cyan
Write-Host "  PSSession Creations:    $($stats.PSSessionCreations)" -ForegroundColor Cyan
Write-Host "  File Transfers:         $($stats.FileTransfers)" -ForegroundColor Cyan
Write-Host "  Suspicious Commands:    $($stats.SuspiciousCommands)" -ForegroundColor Cyan

Write-Host "`nFinding Summary:" -ForegroundColor White
Write-Host "  Total Findings: $($findings.Count)" -ForegroundColor White
Write-Host "  CRITICAL: $criticalCount" -ForegroundColor Red
Write-Host "  HIGH:     $highCount" -ForegroundColor Red
Write-Host "  MEDIUM:   $mediumCount" -ForegroundColor Yellow

# Risk Assessment
$riskScore = ($criticalCount * 10) + ($highCount * 5) + ($mediumCount * 2)
$riskLevel = if ($riskScore -gt 50) { "CRITICAL" } elseif ($riskScore -gt 20) { "HIGH" } elseif ($riskScore -gt 5) { "MEDIUM" } else { "LOW" }
$riskColor = switch ($riskLevel) {
    "CRITICAL" { "Red" }
    "HIGH" { "Red" }
    "MEDIUM" { "Yellow" }
    "LOW" { "Green" }
}

Write-Host "`nRisk Assessment:" -ForegroundColor Cyan
Write-Host "  Risk Score:  $riskScore" -ForegroundColor $riskColor
Write-Host "  Risk Level:  $riskLevel" -ForegroundColor $riskColor

if ($findings.Count -gt 0) {
    Write-Host "`nTop 10 Recent Findings:" -ForegroundColor Cyan
    $findings | Sort-Object Timestamp -Descending | Select-Object -First 10 | 
        Select-Object Timestamp, Severity, Category, Description |
        Format-Table -AutoSize -Wrap
    
    # Generate HTML Report
    $riskClass = "risk-$($riskLevel.ToLower())"
    $reportDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
    
    # Build findings rows
    # Helper function for HTML encoding (avoids System.Web dependency)
    function ConvertTo-HtmlEncoded {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return "" }
        $Text = $Text -replace '&', '&amp;'
        $Text = $Text -replace '<', '&lt;'
        $Text = $Text -replace '>', '&gt;'
        $Text = $Text -replace '"', '&quot;'
        $Text = $Text -replace "'", '&#39;'
        return $Text
    }
    
    $findingsRows = ""
    $rowIndex = 0
    foreach ($f in ($findings | Sort-Object Timestamp -Descending)) {
        $severityClass = switch ($f.Severity) {
            "CRITICAL" { "severity-critical" }
            "HIGH" { "severity-high" }
            "MEDIUM" { "severity-medium" }
            default { "severity-low" }
        }
        $timestamp = if ($f.Timestamp) { $f.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
        $encodedDetails = ConvertTo-HtmlEncoded -Text $f.Details
        $encodedRawLog = ConvertTo-HtmlEncoded -Text $f.RawLog
        $hasRawLog = if (-not [string]::IsNullOrEmpty($f.RawLog)) { "has-details" } else { "" }
        $encodedCategory = ConvertTo-HtmlEncoded -Text $f.Category
        
        $findingsRows += @"
        <tr class="finding-row $hasRawLog" onclick="toggleDetails('details-$rowIndex')">
            <td>$timestamp</td>
            <td><span class="$severityClass">$($f.Severity)</span></td>
            <td>$($f.Category)</td>
            <td>$($f.Description)</td>
            <td>$($f.EventID)</td>
            <td>$($f.Source)</td>
            <td class="details">$encodedDetails</td>
        </tr>
        <tr class="raw-log-row" id="details-$rowIndex" data-category="$encodedCategory">
            <td colspan="7">
                <div class="raw-log-container">
                    <div class="raw-log-header">
                        <span class="raw-log-title">Full Event Log Details</span>
                        <div class="button-group">
                            <button class="detection-logic-btn" onclick="event.stopPropagation(); showDetectionLogic('$encodedCategory')">Detection Logic</button>
                            <button class="copy-btn" onclick="event.stopPropagation(); copyToClipboard('raw-$rowIndex')">Copy to Clipboard</button>
                        </div>
                    </div>
                    <pre class="raw-log-content" id="raw-$rowIndex">$encodedRawLog</pre>
                </div>
            </td>
        </tr>
"@
        $rowIndex++
    }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Threat Hunting Report</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 10px; 
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        header { 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white; 
            padding: 30px;
            text-align: center;
        }
        h1 { 
            font-size: 32px; 
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .subtitle { 
            font-size: 14px; 
            opacity: 0.9;
        }
        .content { padding: 30px; }
        h2 { 
            color: #1e3c72; 
            margin: 30px 0 15px 0; 
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            font-size: 24px;
        }
        .risk-banner {
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            text-align: center;
            font-size: 24px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        .risk-critical { background: #f2dede; color: #a94442; border: 3px solid #a94442; }
        .risk-high { background: #fcf8e3; color: #8a6d3b; border: 3px solid #8a6d3b; }
        .risk-medium { background: #d9edf7; color: #31708f; border: 3px solid #31708f; }
        .risk-low { background: #dff0d8; color: #3c763d; border: 3px solid #3c763d; }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 25px 0;
        }
        .stat-card { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { 
            font-size: 42px; 
            font-weight: bold; 
            margin: 10px 0;
        }
        .stat-label { 
            font-size: 12px; 
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: 0.9;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
            font-size: 13px;
        }
        th { 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white; 
            padding: 15px 10px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 11px;
            cursor: pointer;
            user-select: none;
            position: relative;
        }
        th:hover {
            background: linear-gradient(135deg, #2a5298 0%, #3a62a8 100%);
        }
        th .sort-icon {
            margin-left: 5px;
            font-size: 10px;
        }
        th.sort-asc .sort-icon { color: #90EE90; }
        th.sort-desc .sort-icon { color: #90EE90; }
        td { 
            padding: 12px 10px; 
            border-bottom: 1px solid #e0e0e0;
            vertical-align: top;
        }
        tr:hover { background: #f8f9fa; }
        .severity-critical { 
            background: #d9534f; 
            color: white; 
            padding: 4px 10px; 
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
        }
        .severity-high { 
            background: #f0ad4e; 
            color: white; 
            padding: 4px 10px; 
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
        }
        .severity-medium { 
            background: #5bc0de; 
            color: white; 
            padding: 4px 10px; 
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
        }
        .severity-low { 
            background: #5cb85c; 
            color: white; 
            padding: 4px 10px; 
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
        }
        .details { 
            max-width: 300px; 
            word-wrap: break-word;
            font-family: 'Consolas', monospace;
            font-size: 11px;
            background: #f5f5f5;
            padding: 5px;
            border-radius: 3px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .summary-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        .summary-item.critical { border-left-color: #d9534f; }
        .summary-item.high { border-left-color: #f0ad4e; }
        .summary-item.medium { border-left-color: #5bc0de; }
        footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #e0e0e0;
        }
        /* Interactive row styles */
        .finding-row {
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .finding-row.has-details:hover {
            background: #e3f2fd !important;
        }
        .finding-row.has-details td:first-child::before {
            content: '> ';
            color: #667eea;
            font-size: 12px;
            font-weight: bold;
        }
        .finding-row.expanded td:first-child::before {
            content: 'v ';
        }
        .raw-log-row {
            display: none;
            background: #f8f9fa;
        }
        .raw-log-row.visible {
            display: table-row;
        }
        .raw-log-container {
            background: #1e1e1e;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }
                .raw-log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #444;
            flex-wrap:  wrap;
            gap: 10px;
            min-height: 40px; /* Ensure buttons always have space */
        }
        . raw-log-title {
            color: #4fc3f7;
            font-weight: bold;
            font-size: 14px;
            flex: 0 1 auto; /* Allow title to shrink if needed */
        }
        . copy-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.2s;
            white-space: nowrap; /* Prevent button text from wrapping */
        }
        .copy-btn:hover {
            background: #5a6fd6;
        }
        .copy-btn. copied {
            background: #4caf50;
        }
        .raw-log-content {
            color: #d4d4d4;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-wrap: break-word;
            word-break: break-all;
            overflow-wrap: break-word;
            max-height: 400px;
            overflow-y: auto;
            overflow-x: auto;
            margin: 0;
            padding:  10px;
            background:  #2d2d2d;
            border-radius: 4px;
            line-height:  1.5;
        }
        .detection-logic-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.2s;
            margin-left: 0; /* Remove left margin, gap handles spacing */
            white-space: nowrap;
        }
        .detection-logic-btn:hover {
            background: #138496;
        }
        .button-group {
            display: flex;
            gap: 10px;
            flex-shrink:  0;
            flex-wrap: nowrap; /* Keep buttons together */
        }
        /* Detection Logic Modal */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal-overlay.visible {
            display: flex;
        }
        .modal-content {
            background: white;
            border-radius: 12px;
            max-width: 800px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .modal-header {
            background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
            color: white;
            padding: 20px;
            border-radius: 12px 12px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h3 {
            margin: 0;
            font-size: 18px;
        }
        .modal-close {
            background: rgba(255,255,255,0.2);
            border: none;
            color: white;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .modal-close:hover {
            background: rgba(255,255,255,0.3);
        }
        .modal-body {
            padding: 20px;
        }
        .logic-section {
            margin-bottom: 20px;
        }
        .logic-section-title {
            font-weight: bold;
            color: #1e3c72;
            margin-bottom: 10px;
            font-size: 14px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 5px;
        }
        .logic-item {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 10px;
            border-left: 4px solid #17a2b8;
        }
        .logic-item-label {
            font-weight: bold;
            color: #495057;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        .logic-item-value {
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            color: #212529;
            background: white;
            padding: 8px;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }
        .logic-tip {
            background: #e7f3ff;
            border: 1px solid #b3d7ff;
            border-radius: 6px;
            padding: 12px;
            margin-top: 15px;
            font-size: 13px;
            color: #004085;
        }
        .logic-tip-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .click-hint {
            background: #e3f2fd;
            color: #1565c0;
            padding: 10px 15px;
            border-radius: 6px;
            margin-bottom: 15px;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .click-hint::before {
            content: '💡';
        }
        /* Filter controls */
        .filter-controls {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        .filter-group {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid #ddd;
            background: white;
            border-radius: 20px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }
        .filter-btn:hover {
            border-color: #667eea;
        }
        .filter-btn.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        .filter-btn.critical.active { background: #d9534f; border-color: #d9534f; }
        .filter-btn.high.active { background: #f0ad4e; border-color: #f0ad4e; }
        .filter-btn.medium.active { background: #5bc0de; border-color: #5bc0de; }
        .column-filter {
            padding: 8px 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 12px;
            background: white;
            cursor: pointer;
            min-width: 150px;
        }
        .column-filter:focus {
            outline: none;
            border-color: #667eea;
        }
        .search-box {
            padding: 8px 12px;
            border: 2px solid #ddd;
            border-radius: 20px;
            font-size: 12px;
            width: 250px;
        }
        .search-box:focus {
            outline: none;
            border-color: #667eea;
        }
        .reset-btn {
            padding: 8px 16px;
            border: none;
            background: #dc3545;
            color: white;
            border-radius: 20px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }
        .reset-btn:hover {
            background: #c82333;
        }
        .results-count {
            color: #666;
            font-size: 13px;
            margin-bottom: 10px;
            padding: 8px 12px;
            background: #f0f0f0;
            border-radius: 4px;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Advanced Threat Hunting Report</h1>
            <div class="subtitle">Lateral Movement, Mimikatz, and Credential Dumping Investigation</div>
            <div class="subtitle">Generated: $reportDate | Analysis Period: Last $HoursBack hours</div>
        </header>
        
        <div class="content">
            <div class="risk-banner $riskClass">
                Risk Level: $riskLevel (Score: $riskScore)
            </div>
            
            <h2>Finding Summary</h2>
            <div class="summary-grid">
                <div class="summary-item critical">
                    <div style="font-size: 36px; font-weight: bold; color: #d9534f;">$criticalCount</div>
                    <div>Critical Findings</div>
                </div>
                <div class="summary-item high">
                    <div style="font-size: 36px; font-weight: bold; color: #f0ad4e;">$highCount</div>
                    <div>High Findings</div>
                </div>
                <div class="summary-item medium">
                    <div style="font-size: 36px; font-weight: bold; color: #5bc0de;">$mediumCount</div>
                    <div>Medium Findings</div>
                </div>
            </div>
            
            <h2>Activity Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Mimikatz Executions</div>
                    <div class="stat-number">$($stats.MimikatzExecutions)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">LSASS Access</div>
                    <div class="stat-number">$($stats.LSASSAccess)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">SAM Access</div>
                    <div class="stat-number">$($stats.SAMAccess)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Credential Dumping</div>
                    <div class="stat-number">$($stats.CredentialDumping)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Pass-the-Hash</div>
                    <div class="stat-number">$($stats.PassTheHash)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">WinRM Connections</div>
                    <div class="stat-number">$($stats.WinRMConnections)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Remote Logons</div>
                    <div class="stat-number">$($stats.RemoteLogons)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">PSSession Creations</div>
                    <div class="stat-number">$($stats.PSSessionCreations)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">File Transfers</div>
                    <div class="stat-number">$($stats.FileTransfers)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Suspicious Commands</div>
                    <div class="stat-number">$($stats.SuspiciousCommands)</div>
                </div>
            </div>
            
            <h2>Detailed Findings ($($findings.Count) Total)</h2>
            
            <div class="click-hint">Click on any row to expand and view the full raw event log details. Click column headers to sort.</div>
            
            <div class="filter-controls">
                <div class="filter-group">
                    <span style="font-weight: bold; color: #666;">Severity:</span>
                    <button class="filter-btn active" onclick="filterBySeverity('all')">All</button>
                    <button class="filter-btn critical" onclick="filterBySeverity('CRITICAL')">Critical ($criticalCount)</button>
                    <button class="filter-btn high" onclick="filterBySeverity('HIGH')">High ($highCount)</button>
                    <button class="filter-btn medium" onclick="filterBySeverity('MEDIUM')">Medium ($mediumCount)</button>
                </div>
                <div class="filter-group">
                    <span style="font-weight: bold; color: #666;">Category:</span>
                    <select id="category-filter" class="column-filter" onchange="applyFilters()">
                        <option value="">All Categories</option>
                    </select>
                </div>
                <div class="filter-group">
                    <span style="font-weight: bold; color: #666;">Source:</span>
                    <select id="source-filter" class="column-filter" onchange="applyFilters()">
                        <option value="">All Sources</option>
                    </select>
                </div>
                <div class="filter-group">
                    <span style="font-weight: bold; color: #666;">Event ID:</span>
                    <select id="eventid-filter" class="column-filter" onchange="applyFilters()">
                        <option value="">All Event IDs</option>
                    </select>
                </div>
                <div class="filter-group">
                    <input type="text" class="search-box" id="search-box" placeholder="Search all columns..." onkeyup="applyFilters()">
                </div>
                <div class="filter-group">
                    <button class="reset-btn" onclick="resetFilters()">Reset All Filters</button>
                </div>
            </div>
            
            <div class="results-count">Showing <span id="visible-count">$($findings.Count)</span> of $($findings.Count) findings</div>
            
            <table id="findings-table">
                <thead>
                    <tr>
                        <th onclick="sortTable(0, 'date')" data-col="0">Timestamp (UTC) <span class="sort-icon">[=]</span></th>
                        <th onclick="sortTable(1, 'severity')" data-col="1">Severity <span class="sort-icon">[=]</span></th>
                        <th onclick="sortTable(2, 'string')" data-col="2">Category <span class="sort-icon">[=]</span></th>
                        <th onclick="sortTable(3, 'string')" data-col="3">Description <span class="sort-icon">[=]</span></th>
                        <th onclick="sortTable(4, 'string')" data-col="4">Event ID <span class="sort-icon">[=]</span></th>
                        <th onclick="sortTable(5, 'string')" data-col="5">Source <span class="sort-icon">[=]</span></th>
                        <th onclick="sortTable(6, 'string')" data-col="6">Details <span class="sort-icon">[=]</span></th>
                    </tr>
                </thead>
                <tbody>
                    $findingsRows
                </tbody>
            </table>
        </div>
        
        <footer>
            <p>Advanced Threat Hunting Script | Investigation completed at $reportDate</p>
            <p>This report should be reviewed by security personnel for appropriate response actions.</p>
        </footer>
    </div>
    
    <!-- Detection Logic Modal -->
    <div id="detection-logic-modal" class="modal-overlay" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h3 id="modal-title">Detection Logic</h3>
                <button class="modal-close" onclick="closeDetectionLogic()">&times;</button>
            </div>
            <div class="modal-body" id="modal-body">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>
    
    <script>
        // Detection Logic Database
        const detectionLogicDB = {
            'Mimikatz Execution': {
                description: 'Detects execution of Mimikatz credential dumping tool, including renamed executables',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 1 (Process Creation)',
                criteria: [
                    'Process name or path contains: mimikatz, mimilib, mimidrv',
                    'Command line contains Mimikatz module syntax (::) such as: sekurlsa::, lsadump::, kerberos::, crypto::, dpapi::, token::, privilege::',
                    'Command line contains specific commands: logonpasswords, dcsync, golden, silver, ptt',
                    'OriginalFileName in PE header contains mimikatz (detects renamed executables)',
                    'File Description metadata contains mimikatz or gentilkiwi'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=1} | Where-Object { $_.Message -match \"sekurlsa::|lsadump::|kerberos::|mimikatz|privilege::debug\" }',
                mitre: 'T1003.001 - OS Credential Dumping: LSASS Memory'
            },
            'LSASS Access': {
                description: 'Detects suspicious processes accessing LSASS memory, which may indicate credential dumping',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 10 (Process Access)',
                criteria: [
                    'Target process is lsass.exe',
                    'Source process is NOT one of: svchost.exe, csrss.exe, wininit.exe, services.exe, MsMpEng.exe',
                    'GrantedAccess includes memory read permissions'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=10} | Where-Object { $_.Message -match \"lsass.exe\" -and $_.Message -notmatch \"svchost|csrss|wininit|services|MsMpEng\" }',
                mitre: 'T1003.001 - OS Credential Dumping: LSASS Memory'
            },
            'SAM Database Access': {
                description: 'Detects access to SAM registry hive which contains local account password hashes',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 12, 13 (Registry Events)',
                criteria: [
                    'Target registry path contains: SAM\\SAM\\Domains\\Account\\Users',
                    'Or target path contains: SECURITY\\Policy\\Secrets',
                    'Source process is NOT: services.exe, svchost.exe, lsass.exe, System'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=12,13} | Where-Object { $_.Message -match \"SAM\\\\SAM\\\\Domains|SECURITY\\\\Policy\\\\Secrets\" }',
                mitre: 'T1003.002 - OS Credential Dumping: Security Account Manager'
            },
            'SAM File Copy': {
                description: 'Detects copying of SAM, SYSTEM, or SECURITY files which can be used offline to extract credentials',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 11 (File Create)',
                criteria: [
                    'Target filename contains: \\System32\\config\\SAM',
                    'Or: \\System32\\config\\SYSTEM',
                    'Or: \\System32\\config\\SECURITY',
                    'Or: ntds.dit (Active Directory database)',
                    'Source process is NOT: services.exe, svchost.exe, System'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=11} | Where-Object { $_.Message -match \"config\\\\SAM|config\\\\SYSTEM|config\\\\SECURITY|ntds.dit\" }',
                mitre: 'T1003.002 - OS Credential Dumping: Security Account Manager'
            },
            'PowerShell Credential Dump': {
                description: 'Detects PowerShell commands associated with credential dumping techniques',
                logSource: 'Microsoft-Windows-PowerShell/Operational',
                eventId: 'Event ID 4104 (Script Block Logging)',
                criteria: [
                    'Script block contains: Invoke-Mimikatz, sekurlsa::, lsadump::',
                    'Or contains: DumpCreds, DumpCerts, Get-GPPPassword',
                    'Or contains: comsvcs.dll with MiniDump',
                    'Or contains: procdump targeting lsass',
                    'Or contains: Out-Minidump, ReadProcessMemory with lsass'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-PowerShell/Operational\"; ID=4104} | Where-Object { $_.Message -match \"Invoke-Mimikatz|sekurlsa::|lsadump::|DumpCreds|comsvcs.*MiniDump\" }',
                mitre: 'T1059.001 - Command and Scripting Interpreter: PowerShell'
            },
            'Pass-the-Hash': {
                description: 'Detects Logon Type 9 (NewCredentials) which is commonly used in Pass-the-Hash attacks',
                logSource: 'Security',
                eventId: 'Event ID 4624 (Successful Logon)',
                criteria: [
                    'Logon Type = 9 (NewCredentials)',
                    'This logon type allows the caller to clone its current token and specify new credentials for outbound connections'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4624} | Where-Object { $_.Properties[8].Value -eq 9 }',
                mitre: 'T1550.002 - Use Alternate Authentication Material: Pass the Hash'
            },
            'Explicit Credentials': {
                description: 'Detects when a process uses explicit credentials to log on, which may indicate lateral movement',
                logSource: 'Security',
                eventId: 'Event ID 4648 (Explicit Credential Logon)',
                criteria: [
                    'A logon was attempted using explicit credentials',
                    'Process is NOT: consent.exe, svchost.exe, lsass.exe, services.exe',
                    'Account is NOT: DWM-*, UMFD-*, SYSTEM, LOCAL SERVICE, NETWORK SERVICE'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4648} | Where-Object { $_.Message -notmatch \"consent.exe|DWM-|UMFD-\" }',
                mitre: 'T1078 - Valid Accounts'
            },
            'Privilege Escalation': {
                description: 'Detects when SeDebugPrivilege is assigned, which allows debugging of any process including LSASS',
                logSource: 'Security',
                eventId: 'Event ID 4672 (Special Privileges Assigned)',
                criteria: [
                    'SeDebugPrivilege is in the privilege list',
                    'Account is NOT: SYSTEM, LOCAL SERVICE, NETWORK SERVICE'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4672} | Where-Object { $_.Message -match \"SeDebugPrivilege\" -and $_.Message -notmatch \"SYSTEM|LOCAL SERVICE|NETWORK SERVICE\" }',
                mitre: 'T1134 - Access Token Manipulation'
            },
            'WinRM Activity': {
                description: 'Detects Windows Remote Management (WinRM) session activity used for lateral movement',
                logSource: 'Microsoft-Windows-WinRM/Operational',
                eventId: 'Event ID 6, 33, 91, 142',
                criteria: [
                    'Event ID 6: WSMan session created',
                    'Event ID 33: Remote connection established',
                    'Event ID 91: WinRM client connecting',
                    'Event ID 142: WSMan operation completed'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-WinRM/Operational\"; ID=6,33,91,142}',
                mitre: 'T1021.006 - Remote Services: Windows Remote Management'
            },
            'Remote Logon': {
                description: 'Detects network logons (Type 3) from remote IP addresses',
                logSource: 'Security',
                eventId: 'Event ID 4624 (Successful Logon)',
                criteria: [
                    'Logon Type = 3 (Network)',
                    'Source IP is NOT: 127.*, ::1, fe80::, or empty',
                    'Higher severity if authentication uses NTLM'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4624} | Where-Object { $_.Properties[8].Value -eq 3 -and $_.Properties[18].Value -notmatch \"^127\\.|::1|fe80::\" }',
                mitre: 'T1078 - Valid Accounts'
            },
            'PS Remoting': {
                description: 'Detects PowerShell remoting session host process creation',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 1 (Process Creation)',
                criteria: [
                    'Process image is wsmprovhost.exe (PowerShell remoting host)',
                    'This process hosts remote PowerShell sessions'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=1} | Where-Object { $_.Message -match \"wsmprovhost.exe\" }',
                mitre: 'T1021.006 - Remote Services: Windows Remote Management'
            },
            'WinRM Network': {
                description: 'Detects network connections to WinRM ports (5985/5986)',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 3 (Network Connection)',
                criteria: [
                    'Destination port is 5985 (HTTP) or 5986 (HTTPS)',
                    'Or source process is wsmprovhost.exe'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=3} | Where-Object { $_.Message -match \":5985|:5986|wsmprovhost.exe\" }',
                mitre: 'T1021.006 - Remote Services: Windows Remote Management'
            },
            'PS Remote Command': {
                description: 'Detects PowerShell remote execution commands',
                logSource: 'Microsoft-Windows-PowerShell/Operational',
                eventId: 'Event ID 4103, 4104 (Module/Script Block Logging)',
                criteria: [
                    'Script contains: Enter-PSSession, Invoke-Command, New-PSSession',
                    'Or contains: Copy-Item with -ToSession or -FromSession',
                    'Critical if combined with mimikatz, IEX, or DownloadString'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-PowerShell/Operational\"; ID=4103,4104} | Where-Object { $_.Message -match \"Enter-PSSession|Invoke-Command|New-PSSession\" }',
                mitre: 'T1059.001 - Command and Scripting Interpreter: PowerShell'
            },
            'File Transfer': {
                description: 'Detects file transfers via PowerShell remoting sessions',
                logSource: 'Microsoft-Windows-PowerShell/Operational',
                eventId: 'Event ID 4103, 4104 (Module/Script Block Logging)',
                criteria: [
                    'Script contains: Copy-Item with -ToSession (upload to remote)',
                    'Or contains: Copy-Item with -FromSession (download from remote)'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-PowerShell/Operational\"; ID=4103,4104} | Where-Object { $_.Message -match \"Copy-Item.*-ToSession|Copy-Item.*-FromSession\" }',
                mitre: 'T1570 - Lateral Tool Transfer'
            },
            'Remote Credential Access': {
                description: 'Detects remote PowerShell sessions accessing sensitive processes like LSASS',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 10 (Process Access)',
                criteria: [
                    'Source process is wsmprovhost.exe or powershell.exe with ServerRemoteHost',
                    'Target process is: lsass.exe, services.exe, or winlogon.exe'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=10} | Where-Object { $_.Message -match \"wsmprovhost.exe|ServerRemoteHost\" -and $_.Message -match \"lsass.exe|services.exe|winlogon.exe\" }',
                mitre: 'T1003.001 - OS Credential Dumping: LSASS Memory'
            },
            'DPAPI Activity': {
                description: 'Detects DPAPI Master Key backup or recovery operations, which can indicate credential theft',
                logSource: 'Security',
                eventId: 'Event ID 4692 (Master Key Backup), 4693 (Master Key Recovery)',
                criteria: [
                    'Event 4692: DPAPI Master Key was backed up',
                    'Event 4693: DPAPI Master Key recovery was attempted',
                    'Recovery from Domain Controller indicates potential credential extraction'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4692,4693}',
                mitre: 'T1555 - Credentials from Password Stores'
            },
            'Kerberos Anomaly': {
                description: 'Detects suspicious Kerberos ticket requests that may indicate Golden/Silver ticket or Kerberoasting attacks',
                logSource: 'Security',
                eventId: 'Event ID 4768 (TGT Request), 4769 (TGS Request)',
                criteria: [
                    'Ticket encryption type is RC4 (0x17/23) - weak encryption often used in attacks',
                    'Pre-authentication type is 0 (disabled) - common in AS-REP roasting',
                    'Unusual service ticket requests may indicate Kerberoasting'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4768,4769} | Where-Object { $_.Message -match \"Ticket Encryption Type:\\s*(0x17|23)\" }',
                mitre: 'T1558 - Steal or Forge Kerberos Tickets'
            },
            'NTLM Authentication': {
                description: 'Detects suspicious NTLM authentication events that may indicate Pass-the-Hash attacks',
                logSource: 'Security',
                eventId: 'Event ID 4776 (NTLM Credential Validation)',
                criteria: [
                    'NTLM authentication with empty or missing source workstation (common in PtH)',
                    'Failed NTLM authentication attempts (non-zero error codes)',
                    'NTLM usage in environments where Kerberos should be used'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4776} | Where-Object { $_.Message -notmatch \"Source Workstation:\\s*\\S+\" -or $_.Message -match \"Error Code:\\s*0x[^0]\" }',
                mitre: 'T1550.002 - Use Alternate Authentication Material: Pass the Hash'
            },
            'DCSync Attack': {
                description: 'Detects DCSync attacks where an attacker uses directory replication to extract password hashes',
                logSource: 'Security',
                eventId: 'Event ID 4662 (Operation on Directory Object)',
                criteria: [
                    'Access to directory replication rights (DS-Replication-Get-Changes)',
                    'GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (Get-Changes)',
                    'GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (Get-Changes-All)',
                    'Excludes legitimate Domain Controller machine accounts'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4662} | Where-Object { $_.Message -match \"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2\" }',
                mitre: 'T1003.006 - OS Credential Dumping: DCSync'
            },
            'Process Injection': {
                description: 'Detects CreateRemoteThread calls which may indicate process injection attacks',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 8 (CreateRemoteThread)',
                criteria: [
                    'A process created a thread in another process',
                    'Source process is NOT a known legitimate process (csrss, wininit, services, svchost)',
                    'CRITICAL if target is lsass.exe'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=8} | Where-Object { $_.Message -notmatch \"SourceImage:.*\\\\(csrss|wininit|services|svchost)\\.exe\" }',
                mitre: 'T1055 - Process Injection'
            },
            'Process Tampering': {
                description: 'Detects process tampering/hollowing techniques used to evade detection',
                logSource: 'Microsoft-Windows-Sysmon/Operational',
                eventId: 'Event ID 25 (Process Tampering)',
                criteria: [
                    'Process image was modified after creation',
                    'Types include: Image is replaced, Image is locked for access',
                    'Common technique in malware to hide malicious code'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=25}',
                mitre: 'T1055.012 - Process Injection: Process Hollowing'
            },
            'Log Cleared': {
                description: 'Detects when security-relevant event logs are cleared, which may indicate anti-forensics',
                logSource: 'Security / System',
                eventId: 'Event ID 1102 (Security Log Cleared), 104 (System Log Cleared)',
                criteria: [
                    'Security event log was cleared',
                    'Or Sysmon log was cleared',
                    'Or other security-relevant logs were cleared',
                    'Captures the user account that performed the action'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=1102}; Get-WinEvent -FilterHashtable @{LogName=\"System\"; ID=104}',
                mitre: 'T1070.001 - Indicator Removal: Clear Windows Event Logs'
            },
            'Kerberoasting': {
                description: 'Detects Kerberoasting - requesting TGS tickets with RC4 encryption to crack offline',
                logSource: 'Security',
                eventId: 'Event ID 4769 (TGS Request)',
                criteria: [
                    'Multiple TGS requests from same source IP',
                    'Ticket Encryption Type is RC4 (0x17 or 23)',
                    '3+ requests indicate attack'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4769} | Where-Object { $_.Message -match \"Ticket Encryption Type:\\s*(0x17|23)\" }',
                mitre: 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
            },
            'AS-REP Roasting': {
                description: 'Detects AS-REP Roasting - targeting accounts without Kerberos pre-authentication',
                logSource: 'Security',
                eventId: 'Event ID 4768 (TGT Request)',
                criteria: [
                    'Pre-Authentication Type is 0 (no pre-auth)',
                    'Account has Do not require Kerberos preauthentication enabled'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4768} | Where-Object { $_.Message -match \"Pre-Authentication Type:\\s*0\" }',
                mitre: 'T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting'
            },
            'Golden Ticket Suspected': {
                description: 'Detects potential Golden Ticket - forged TGT with krbtgt hash',
                logSource: 'Security',
                eventId: 'Event ID 4768 (TGT Request)',
                criteria: [
                    'Administrator TGT request with RC4 encryption',
                    'Request from non-DC source'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4768} | Where-Object { $_.Message -match \"Account Name:\\s*Administrator\" -and $_.Message -match \"0x17\" }',
                mitre: 'T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket'
            },
            'Skeleton Key Attack': {
                description: 'Detects Skeleton Key - LSASS patch allowing master password on DC',
                logSource: 'Sysmon / System',
                eventId: 'Sysmon 1, System 7045',
                criteria: [
                    'misc::skeleton command detected',
                    'mimidrv service installation'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=1} | Where-Object { $_.Message -match \"misc::skeleton\" }',
                mitre: 'T1556.001 - Modify Authentication Process'
            },
            'S4U Delegation Abuse': {
                description: 'Detects S4U2Self/S4U2Proxy abuse for impersonation',
                logSource: 'Security',
                eventId: 'Event ID 4769 (TGS Request)',
                criteria: [
                    'TGS request with Transited Services populated',
                    'Service requesting ticket on behalf of another user'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4769} | Where-Object { $_.Message -match \"Transited Services:\\s*[^-]\" }',
                mitre: 'T1558 - Steal or Forge Kerberos Tickets'
            },
            'Credential Dumping (sekurlsa)': {
                description: 'Detects Mimikatz sekurlsa module commands',
                logSource: 'PowerShell',
                eventId: 'Event ID 4104',
                criteria: [
                    'sekurlsa::logonpasswords',
                    'sekurlsa::tickets',
                    'sekurlsa::pth'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-PowerShell/Operational\"; ID=4104} | Where-Object { $_.Message -match \"sekurlsa::\" }',
                mitre: 'T1003.001 - OS Credential Dumping: LSASS Memory'
            },
            'Credential Dumping (lsadump)': {
                description: 'Detects Mimikatz lsadump module commands',
                logSource: 'PowerShell',
                eventId: 'Event ID 4104',
                criteria: [
                    'lsadump::sam',
                    'lsadump::secrets',
                    'lsadump::dcsync'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-PowerShell/Operational\"; ID=4104} | Where-Object { $_.Message -match \"lsadump::\" }',
                mitre: 'T1003 - OS Credential Dumping'
            },
            'Kerberos Manipulation': {
                description: 'Detects Mimikatz kerberos module for ticket attacks',
                logSource: 'PowerShell',
                eventId: 'Event ID 4104',
                criteria: [
                    'kerberos::golden',
                    'kerberos::silver',
                    'kerberos::ptt'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-PowerShell/Operational\"; ID=4104} | Where-Object { $_.Message -match \"kerberos::\" }',
                mitre: 'T1558 - Steal or Forge Kerberos Tickets'
            },
            'Token Manipulation': {
                description: 'Detects Mimikatz token module for privilege escalation',
                logSource: 'PowerShell',
                eventId: 'Event ID 4104',
                criteria: [
                    'token::elevate',
                    'token::list'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-PowerShell/Operational\"; ID=4104} | Where-Object { $_.Message -match \"token::\" }',
                mitre: 'T1134 - Access Token Manipulation'
            },
            'Overpass-the-Hash': {
                description: 'Detects Overpass-the-Hash via Logon Type 9',
                logSource: 'Security',
                eventId: 'Event ID 4624',
                criteria: [
                    'Logon Type 9 (NewCredentials)',
                    'NTLM hash used to get Kerberos ticket'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4624} | Where-Object { $_.Message -match \"Logon Type:\\s*9\" }',
                mitre: 'T1550.002 - Use Alternate Authentication Material'
            },
            'Password Spraying': {
                description: 'Detects Password Spraying attacks',
                logSource: 'Security',
                eventId: 'Event ID 4771',
                criteria: [
                    '5+ failures from same source',
                    'Failures to 3+ different accounts'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4771}',
                mitre: 'T1110.003 - Brute Force: Password Spraying'
            },
            'Pass-the-Ticket': {
                description: 'Detects Pass-the-Ticket via user from multiple IPs',
                logSource: 'Security',
                eventId: 'Event ID 4624',
                criteria: [
                    'Network logon with Kerberos',
                    'Same user from multiple source IPs'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Security\"; ID=4624} | Where-Object { $_.Message -match \"Logon Type:\\s*3\" -and $_.Message -match \"Kerberos\" }',
                mitre: 'T1550.003 - Use Alternate Authentication Material: Pass the Ticket'
            },
            'Rubeus Execution': {
                description: 'Detects Rubeus Kerberos attack tool',
                logSource: 'Sysmon',
                eventId: 'Event ID 1',
                criteria: [
                    'Rubeus.exe or commands: kerberoast, asreproast, asktgt, s4u, golden, silver, ptt'
                ],
                manualQuery: 'Get-WinEvent -FilterHashtable @{LogName=\"Microsoft-Windows-Sysmon/Operational\"; ID=1} | Where-Object { $_.Message -match \"rubeus|kerberoast|asreproast\" }',
                mitre: 'T1558 - Steal or Forge Kerberos Tickets'
            }
        };
        
        function showDetectionLogic(category) {
            const logic = detectionLogicDB[category];
            const modal = document.getElementById('detection-logic-modal');
            const modalTitle = document.getElementById('modal-title');
            const modalBody = document.getElementById('modal-body');
            
            if (!logic) {
                modalTitle.textContent = 'Detection Logic - ' + category;
                modalBody.innerHTML = '<p>Detection logic documentation not available for this category.</p>';
            } else {
                modalTitle.textContent = 'Detection Logic - ' + category;
                
                let criteriaHtml = logic.criteria.map(c => '<li>' + c + '</li>').join('');
                
                modalBody.innerHTML = 
                    '<div class="logic-section">' +
                        '<div class="logic-section-title">Description</div>' +
                        '<div class="logic-item">' +
                            '<div class="logic-item-value">' + logic.description + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="logic-section">' +
                        '<div class="logic-section-title">Log Source</div>' +
                        '<div class="logic-item">' +
                            '<div class="logic-item-label">Log Name</div>' +
                            '<div class="logic-item-value">' + logic.logSource + '</div>' +
                        '</div>' +
                        '<div class="logic-item">' +
                            '<div class="logic-item-label">Event ID</div>' +
                            '<div class="logic-item-value">' + logic.eventId + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="logic-section">' +
                        '<div class="logic-section-title">Detection Criteria</div>' +
                        '<div class="logic-item">' +
                            '<ul style="margin: 0; padding-left: 20px;">' + criteriaHtml + '</ul>' +
                        '</div>' +
                    '</div>' +
                    '<div class="logic-section">' +
                        '<div class="logic-section-title">Manual Query (PowerShell)</div>' +
                        '<div class="logic-item">' +
                            '<div class="logic-item-value" style="font-size: 11px; overflow-x: auto;">' + logic.manualQuery + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="logic-tip">' +
                        '<div class="logic-tip-title">MITRE ATT&CK Reference</div>' +
                        '<div>' + logic.mitre + '</div>' +
                    '</div>';
            }
            
            modal.classList.add('visible');
        }
        
        function closeDetectionLogic() {
            document.getElementById('detection-logic-modal').classList.remove('visible');
        }
        
        function closeModal(event) {
            if (event.target.classList.contains('modal-overlay')) {
                closeDetectionLogic();
            }
        }
        
        // Close modal on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeDetectionLogic();
            }
        });
        
        // Current filter state
        let currentSeverityFilter = 'all';
        let currentSortColumn = -1;
        let currentSortDirection = 'none';
        
        // Initialize filters on page load
        document.addEventListener('DOMContentLoaded', function() {
            populateFilterDropdowns();
        });
        
        // Populate dropdown filters with unique values from table
        function populateFilterDropdowns() {
            const rows = document.querySelectorAll('.finding-row');
            const categories = new Set();
            const sources = new Set();
            const eventIds = new Set();
            
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                if (cells.length >= 6) {
                    categories.add(cells[2].textContent.trim());
                    eventIds.add(cells[4].textContent.trim());
                    sources.add(cells[5].textContent.trim());
                }
            });
            
            populateDropdown('category-filter', Array.from(categories).sort());
            populateDropdown('source-filter', Array.from(sources).sort());
            populateDropdown('eventid-filter', Array.from(eventIds).sort());
        }
        
        function populateDropdown(id, values) {
            const select = document.getElementById(id);
            const currentValue = select.value;
            
            // Keep the first "All" option
            while (select.options.length > 1) {
                select.remove(1);
            }
            
            values.forEach(value => {
                if (value) {
                    const option = document.createElement('option');
                    option.value = value;
                    option.textContent = value;
                    select.appendChild(option);
                }
            });
            
            select.value = currentValue;
        }
        
        function toggleDetails(id) {
            const detailRow = document.getElementById(id);
            const findingRow = detailRow.previousElementSibling;
            
            if (detailRow.classList.contains('visible')) {
                detailRow.classList.remove('visible');
                findingRow.classList.remove('expanded');
            } else {
                document.querySelectorAll('.raw-log-row.visible').forEach(row => {
                    row.classList.remove('visible');
                    row.previousElementSibling.classList.remove('expanded');
                });
                
                detailRow.classList.add('visible');
                findingRow.classList.add('expanded');
            }
        }
        
        function copyToClipboard(id) {
            const content = document.getElementById(id).textContent;
            navigator.clipboard.writeText(content).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.classList.remove('copied');
                }, 2000);
            });
        }
        
        function filterBySeverity(severity) {
            currentSeverityFilter = severity;
            
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            applyFilters();
        }
        
        function applyFilters() {
            const rows = document.querySelectorAll('.finding-row');
            const searchQuery = document.getElementById('search-box').value.toLowerCase();
            const categoryFilter = document.getElementById('category-filter').value;
            const sourceFilter = document.getElementById('source-filter').value;
            const eventIdFilter = document.getElementById('eventid-filter').value;
            
            let visibleCount = 0;
            
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                const severityCell = row.querySelector('td:nth-child(2) span');
                const severityText = severityCell ? severityCell.textContent : '';
                const detailRow = row.nextElementSibling;
                
                const category = cells[2] ? cells[2].textContent.trim() : '';
                const eventId = cells[4] ? cells[4].textContent.trim() : '';
                const source = cells[5] ? cells[5].textContent.trim() : '';
                const rowText = row.textContent.toLowerCase();
                
                // Apply all filters
                const matchesSeverity = currentSeverityFilter === 'all' || severityText === currentSeverityFilter;
                const matchesCategory = !categoryFilter || category === categoryFilter;
                const matchesSource = !sourceFilter || source === sourceFilter;
                const matchesEventId = !eventIdFilter || eventId === eventIdFilter;
                const matchesSearch = !searchQuery || rowText.includes(searchQuery);
                
                if (matchesSeverity && matchesCategory && matchesSource && matchesEventId && matchesSearch) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                    if (detailRow) detailRow.classList.remove('visible');
                }
            });
            
            document.getElementById('visible-count').textContent = visibleCount;
        }
        
        function resetFilters() {
            currentSeverityFilter = 'all';
            
            // Reset severity buttons
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelector('.filter-btn').classList.add('active');
            
            // Reset dropdowns
            document.getElementById('category-filter').value = '';
            document.getElementById('source-filter').value = '';
            document.getElementById('eventid-filter').value = '';
            document.getElementById('search-box').value = '';
            
            // Reset sort indicators
            document.querySelectorAll('th').forEach(th => {
                th.classList.remove('sort-asc', 'sort-desc');
                const icon = th.querySelector('.sort-icon');
                if (icon) icon.textContent = '[=]';
            });
            currentSortColumn = -1;
            currentSortDirection = 'none';
            
            applyFilters();
        }
        
        function sortTable(columnIndex, dataType) {
            const table = document.getElementById('findings-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr.finding-row'));
            const headers = table.querySelectorAll('th');
            
            // Determine sort direction
            if (currentSortColumn === columnIndex) {
                if (currentSortDirection === 'asc') {
                    currentSortDirection = 'desc';
                } else if (currentSortDirection === 'desc') {
                    currentSortDirection = 'none';
                } else {
                    currentSortDirection = 'asc';
                }
            } else {
                currentSortColumn = columnIndex;
                currentSortDirection = 'asc';
            }
            
            // Update header indicators
            headers.forEach((th, idx) => {
                th.classList.remove('sort-asc', 'sort-desc');
                const icon = th.querySelector('.sort-icon');
                if (icon) {
                    if (idx === columnIndex) {
                        if (currentSortDirection === 'asc') {
                            th.classList.add('sort-asc');
                            icon.textContent = '[ASC]';
                        } else if (currentSortDirection === 'desc') {
                            th.classList.add('sort-desc');
                            icon.textContent = '[DESC]';
                        } else {
                            icon.textContent = '[=]';
                        }
                    } else {
                        icon.textContent = '[=]';
                    }
                }
            });
            
            // Sort rows
            if (currentSortDirection !== 'none') {
                rows.sort((a, b) => {
                    const aValue = a.querySelectorAll('td')[columnIndex].textContent.trim();
                    const bValue = b.querySelectorAll('td')[columnIndex].textContent.trim();
                    
                    let comparison = 0;
                    
                    if (dataType === 'date') {
                        comparison = new Date(aValue) - new Date(bValue);
                    } else if (dataType === 'severity') {
                        // Order: MEDIUM (0) -> HIGH (1) -> CRITICAL (2) for ascending
                        const severityOrder = { 'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3 };
                        comparison = (severityOrder[aValue] || -1) - (severityOrder[bValue] || -1);
                    } else {
                        comparison = aValue.localeCompare(bValue);
                    }
                    
                    return currentSortDirection === 'desc' ? -comparison : comparison;
                });
            }
            
            // Re-append rows with their detail rows
            rows.forEach(row => {
                const detailRow = row.nextElementSibling;
                tbody.appendChild(row);
                if (detailRow && detailRow.classList.contains('raw-log-row')) {
                    tbody.appendChild(detailRow);
                }
            });
        }
    </script>
</body>
</html>
"@

    # Write HTML report
    try {
        [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
        Write-Host "`n[+] HTML Report saved to: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to save HTML report: $_" -ForegroundColor Red
    }
    
    # Export findings to CSV as well (with RawLog as JSON)
    $csvPath = $OutputPath -replace '\.html$', '.csv'
    try {
        $findings | Select-Object @{Name='Timestamp';Expression={$_.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")}}, 
            Severity, 
            Category, 
            Description, 
            EventID, 
            Source, 
            Details,
            @{Name='RawLog';Expression={ 
                # Escape the raw log properly for JSON
                $escaped = $_.RawLog -replace '\\', '\\' -replace '"', '\"' -replace "`r", '\r' -replace "`n", '\n' -replace "`t", '\t'
                "{`"EventLog`":`"$escaped`"}"
            }} | Export-Csv -Path $csvPath -NoTypeInformation -Force -Encoding UTF8
        Write-Host "[+] CSV Report saved to: $csvPath" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to save CSV report: $_" -ForegroundColor Red
    }
} else {
    Write-Host "`n[+] No suspicious findings detected in the analyzed timeframe." -ForegroundColor Green
}

Write-Host "`n[*] Investigation complete." -ForegroundColor Cyan