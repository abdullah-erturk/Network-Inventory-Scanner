<# : hybrid batch + powershell script
@powershell -noprofile -ExecutionPolicy Bypass -c "$param='%*';$ScriptPath='%~f0';iex((Get-Content('%~f0') -Raw))"
@echo off
exit /b
#>

# Network Inventory Scanner
# Bu betik ağdaki cihazları çok hızlı(paralel) tarar, CSV/HTML çıktı verir, güvenlik ve MAC vendor analizi yapar.
# Kodlama dili İngilizce, yorumlar Türkçedir.

$ErrorActionPreference = "SilentlyContinue"

# Konsol çıktılarını evrensel UTF-8 standardına çekelim (Çince/Arapça/Kirilce karakter destekleri için)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Gerekli .NET kütüphanelerini yükle
Add-Type -AssemblyName System.Windows.Forms

# --- Fonksiyonlar ---

Function Get-IPRange {
    Param([string]$InputStr)
    if (-not $InputStr) { return $null }
    $InputStr = $InputStr.Trim().Trim('"').Trim("'")
    if ($InputStr -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)") {
        try {
            $baseIpStr = $Matches[1]; $maskLength = [int]$Matches[2]
            $mask = [Convert]::ToUInt32(("1" * $maskLength).PadRight(32, "0"), 2)
            $invMask = [Convert]::ToUInt32(("0" * $maskLength).PadRight(32, "1"), 2)
            $ip = [System.Net.IPAddress]::Parse($baseIpStr)
            $ipBytes = $ip.GetAddressBytes()
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ipBytes) }
            $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
            $network = $ipInt -band $mask
            $broadcast = $network -bor $invMask
            if ($maskLength -eq 32) { return @($baseIpStr) }
            $hosts = @()
            for ($i = $network; $i -le $broadcast; $i++) {
                $bytes = [BitConverter]::GetBytes([uint32]$i)
                if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
                $hosts += ([System.Net.IPAddress]$bytes).IPAddressToString
                if ($hosts.Count -gt 512) { break }
            }
            return $hosts
        } catch { return $null }
    }
    try {
        $ip = [System.Net.IPAddress]::Parse($InputStr)
        return @($ip.IPAddressToString)
    } catch { return $null }
}

Function Get-UserSelectedSubnet {
    Write-Host "--- Network Adapter Selection ---" -ForegroundColor Cyan
    $ValidAdapters = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
        $_.IPAddress -notmatch "^127\." -and 
        $_.IPAddress -notmatch "^169\.254" -and 
        $_.AddressState -eq "Preferred"
    })
    if ($ValidAdapters.Count -eq 0) {
        Write-Host "No active network adapters found." -ForegroundColor Red
        return $null
    }
    for ($i = 0; $i -lt $ValidAdapters.Count; $i++) {
        $alias = $ValidAdapters[$i].InterfaceAlias
        $addr = $ValidAdapters[$i].IPAddress
        Write-Host "[$($i + 1)] $alias - $addr"
    }
    $Selection = Read-Host "`nEnter adapter number [1-$($ValidAdapters.Count)] or target IP/Subnet directly (e.g. 192.168.1.0/24)"
    
    # Doğrudan IP veya Subnet girildiyse
    if ($Selection -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
        return $Selection
    }
    
    # Numarayla Adaptör seçildiyse
    if ($Selection -match "^\d+$") {
        $Idx = [int]$Selection - 1
        if ($Idx -ge 0 -and $Idx -lt $ValidAdapters.Count) {
            $Selected = $ValidAdapters[$Idx]
            $ip = $Selected.IPAddress
            $octets = $ip.Split('.')
            return "$($octets[0]).$($octets[1]).$($octets[2]).0/24"
        }
    }
    return $null
}

Function Get-LocalMACs {
    $LocalIPs = @{}
    Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object {
        $ip = $_.IPAddress
        $alias = $_.InterfaceAlias
        $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
        if ($adapter) {
            $LocalIPs[$ip] = $adapter.MacAddress.Replace("-", ":")
        }
    }
    return $LocalIPs
}

$OUITable = @{
    # Cisco
    "00000C"="Cisco"; "000142"="Cisco"; "000143"="Cisco"; "00107B"="Cisco"; "001201"="Cisco"; "00141C"="Cisco"
    "001B0C"="Cisco"; "001C58"="Cisco"; "001DFA"="Cisco"; "001E13"="Cisco"; "001EBD"="Cisco"; "001F00"="Cisco"
    # Apple
    "000393"="Apple"; "000A27"="Apple"; "001124"="Apple"; "001451"="Apple"; "0025BC"="Apple"; "003E00"="Apple"
    "04E536"="Apple"; "1040F3"="Apple"; "14109F"="Apple"; "1C5CFA"="Apple"; "28CFE9"="Apple"; "34159E"="Apple"
    "480FCF"="Apple"; "4C3275"="Apple"; "5855CA"="Apple"; "60FB42"="Apple"; "6476BA"="Apple"; "6CB158"="Apple"
    "8C2937"="Apple"; "98E0D9"="Apple"; "A4D18C"="Apple"; "B03495"="Apple"; "C8E0EB"="Apple"; "D02598"="Apple"
    "E4CE8F"="Apple"; "F0C731"="Apple"; "F81EAF"="Apple"
    # Microsoft
    "00155D"="Microsoft"; "0003FF"="Microsoft"; "001DD8"="Microsoft"; "281878"="Microsoft"; "6045BD"="Microsoft"
    "7C1E52"="Microsoft"; "B4F547"="Microsoft"; "C0335E"="Microsoft"; "EC8350"="Microsoft"
    # VMware
    "000569"="VMware"; "000C29"="VMware"; "001C14"="VMware"; "005056"="VMware"
    # Intel
    "0002B3"="Intel"; "000347"="Intel"; "000E0C"="Intel"; "001111"="Intel"; "0013E8"="Intel"; "001517"="Intel"
    "001B21"="Intel"; "001CC4"="Intel"; "001E67"="Intel"; "00215C"="Intel"; "002314"="Intel"; "0024D6"="Intel"
    "3C970E"="Intel"; "58946B"="Intel"; "606720"="Intel"; "808600"="Intel"; "A0A8CD"="Intel"; "CCB0DA"="Intel"
    "E4F89C"="Intel"; "F4B520"="Intel"; "FCF8AE"="Intel"
    # Samsung
    "001599"="Samsung"; "001E90"="Samsung"; "00214C"="Samsung"; "0023CF"="Samsung"; "0024E4"="Samsung"
    "002639"="Samsung"; "14F42A"="Samsung"; "187AF5"="Samsung"; "244B03"="Samsung"; "2CD05A"="Samsung"
    "38EEDD"="Samsung"; "444CE6"="Samsung"; "5001D9"="Samsung"; "5C0A5B"="Samsung"; "64A2F9"="Samsung"
    "784B87"="Samsung"; "8018A7"="Samsung"; "8C8E76"="Samsung"; "9C0298"="Samsung"; "A80600"="Samsung"
    "B46293"="Samsung"; "B8BBAF"="Samsung"; "C81BFF"="Samsung"; "D4685D"="Samsung"; "DC7144"="Samsung"
    "E01EE1"="Samsung"; "EC1F72"="Samsung"; "F40304"="Samsung"; "FCF136"="Samsung"
    # Huawei
    "001882"="Huawei"; "001E10"="Huawei"; "0022A1"="Huawei"; "00259E"="Huawei"; "00464B"="Huawei"
    "0819A6"="Huawei"; "104780"="Huawei"; "14B968"="Huawei"; "1CBDF9"="Huawei"; "20F3A3"="Huawei"
    "286ED4"="Huawei"; "3400A3"="Huawei"; "3C8C40"="Huawei"; "4455C4"="Huawei"; "4C8BEE"="Huawei"
    "548998"="Huawei"; "5C4CA9"="Huawei"; "646CBA"="Huawei"; "707BD2"="Huawei"; "80B686"="Huawei"
    "8853D4"="Huawei"; "9CD073"="Huawei"; "A4DCAF"="Huawei"; "AC853D"="Huawei"; "BC7670"="Huawei"
    "C4A366"="Huawei"; "E0247F"="Huawei"; "F4559C"="Huawei"; "FCB2F4"="Huawei"
    # Xiaomi
    "143004"="Xiaomi"; "28E31F"="Xiaomi"; "38A4ED"="Xiaomi"; "508A06"="Xiaomi"; "58C38B"="Xiaomi"
    "60F5F6"="Xiaomi"; "640980"="Xiaomi"; "74E2F5"="Xiaomi"; "7C1DDA"="Xiaomi"; "8C4500"="Xiaomi"
    "9C99A0"="Xiaomi"; "ACF7F3"="Xiaomi"; "B0E235"="Xiaomi"; "C45A3C"="Xiaomi"; "C8F742"="Xiaomi"
    "D4970B"="Xiaomi"; "E0B94D"="Xiaomi"; "F48BC1"="Xiaomi"; "FC017C"="Xiaomi"
    # TP-Link
    "000A18"="TP-Link"; "001D0F"="TP-Link"; "002111"="TP-Link"; "002315"="TP-Link"; "002521"="TP-Link"
    "100DBA"="TP-Link"; "14CC20"="TP-Link"; "1CA59A"="TP-Link"; "28DE65"="TP-Link"; "30B5C2"="TP-Link"
    "34E894"="TP-Link"; "4C0143"="TP-Link"; "5495A3"="TP-Link"; "5CE8EF"="TP-Link"; "6038E0"="TP-Link"
    "645601"="TP-Link"; "68FF7B"="TP-Link"; "704F57"="TP-Link"; "882593"="TP-Link"; "98DA06"="TP-Link"
    "B09575"="TP-Link"; "C006C3"="TP-Link"; "D46E0E"="TP-Link"; "E41629"="TP-Link"; "F4F26D"="TP-Link"
    "FAA1D6"="TP-Link"
    # Realtek
    "0005D2"="Realtek"; "000A3A"="Realtek"; "0014D1"="Realtek"; "001AA9"="Realtek"; "001CE1"="Realtek"
    "00E04C"="Realtek"; "525400"="Realtek" # QEMU commonly uses Realtek
    # Asus
    "000C6E"="Asus"; "00112F"="Asus"; "0015F2"="Asus"; "001A8C"="Asus"; "001BFC"="Asus"; "001E8C"="Asus"
    "002215"="Asus"; "00E018"="Asus"; "049226"="Asus"; "08606E"="Asus"; "10BF48"="Asus"; "14DAE9"="Asus"
    "3085A9"="Asus"; "38D547"="Asus"; "4C7CF4"="Asus"; "509A4C"="Asus"; "60A44C"="Asus"; "74D02B"="Asus"
    "C86000"="Asus"; "F07959"="Asus"
    # HP
    "000E7F"="HP"; "00110A"="HP"; "001438"="HP"; "001560"="HP"; "001708"="HP"; "0018FE"="HP"
    "001B78"="HP"; "001E0B"="HP"; "00215A"="HP"; "00237D"="HP"; "002481"="HP"; "0025B3"="HP"
    "002655"="HP"; "0030C1"="HP"; "0060B0"="HP"
    # Dell
    "001422"="Dell"; "001E4F"="Dell"; "00219B"="Dell"; "002219"="Dell"; "0023AE"="Dell"; "0024E8"="Dell"
    "0026B9"="Dell"; "00B0D0"="Dell"; "0CB2B7"="Dell"; "109836"="Dell"; "14FEB5"="Dell"; "1866DA"="Dell"
    "30F772"="Dell"; "4C3488"="Dell"; "5C260A"="Dell"; "805609"="Dell"; "90B11C"="Dell"; "B82A72"="Dell"
    "D4AE52"="Dell"; "F8B156"="Dell"
    # Netgear
    "00095B"="Netgear"; "000FB5"="Netgear"; "00146C"="Netgear"; "00184D"="Netgear"; "001B2F"="Netgear"
    "001E2A"="Netgear"; "00223F"="Netgear"; "0024B2"="Netgear"; "0026F2"="Netgear"
    # Sony
    "00014A"="Sony"; "000A13"="Sony"; "001315"="Sony"; "0019C5"="Sony"; "00248A"="Sony"
    "18002D"="Sony"; "2840D3"="Sony"; "3C0754"="Sony"; "54429E"="Sony"; "709E29"="Sony"; "B4232C"="Sony"
    # LG
    "000E39"="LG"; "0018C5"="LG"; "001C62"="LG"; "001E04"="LG"; "0021FB"="LG"
    # Synology
    "001132"="Synology"; "001131"="Synology"
    # Parallels & VirtualBox
    "001C42"="Parallels"; "080027"="VirtualBox"
    # Raspberry Pi
    "B827EB"="RaspberryPi"; "DCA632"="RaspberryPi"; "28CDC1"="RaspberryPi"; "E45F01"="RaspberryPi"
    # Broadcom
    "000AD0"="Broadcom"; "001018"="Broadcom"; "0014FD"="Broadcom"; "001A11"="Broadcom"
    # D-Link
    "00055D"="D-Link"; "000D88"="D-Link"; "000F3D"="D-Link"; "001195"="D-Link"; "001346"="D-Link"; "0015E9"="D-Link"
    # Ubiquiti
    "002722"="Ubiquiti"; "0418D6"="Ubiquiti"; "18E829"="Ubiquiti"; "24A43C"="Ubiquiti"; "44D9E7"="Ubiquiti"
    "602232"="Ubiquiti"; "68D79A"="Ubiquiti"; "788A20"="Ubiquiti"; "802AA8"="Ubiquiti"; "B4FBE4"="Ubiquiti"
    "F09FC2"="Ubiquiti"
    # Lenovo
    "00145E"="Lenovo"; "10D38A"="Lenovo"; "207693"="Lenovo"; "3C18A0"="Lenovo"; "488A58"="Lenovo"
    "001B59"="Lenovo"
}

# Runspace (Paralel İşlem) Bloğu
$ScanBlock = {
    param($IP, $CommonPorts, $LocalMAC, $OUITable)
    $ErrorActionPreference = "SilentlyContinue"
    $Result = [PSCustomObject]@{
        IPAddress  = $IP
        IsAlive    = $false
        MACAddress = "N/A"
        Hostname   = "N/A"
        OSGuess    = "Unknown"
        Vendor     = "Unknown"
        OpenPorts  = ""
        Banner     = ""
        Risk       = "Low"
    }
    
    # 1. Ping (.NET sınıfı hızlı asenkron yapı)
    $Ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $Reply = $Ping.Send($IP, 200) # 200ms timeout
        if ($Reply.Status -eq 'Success') {
            $Result.IsAlive = $true
            $TTL = if ($Reply.Options) { $Reply.Options.Ttl } else { 0 }
        } else {
            return $Result
        }
    } catch { return $Result }

    # 2. Port Tarama ve Banner Grabbing
    $OpenPortsList = @()
    $BannerStr = @()
    foreach ($p in $CommonPorts) {
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $Connect = $TcpClient.BeginConnect($IP, $p, $null, $null)
            if ($Connect.AsyncWaitHandle.WaitOne(40, $false)) {
                if ($TcpClient.Connected) {
                    $OpenPortsList += $p
                    # Banner Grabbing
                    if ($p -in @(21, 22, 80)) {
                        $Stream = $TcpClient.GetStream()
                        if ($p -eq 80) {
                            $Writer = New-Object System.IO.StreamWriter($Stream)
                            try { $Writer.WriteLine("HEAD / HTTP/1.0`r`n`r`n"); $Writer.Flush() }
                            finally {}
                            Start-Sleep -Milliseconds 80
                        }
                        $Stream.ReadTimeout = 100
                        if ($Stream.DataAvailable) {
                            $Buffer = New-Object byte[] 128
                            $BytesRead = $Stream.Read($Buffer, 0, $Buffer.Length)
                            if ($BytesRead -gt 0) {
                                $bText = [System.Text.Encoding]::ASCII.GetString($Buffer, 0, $BytesRead).Trim() -replace '\s+', ' '
                                if ($bText.Length -gt 15) { $bText = $bText.Substring(0, 15) }
                                $BannerStr += "$($p):$bText"
                            }
                        }
                    }
                }
            }
        } catch {} finally {
            if ($TcpClient) { $TcpClient.Close(); $TcpClient.Dispose() }
        }
    }
    if ($OpenPortsList.Count -gt 0) { $Result.OpenPorts = $OpenPortsList -join "," } else { $Result.OpenPorts = "None" }
    if ($BannerStr.Count -gt 0) { $Result.Banner = $BannerStr -join " | " }

    # 3. OS ve Cihaz Tipi Tahmini
    if ($OpenPortsList -contains 9100 -or $OpenPortsList -contains 515 -or $OpenPortsList -contains 631) { $Result.OSGuess = "Printer" }
    elseif ($OpenPortsList -contains 445 -or $OpenPortsList -contains 139 -or $OpenPortsList -contains 135) { $Result.OSGuess = "Windows" }
    elseif ($OpenPortsList -contains 23 -or $OpenPortsList -contains 161 -or $OpenPortsList -contains 2000) { $Result.OSGuess = "Switch/Network Dev" }
    elseif ($IP -match "\.(1|254)$") { $Result.OSGuess = "Network Device/Gateway" }
    elseif ($TTL -gt 0) {
        if ($TTL -le 64) { $Result.OSGuess = "Linux/macOS/Android" }
        elseif ($TTL -le 128) { $Result.OSGuess = "Windows" }
        elseif ($TTL -le 255) { $Result.OSGuess = "Network Device" }
    }
    elseif ($OpenPortsList -contains 22) { $Result.OSGuess = "Linux/Unix (SSH)" }
    elseif ($OpenPortsList -contains 80 -or $OpenPortsList -contains 443) { $Result.OSGuess = "Web Server/IoT" }

    # 4. MAC Adresi ve Vendor Tespiti
    if ($LocalMAC) {
        $Result.MACAddress = $LocalMAC
    } else {
        $ARP = arp -a $IP | Out-String
        if ($ARP -match "([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})") {
            $Result.MACAddress = $Matches[1].ToUpper().Replace("-", ":")
        }
    }
    if ($Result.MACAddress -ne "N/A" -and $Result.MACAddress.Length -ge 8) {
        $Prefix = $Result.MACAddress.Substring(0, 8).Replace(":", "")
        if ($OUITable.ContainsKey($Prefix)) {
            $Result.Vendor = $OUITable[$Prefix]
        }
    }

    # 5. Hostname Çözümleme
    try {
        $Name = [System.Net.Dns]::GetHostEntry($IP).HostName
        if ($Name -notmatch "^\d{1,3}\.\d{1,3}") { $Result.Hostname = $Name }
    } catch {}
    if ($Result.Hostname -eq "N/A" -or $Result.Hostname -eq "") {
        $nbt = nbtstat -A $IP
        foreach ($line in $nbt) {
            # Faklı dillerde "UNIQUE" ibaresi değişir (örn: BENZERSİZ, EINSTEIN vb.), bu yüzden sadece <00> tag araması yapıyoruz.
            if ($line -match "^\s+([^\s]+)\s+<00>") {
                $Result.Hostname = $Matches[1].Trim()
                break
            }
        }
    }

    # 6. Güvenlik/Risk Analizi
    $score = 0
    if ($OpenPortsList -contains 23) { $score += 2 } # Telnet
    if ($OpenPortsList -contains 21) { $score += 1 } # FTP
    if ($OpenPortsList -contains 445) {
        $Test = Test-Path "\\$IP\C$" -ErrorAction SilentlyContinue
        if ($Test) { $score += 3; $Result.Banner += " [C$ OPEN!]" }
    }
    if ($score -ge 3) { $Result.Risk = "High" }
    elseif ($score -ge 1) { $Result.Risk = "Medium" }

    return $Result
}

# --- Main Program ---
$Host.UI.RawUI.WindowTitle = "NetScan | made by Abdullah ERTURK"
Clear-Host
Write-Host
Write-Host "	github.com/abdullah-erturk" -ForegroundColor Yellow
Write-Host
Write-Host "	erturk.netlify.app" -ForegroundColor Yellow
Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "         Network Inventory Scanner       " -ForegroundColor White -BackgroundColor Blue
Write-Host "=========================================`n" -ForegroundColor Cyan

$TargetInput = $param
if (-not $TargetInput) {
    $TargetInput = Get-UserSelectedSubnet
    if (-not $TargetInput) {
        Write-Host "[*] Manual Target Entry Fallback (e.g. 192.168.1.0/24)" -ForegroundColor Yellow
        $TargetInput = Read-Host "Enter Target"
    }
    if (-not $TargetInput) { Write-Host "`n[!] No target provided." -ForegroundColor Red; pause; exit }
}

$LocalMACs = Get-LocalMACs
$Targets = Get-IPRange $TargetInput
if (-not $Targets) { Write-Host "`n[!] Invalid target: '$TargetInput'" -ForegroundColor Red; pause; exit }

Write-Host "`n[*] Target: $TargetInput ($($Targets.Count) addresses)"
Write-Host "[*] Parallel Scanning Mode (Runspaces Active)" -ForegroundColor Green
Write-Host "[*] Ports: 21, 22, 23, 80, 443, 445, 515, 631, 9100, 135, 139, 161, 2000, 3389, 8080"
Write-Host "[*] (Press Ctrl+C to stop)`n" -ForegroundColor Gray

$CommonPorts = @(21, 22, 23, 80, 443, 445, 515, 631, 9100, 135, 139, 161, 2000, 3389, 8080)

$sw = [Diagnostics.Stopwatch]::StartNew()
# Runspace Pool Ayarları
$MaxThreads = [math]::Min(100, [Environment]::ProcessorCount * 5)
$Pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
$Pool.Open()
$Jobs = @()

foreach ($IP in $Targets) {
    $LocalM = if ($LocalMACs.ContainsKey($IP)) { $LocalMACs[$IP] } else { $null }
    $PS = [powershell]::Create().AddScript($ScanBlock).AddArgument($IP).AddArgument($CommonPorts).AddArgument($LocalM).AddArgument($OUITable)
    $PS.RunspacePool = $Pool
    $Jobs += [PSCustomObject]@{
        IP     = $IP
        Pipe   = $PS
        Result = $PS.BeginInvoke()
    }
}

# İlerleme Takibi
$Total = $Targets.Count
$Completed = 0
while (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0) {
    $Completed = ($Jobs | Where-Object { $_.Result.IsCompleted }).Count
    if ($Total -gt 1) {
        $Progress = [math]::Round(($Completed / $Total) * 100)
        Write-Progress -Activity "Mass Parallel Scanning " -Status "Completed: $Completed/$Total" -PercentComplete $Progress
    }
    Start-Sleep -Milliseconds 100
}
Write-Progress -Activity "Mass Parallel Scanning " -Completed

# Sonuçları Toplama ve Ekrana Bastırma
$TableOutput = @()
$seqNo = 1

# Başlık Yazdırma
$fmtIP     = "IP Address".PadRight(15)
$fmtName   = "Hostname".PadRight(25)
$fmtOS     = "OS / Device".PadRight(22)
$fmtVen    = "Vendor".PadRight(12)
$fmtPort   = "Ports/Risk".PadRight(18)
Write-Host "$fmtIP | $fmtName | $fmtOS | $fmtVen | $fmtPort" -ForegroundColor Cyan
Write-Host ("-"*98) -ForegroundColor Cyan

foreach ($Job in $Jobs) {
    $Res = $Job.Pipe.EndInvoke($Job.Result)
    $Job.Pipe.Dispose()
    if ($Res -and $Res.IsAlive) {
        
        $cColor = "Green"
        if ($Res.Risk -eq "High") { $cColor = "Red" }
        elseif ($Res.Risk -eq "Medium") { $cColor = "Yellow" }
        
        $dIP = $Res.IPAddress.PadRight(15)
        $dN = $Res.Hostname
        if ($dN.Length -gt 25) { $dN = $dN.Substring(0, 22) + "..." }
        $dN = $dN.PadRight(25)
        $dOS = $Res.OSGuess
        if ($dOS.Length -gt 22) { $dOS = $dOS.Substring(0, 19) + "..." }
        $dOS = $dOS.PadRight(22)
        $dVen = $Res.Vendor
        if ($dVen.Length -gt 12) { $dVen = $dVen.Substring(0, 11) + "." }
        $dVen = $dVen.PadRight(12)
        
        $pStr = $Res.OpenPorts
        if ($Res.Risk -ne "Low") { $pStr += " [!$($Res.Risk)]" }
        if ($pStr.Length -gt 35) { $pStr = $pStr.Substring(0, 32) + "..." }
        
        Write-Host "$dIP | $dN | $dOS | $dVen | $pStr" -ForegroundColor $cColor
        
        $TableOutput += [PSCustomObject]@{
            "No"          = $seqNo
            "IP Address"  = $Res.IPAddress
            "MAC Address" = $Res.MACAddress
            "Vendor"      = $Res.Vendor
            "Hostname"    = $Res.Hostname
            "OS"          = $Res.OSGuess
            "Open Ports"  = $Res.OpenPorts
            "Risk"        = $Res.Risk
            "Banner"      = $Res.Banner
        }
        $seqNo++
    }
}
$Pool.Close()
$Pool.Dispose()
$sw.Stop()

# Tabloyu IP sırasına göre diz ve sıra numaralarını güncelle
if ($TableOutput) {
    $TableOutput = $TableOutput | Sort-Object { [System.Version]$_."IP Address" }
    for ($i=0; $i -lt $TableOutput.Count; $i++) { $TableOutput[$i].No = $i + 1 }
}

# Değişim (Diff) Kaydı
$DiffMsg = ""
$LastScanPath = "$env:TEMP\netscan_last.csv"
if (Test-Path $LastScanPath) {
    $OldData = Import-Csv $LastScanPath -ErrorAction SilentlyContinue
    if ($TableOutput) {
        $NewIPs = $TableOutput."IP Address"
        $OldIPs = if ($OldData) { $OldData."IP Address" } else { @() }
        $Added = $NewIPs | Where-Object { $_ -notin $OldIPs }
        if ($Added) { $DiffMsg += "`n[+] NEW DEVICES DETECTED: $($Added -join ', ')" }
        $Removed = $OldIPs | Where-Object { $_ -notin $NewIPs }
        if ($Removed) { $DiffMsg += "`n[-] DEVICES GONE: $($Removed -join ', ')" }
    }
}
# Gelecek için mevcut durumu kaydet
if ($TableOutput) { $TableOutput | Export-Csv -Path $LastScanPath -NoTypeInformation -Force }

if ($TableOutput) {
    Write-Host "`n[#] Scan Summary (Total Found: $($TableOutput.Count) | Time: $($sw.Elapsed.TotalSeconds.ToString('F2'))s)" -ForegroundColor Cyan
    $TableOutput | Format-Table -AutoSize | Out-String | Write-Host
    if ($DiffMsg) { Write-Host $DiffMsg -ForegroundColor Magenta }
    
    Write-Host "`nScan complete. Press 'S' to Save results, or any other key to Exit." -ForegroundColor Yellow
    $Key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    if ($Key.Character -eq 's' -or $Key.Character -eq 'S') {
        $SaveFile = New-Object System.Windows.Forms.SaveFileDialog
        $SaveFile.Filter = "HTML Report (*.html)|*.html|Text files (*.txt)|*.txt"
        $SaveFile.Title = "Save Scan Results"
        $SaveFile.FileName = "Network_Scan_Report_$(Get-Date -Format 'dd.MM.yy')"
        
        if ($SaveFile.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $Ext = [System.IO.Path]::GetExtension($SaveFile.FileName).ToLower()
            if ($Ext -eq ".html") {
                $HtmlHead = @"
<style>
body{font-family:sans-serif;background:#1e1e1e;color:#ddd;padding:20px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #444;padding:8px}
th{background:#333}
</style>
<script>
window.onload=function(){
  document.querySelectorAll('td').forEach(function(td){
    if(td.textContent==='High'){td.style.color='#ff4444';td.style.fontWeight='bold'}
    else if(td.textContent==='Medium'){td.style.color='#ffaa00'}
    else if(td.textContent==='Low'){td.style.color='#44ff44'}
  })
}
</script>
"@
                $DiffHtml = if ($DiffMsg) { "<pre style='color:#ffaa00'>$DiffMsg</pre>" } else { "" }
                $TableOutput | ConvertTo-Html -Head $HtmlHead -Title "NetScan Report" -PreContent "<h2>github.com/abdullah-erturk</h2><h2>Network Scan: $TargetInput</h2><p>Date: $(Get-Date)</p>$DiffHtml" | Out-File $SaveFile.FileName -Encoding utf8
            }
            else {
                # .txt
                $Report = "github.com/abdullah-erturk`r`nNetwork Scan Report`r`nGenerated on: $(Get-Date)`r`nTarget: $TargetInput`r`n"
                if ($DiffMsg) { $Report += "$DiffMsg`r`n" }
                $Report += "================================================================================`r`n"
                $Report += ($TableOutput | Format-Table -AutoSize | Out-String)
                $Report | Out-File $SaveFile.FileName -Encoding utf8
            }
            Write-Host "`n[+] Report saved to: $($SaveFile.FileName)" -ForegroundColor Green
            Start-Sleep -Seconds 2
        }
    }
} else {
    Write-Host "`n[-] No active hosts found." -ForegroundColor Yellow
    pause
}
