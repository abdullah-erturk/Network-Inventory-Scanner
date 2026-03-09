<div align="center">

<a href="https://buymeacoffee.com/abdullaherturk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

# 🔍 NetScan — Network Inventory Scanner

**Ağ Envanter Tarayıcı / Network Inventory Scanner**

![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge)
![Tech](https://img.shields.io/badge/Tech-Batch_&_PowerShell-blue?style=for-the-badge)
[![Open Source?](https://img.shields.io/badge/Open%20source%3F-Of%20course%21%20%E2%9D%A4-009e0a.svg?style=flat)](https://github.com/abdullah-erturk/Office-365-Enterprise-Setup)

![sample](https://github.com/abdullah-erturk/Network-Inventory-Scanner/blob/main/previev.jpg)

</div>

---

## Link:

[![Stable?](https://img.shields.io/badge/Release-v1.svg?style=flat)](https://github.com/abdullah-erturk/Network-Inventory-Scanner/archive/refs/heads/main.zip)

<details>
<summary><strong>Türkçe Tanıtım</strong></summary>

### 📌 Nedir?

**NetScan**, Windows ortamında çalışan, kurulum gerektirmeyen, hibrit `.bat` + PowerShell mimarisiyle yazılmış gelişmiş bir ağ envanter tarama aracıdır. Çift tıkla çalışır, ağdaki tüm aktif cihazları saniyeler içinde tespit eder.

---

### ⚙️ Nasıl Çalışır?

Betik, 6 aşamalı bir tarama zinciri uygular:

**1. Adaptör Seçimi**
Sistemdeki aktif ağ adaptörleri listelenir. Kullanıcı bir adaptör seçer; betik otomatik olarak o adaptörün `/24` alt ağını hedef alır.

**2. Paralel Ping (Runspace Pool)**
Tüm IP adresleri aynı anda `.NET NetworkInformation.Ping` sınıfıyla taranır. `ProcessorCount × 5` kadar iş parçacığı eşzamanlı çalışır; 254 adreslik bir `/24` ağ yalnızca birkaç saniyede tamamlanır.

**3. Port Tarama & Banner Grabbing**
Aktif bulunan her cihazda 15 yaygın port (`21, 22, 23, 80, 443, 445, 515, 631, 9100, 135, 139, 161, 2000, 3389, 8080`) TCP bağlantısıyla test edilir. FTP, SSH ve HTTP portlarında bağlantı kurulduğunda servis başlık bilgisi (banner) okunur.

**4. OS & Cihaz Tipi Tahmini**
TTL değeri ve açık port kombinasyonu analiz edilerek cihaz işletim sistemi ve tipi tahmin edilir:
- `TTL ≤ 64` → Linux / macOS / Android
- `TTL ≤ 128` → Windows
- Port 9100/515/631 → Yazıcı
- Port 23/161/2000 → Switch / Ağ Cihazı

**5. MAC Adresi & Üretici Tespiti**
ARP tablosundan MAC adresi okunur. İlk 3 byte (OUI) yerleşik veritabanıyla karşılaştırılarak üretici (Cisco, Apple, Samsung, Huawei vb.) tespit edilir. Yerel makine için doğrudan adaptör sürücüsünden alınır.

**6. Güvenlik & Risk Analizi**
Her cihaz için risk skoru hesaplanır:
- Telnet (port 23) açık → `Medium`
- FTP (port 21) açık → `Medium`
- SMB (port 445) açık **ve** `C$` paylaşımına erişilebilir → `High`

Sonuçlar konsolda renk kodlu gösterilir: 🟢 Düşük · 🟡 Orta · 🔴 Yüksek

---

### 🆕 Değişim Tespiti (Diff)

Her tarama sonucu `%TEMP%\netscan_last.csv` dosyasına kaydedilir. Bir sonraki taramada yeni eklenen veya kaybolan cihazlar otomatik olarak raporlanır.

---

### 💾 Rapor Kaydetme

Tarama tamamlandıktan sonra `S` tuşuna basarak sonuçları kaydedebilirsiniz:

| Format | İçerik |
|--------|--------|
| `.html` | Dark-theme, Risk renk kodlamalı, diff bölümlü interaktif rapor |
| `.txt`  | Düz metin, Format-Table çıktısı |

---

### 🖥️ Kullanım Alanları

- **Sistem yöneticileri** — Kurumsal ağ envanteri ve yetkisiz cihaz tespiti
- **BT güvenlik ekipleri** — Periyodik ağ taraması, risk tespiti, Telnet/FTP gibi güvensiz servislerin tespiti
- **Ağ mühendisleri** — Yeni kurulum sonrası cihaz doğrulama
- **Ev / SOHO kullanıcıları** — Kendi ağına bağlı cihazları görme
- **Penetrasyon testçileri** — Hızlı keşif (reconnaissance) aşaması
- **Öğrenciler / eğitim** — Ağ protokolleri ve tarama yöntemlerini öğrenme

---

### 🚀 Kullanım

```batch
# Çift tıkla çalıştır — adaptör seçim menüsü açılır

# Ya da hedef doğrudan argüman olarak verilebilir:
netscan.bat 192.168.1.0/24
netscan.bat 10.0.0.15
```

**Gereksinimler:** Windows 7+ · PowerShell 5.1+ · Yönetici yetkisi (ARP/NetBIOS için önerilir)

---

### 📊 Örnek Çıktı

```
=========================================
         Network Inventory Scanner
=========================================

[*] Target: 192.168.1.0/24 (256 addresses)
[*] Parallel Scanning Mode (Runspaces Active)

IP Address      | Hostname                  | OS / Device            | Vendor       | Ports/Risk
------------------------------------------------------------------------------------------------
192.168.1.1     | router.local              | Network Device/Gateway | TP-Link      | 80,443
192.168.1.5     | DESKTOP-AB12C             | Windows                | Intel        | 135,445,3389
192.168.1.12    | macbook-pro.local         | Linux/macOS/Android    | Apple        | 22,80
192.168.1.20    | HP-LaserJet               | Printer                | HP           | 80,9100
192.168.1.33    | N/A                       | Windows                | Unknown      | 23,21 [!High]

[#] Scan Summary (Total Found: 5 | Time: 8.43s)

[+] NEW DEVICES DETECTED: 192.168.1.33
```

</details>

<details>
<summary><strong>English Description</strong></summary>

### 📌 What is it?

**NetScan** is an advanced network inventory scanner for Windows, built with a hybrid `.bat` + PowerShell architecture. No installation required — just double-click. It detects all active devices on the network within seconds.

---

### ⚙️ How It Works

The script runs a 6-stage scanning pipeline:

**1. Adapter Selection**
Active network adapters are listed. The user selects one; the script automatically targets the adapter's `/24` subnet.

**2. Parallel Ping (Runspace Pool)**
All IP addresses are scanned simultaneously using `.NET NetworkInformation.Ping`. A thread pool of `ProcessorCount × 5` workers runs concurrently — a full `/24` network (254 hosts) completes in just a few seconds.

**3. Port Scanning & Banner Grabbing**
For each live host, 15 common ports (`21, 22, 23, 80, 443, 445, 515, 631, 9100, 135, 139, 161, 2000, 3389, 8080`) are tested via TCP. Service banners are captured for FTP, SSH, and HTTP connections.

**4. OS & Device Type Detection**
TTL value and open port combinations are analyzed to estimate the operating system and device type:
- `TTL ≤ 64` → Linux / macOS / Android
- `TTL ≤ 128` → Windows
- Port 9100/515/631 → Printer
- Port 23/161/2000 → Switch / Network Device

**5. MAC Address & Vendor Lookup**
MAC addresses are read from the ARP table. The first 3 bytes (OUI) are matched against a built-in database to identify the manufacturer (Cisco, Apple, Samsung, Huawei, etc.). For the local machine, the adapter driver is queried directly.

**6. Security & Risk Analysis**
A risk score is calculated for each device:
- Telnet (port 23) open → `Medium`
- FTP (port 21) open → `Medium`
- SMB (port 445) open **and** `C$` share accessible → `High`

Results are displayed in color-coded output: 🟢 Low · 🟡 Medium · 🔴 High

---

### 🆕 Change Detection (Diff)

Every scan result is saved to `%TEMP%\netscan_last.csv`. On the next run, newly added or missing devices are automatically reported.

---

### 💾 Report Export

After scanning, press `S` to save results:

| Format | Content |
|--------|---------|
| `.html` | Dark-theme, risk color-coded, interactive report with diff section |
| `.txt`  | Plain text Format-Table output |

---

### 🖥️ Use Cases

- **System administrators** — Corporate network inventory and unauthorized device detection
- **IT security teams** — Periodic network audits, risk assessment, detection of insecure services like Telnet/FTP
- **Network engineers** — Post-deployment device verification
- **Home / SOHO users** — See all devices connected to your own network
- **Penetration testers** — Fast reconnaissance phase
- **Students / education** — Learn network protocols and scanning techniques

---

### 🚀 Usage

```batch
# Double-click to run — adapter selection menu appears

# Or pass the target directly as an argument:
netscan.bat 192.168.1.0/24
netscan.bat 10.0.0.15
```

**Requirements:** Windows 7+ · PowerShell 5.1+ · Administrator rights (recommended for ARP/NetBIOS)

---

### 📊 Sample Output

```
=========================================
         Network Inventory Scanner
=========================================

[*] Target: 192.168.1.0/24 (256 addresses)
[*] Parallel Scanning Mode (Runspaces Active)

IP Address      | Hostname                  | OS / Device            | Vendor       | Ports/Risk
------------------------------------------------------------------------------------------------
192.168.1.1     | router.local              | Network Device/Gateway | TP-Link      | 80,443
192.168.1.5     | DESKTOP-AB12C             | Windows                | Intel        | 135,445,3389
192.168.1.12    | macbook-pro.local         | Linux/macOS/Android    | Apple        | 22,80
192.168.1.20    | HP-LaserJet               | Printer                | HP           | 80,9100
192.168.1.33    | N/A                       | Windows                | Unknown      | 23,21 [!High]

[#] Scan Summary (Total Found: 5 | Time: 8.43s)

[+] NEW DEVICES DETECTED: 192.168.1.33
```

</details>

<div align="center">

Made with ❤️ by [Abdullah ERTÜRK](https://github.com/abdullah-erturk)

[🌐 erturk.netlify.app](https://erturk.netlify.app)

</div>
