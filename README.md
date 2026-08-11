# BW16 with OLED - NetCut ARP Integration

Complete firmware untuk BW16 dengan modul NetCut ARP untuk attacking & Troll mode.

## 📁 File Structure

```
.
├── firmware.ino              # Main firmware dengan UI menu
├── netcut.h                  # NetCut ARP module header
├── netcut.cpp                # NetCut ARP implementation
├── platformio.ini            # Build configuration
├── dns.h/cpp                 # DNS server modul
├── wifi_cust_tx.h/cpp        # Custom WiFi TX
├── debug.h                   # Debug utilities
└── wifi_conf.h               # WiFi configuration
```

## 🚀 Quick Build

### Prerequisites
- PlatformIO CLI atau IDE
- Realtek RTL8720DN board definition
- ArduinoJson & LittleFS libraries

### Build Steps

**1. Clone/Pull repository:**
```bash
git clone https://github.com/Valzzsxs/BW16withOled.git
cd BW16withOled
```

**2. Install dependencies:**
```bash
pio lib install
```

**3. Build firmware:**
```bash
pio run -e bw16_oled
```

**4. Upload to BW16:**
```bash
pio run -e bw16_oled -t upload
```

## 📊 Build Configuration

File: `platformio.ini`

```ini
[env:bw16_oled]
platform = realtek-ambz
board = rtl8720dn
framework = arduino
lib_deps =
    ArduinoJson@^6.21.0
    LittleFS@^2.0.0
build_flags =
    -DARDUINO_RTL8720DN
    -DUSE_SPIFFS
    -std=c++17
```

## 🎮 Usage

### Main Menu Options

| Option | Function |
|--------|----------|
| **Scan Networks** | Scan WiFi networks via deauth |
| **Random SSID** | Broadcast random SSIDs |
| **Rickroll SSID** | Broadcast rickroll SSID list |
| **NetCut ARP** | ⭐ ARP poisoning & Troll mode |
| **Stop All** | Stop all attacks |

### NetCut ARP Features

✅ **ARP Poisoning (Cut Mode)**
- Scan devices di network
- Cut device connectivity (bidirectional ARP poison)
- Restore devices dengan ARP restore packets
- Auto-restore saat exit

✅ **Troll Mode**
- Alternating online/offline timer
- Per-device individual control
- Configurable timing (1-300 detik)

✅ **VIP Protection**
- Whitelist MAC addresses
- Persist ke LittleFS JSON
- VIP devices immune dari attack

✅ **L2 Bridge Hook**
- Drop packets dari cut devices
- Layer 2 filtering aktif

## 🔧 Troubleshooting

### Compile Error: `undefined reference to 'netcutMenu'`
**Solusi:** Pastikan `netcut.cpp` dan `netcut.h` ada di repo dan `#include "netcut.h"` di firmware.ino

### Error: `lwip/etharp.h not found`
**Solusi:** Update platform Realtek & pastikan ESP-IDF sudah installed:
```bash
pio platform update realtek-ambz
```

### Upload gagal
**Solusi:** 
- Check COM port: `pio device list`
- Hold BOOT button saat upload
- Adjust `upload_speed` di platformio.ini ke 460800

## 📝 Serial Monitor

Monitor output untuk debug:
```bash
pio device monitor -p /dev/ttyUSB0 -b 115200
```

Output untuk NetCut:
```
[NetCut] Starting ARP scan...
[NetCut] Found: 5 devices
[NetCut] Scan done: 5 devices, GW MAC valid: 1
[NetCut] Attack running - Press Esc to stop...
```

## 📦 Binary Output

Compiled binary tersedia di:
```
.pio/build/bw16_oled/firmware.bin
.pio/build/bw16_oled/firmware.elf
```

## ⚠️ Legal Notice

Modul ini hanya untuk **educational & authorized testing purposes**. Gunakan hanya di network yang Anda miliki/authorized. Unauthorized access illegal!

## 📄 License

Public Domain - Use at your own risk

---

**Repository:** https://github.com/Valzzsxs/BW16withOled

**Last Updated:** 2026-08-11

**Status:** ✅ Build Ready
