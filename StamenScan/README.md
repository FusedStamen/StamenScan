# StamenScan

**Passive Surveillance Infrastructure Detection for the WiFi Pineapple Pager**

Designed for wardriving — runs continuously, detects surveillance infrastructure nearby via simultaneous WiFi + BLE scanning, and alerts on finds.

---

## What it detects

| Category | Method | Severity | Detection Technique | Source |
|----------|--------|----------|-------------------|--------|
| Flock Safety ALPR cameras | WiFi (35 OUIs) | HIGH | addr2 transmitter, addr1 receiver (sleeping cameras), wildcard probe signature | @NitekryDPaul, DeFlockJoplin, WiGLE |
| Flock Safety FS Ext Battery | BLE (9 OUIs + name + mfr ID) | HIGH | OUI prefix, device name, manufacturer ID 0x09C8 | colonelpanichacks/flock-you, Will Greenberg |
| Axon body cams / tasers | BLE (4 OUIs + name) | HIGH | OUI prefix, device name | judcrandall/lookout.py |
| Raven / ShotSpotter | BLE (service UUID) | HIGH | Custom UUID range 0x3100-0x3500 | GainSec dataset |
| Axis network cameras | WiFi (4 OUIs) | MEDIUM | OUI prefix | Axis Communications docs |
| Verkada cloud cameras | WiFi (1 OUI) | MEDIUM | OUI prefix | Verkada help docs |
| Hikvision IP cameras | WiFi (8 OUIs) | MEDIUM | OUI prefix | IPVM OUI database |
| Dahua IP cameras | WiFi (3 OUIs) | MEDIUM | OUI prefix | IPVM OUI database |

Total: 64 OUIs + BLE manufacturer ID + Raven service UUIDs.

---

## Detection layers

**WiFi:**
- `addr2` (transmitter) OUI match on all management + data frames
- `addr1` (receiver) OUI match — catches sleeping Flock cameras that never transmit (@NitekryDPaul)
- Wildcard probe signature — probe-req + empty SSID + OUI match (DeFlockJoplin, 11/12 cameras, 2 false positives)
- SSID keyword match — flock, penguin, pigvision, fs ext battery, axon

**BLE (via btmon):**
- OUI prefix match
- Device name keyword match
- Manufacturer ID `0x09C8` (XUNTONG) — catches Flock BLE with randomized MACs (Will Greenberg)
- Raven/ShotSpotter service UUID range `0x3100`–`0x3500` (GainSec)

---

## Alert behavior

| Severity | Alert |
|----------|-------|
| HIGH (Flock/Axon/Raven) | `ALERT` dialog + 3x `RINGTONE` + 3x `VIBRATE` + red log |
| MEDIUM (Axis/Verkada/Hikvision/Dahua) | `VIBRATE` + blue log |

---

## Loot output

Detections saved to `/root/loot/stamenscan/stamenscan_TIMESTAMP.csv`:

```
timestamp,gps_lat,gps_lon,mac,oui,category,severity,description,method,rssi
2026-05-03T14:22:11,42.370,-71.210,70:C9:4E:xx:xx:xx,70:C9:4E,FLOCK,HIGH,Flock Safety infrastructure,wifi_addr2,0
```

GPS coordinates logged if module available. Without GPS, recorded as `0,0`.

Detection methods logged:
- `wifi_addr2` — transmitter OUI match
- `wifi_addr1` — receiver OUI match (sleeping camera)
- `wifi_wildcard_probe` — wildcard probe + OUI (highest precision)
- `wifi_ssid` — SSID keyword match
- `ble_oui` — BLE OUI prefix match
- `ble_name` — BLE device name keyword
- `ble_manufacturer` — manufacturer ID 0x09C8
- `ble_uuid` — Raven service UUID

---

## Requirements

- WiFi Pineapple Pager
- `wlan0mon` or `wlan1mon` in monitor mode for WiFi scanning
- `hci0` + `btmon` for BLE scanning
- GPS optional

---

## Installation

Copy both files to the same directory:

```
/root/payloads/user/reconnaissance/StamenScan/
├── payload.sh
└── stamenscan_oui.txt
```

---

## OUI database

`stamenscan_oui.txt` can be updated independently as new OUIs are discovered. Format:

```
OUI|CATEGORY|SEVERITY|Description|Detection Method
70:C9:4E|FLOCK|HIGH|Flock Safety infrastructure (NitekryDPaul)|WIFI
```

---

## Research credits

- **@NitekryDPaul** — 30 Flock WiFi OUIs + addr1 receiver-side detection technique
- **Michael / DeFlockJoplin** — 31st OUI (`82:6B:F2`) + wildcard probe signature (11/12 cameras field tested in Joplin)
- **colonelpanichacks** ([flock-you](https://github.com/colonelpanichacks/flock-you)) — Flock BLE OUI research + Marauder firmware OUI list
- **Will Greenberg** ([flock-you fork](https://github.com/wgreenberg/flock-you)) — BLE manufacturer ID `0x09C8` (XUNTONG) detection
- **GainSec** — Raven/ShotSpotter BLE service UUID dataset (`raven_configurations.json`)
- **judcrandall** ([lookout.py](https://github.com/judcrandall/lookout.py)) — Axon BLE OUI detection
- **WiGLE community / ringmast4r** — field-verified OUI data
- **OSINTI4L** — Fuzz_Finder (Axon detection inspiration)
- **colonelpanichacks** — Flock_Detect payload (BLE detection inspiration)

---

## Disclaimer

Passive reception only. StamenScan does not transmit and does not authenticate to any network. Detecting publicly broadcast wireless frames is legal in most jurisdictions. Always comply with local laws.
