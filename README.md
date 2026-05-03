# StamenScan

**Passive Surveillance Infrastructure Detection for the WiFi Pineapple Pager**

Designed for wardriving — runs continuously, alerts on surveillance infrastructure detected nearby via WiFi and BLE.

---

## What it detects

| Category | Method | Severity | Source |
|----------|--------|----------|--------|
| Flock Safety ALPR cameras | WiFi (35 OUIs) | HIGH | @NitekryDPaul, DeFlockJoplin, WiGLE |
| Flock Safety FS Ext Battery | BLE (9 OUIs) | HIGH | colonelpanichacks/flock-you, WiGLE |
| Axon body cams / tasers | BLE (4 OUIs) | HIGH | judcrandall/lookout.py |
| Axis network cameras | WiFi (4 OUIs) | MEDIUM | Axis Communications docs |
| Verkada cloud cameras | WiFi (1 OUI) | MEDIUM | Verkada help docs |
| Hikvision IP cameras | WiFi (8 OUIs) | MEDIUM | IPVM OUI database |
| Dahua IP cameras | WiFi (3 OUIs) | MEDIUM | IPVM OUI database |

Total: 64 OUIs across 7 surveillance infrastructure categories.

---

## Alert behavior

| Severity | Alert |
|----------|-------|
| HIGH (Flock/Axon) | `ALERT` dialog + `RINGTONE` + `VIBRATE` + red log |
| MEDIUM (Axis/Verkada/Hikvision/Dahua) | `VIBRATE` + blue log |

---

## Loot output

Detections saved to `/root/loot/stamenscan/stamenscan_TIMESTAMP.csv`:

```
timestamp,gps_lat,gps_lon,mac,oui,category,severity,description,method,rssi
2026-05-03T14:22:11,42.370,-71.210,70:C9:4E:xx:xx:xx,70:C9:4E,FLOCK,HIGH,Flock Safety infrastructure,WIFI,0
```

GPS coordinates logged if module is available. Without GPS, recorded as `0,0`.

---

## Requirements

- WiFi Pineapple Pager
- `wlan0mon` or `wlan1mon` in monitor mode for WiFi scanning
- `hci0` for BLE scanning
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
- **Michael / DeFlockJoplin** — 31st OUI (`82:6B:F2`) + wildcard probe signature (11/12 cameras field tested)
- **colonelpanichacks** ([flock-you](https://github.com/colonelpanichacks/flock-you)) — Flock BLE OUI research
- **judcrandall** ([lookout.py](https://github.com/judcrandall/lookout.py)) — Axon BLE detection
- **WiGLE community / ringmast4r** — field-verified OUI data
- **OSINTI4L** — Fuzz_Finder (Axon detection inspiration)
- **colonelpanichacks** — Flock_Detect payload (BLE detection inspiration)

---

## Disclaimer

Passive reception only. StamenScan does not transmit and does not authenticate to any network. Detecting publicly broadcast wireless frames is legal in most jurisdictions. Always comply with local laws.
