# Changelog

## [2.0] - 2026-05-03

### Added
- Simultaneous WiFi + BLE scanning — both run in parallel each cycle
- addr1 (receiver) OUI match — detects sleeping Flock cameras that never transmit (NitekryDPaul research)
- Wildcard probe request detection — Management + subtype 4 + empty SSID + OUI match (DeFlockJoplin research)  
- BLE device name keyword matching — catches Flock/Axon devices by broadcast name
- BLE manufacturer ID 0x09C8 (XUNTONG) detection — catches Flock BLE with randomized MACs (Will Greenberg research)
- Raven/ShotSpotter gunshot detector detection via BLE service UUID range 0x3100-0x3500 (GainSec dataset)
- RAVEN category — SoundThinking/ShotSpotter acoustic surveillance nodes
- btmon-based BLE capture replacing bluetoothctl-only approach — exposes full advertisement data
- Cleanup trap — kills all background processes cleanly on exit
- Auto-setup for external MediaTek MT7612U adapter (AWUS036ACM) — 
  detects and brings up wlan2mon automatically without needing 
  external-mediatek-radio-loader first
- wlan2mon added to monitor interface priority list (preferred over internal)

### Changed
- tcpdump now captures all management + data frames (was probe-req/beacon only)
- tcpdump filters at capture time to reduce file size and processing overhead
- Parsers use grep passes on completed files instead of line-by-line loops — much faster on MIPS CPU
- Scan cycle reduced to 12 seconds

### Fixed
- Pager no longer slows down/requires restart after exiting payload

## [1.1] - 2026-05-03

### Fixed
- SCRIPT_DIR resolution with multiple fallbacks for Pager execution context
- Switched BLE scan from hcitool lescan to bluetoothctl pipe pattern (BlueZ 5.72 compatibility)
- tcpdump PID capture — single-line command ensures $! captures background process correctly
- Added explicit "No monitor interface" warning instead of silent return

### Changed
- GPS now optional — warns at startup if unavailable, logs 0,0 without GPS
- HIGH severity alerts now fire three beep/vibrate cycles for better field awareness
- Reduced BLE scan time from 12s to 10s for faster loop cadence

## [1.0] - 2026-05-03

### Initial release
- Passive surveillance infrastructure detection via WiFi and BLE
- 64 OUIs across 7 categories: Flock Safety, Axon, Axis, Verkada, Hikvision, Dahua
- GPS coordinate logging with detections
- HIGH/MEDIUM severity alert tiers
- CSV loot output to /root/loot/stamenscan/
