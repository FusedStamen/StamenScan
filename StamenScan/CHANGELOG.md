# Changelog

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
