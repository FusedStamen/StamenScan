#!/bin/bash
# Title:       StamenScan
# Author:      FusedStamen
# Version:     1.1
# Category:    Reconnaissance
# Description: Passive surveillance infrastructure detection payload.
#              Detects Flock Safety ALPR cameras (35 WiFi OUIs + 9 BLE OUIs),
#              Axon body cameras/tasers, Axis/Verkada/Hikvision/Dahua cameras.
#              Designed for wardriving — runs continuously, optionally logs GPS
#              coordinates with each detection, and alerts on high-severity finds.
#
# OUI Research Credits:
#   @NitekryDPaul — 30 Flock WiFi OUIs (promiscuous-mode research)
#   Michael/DeFlockJoplin — 31st OUI + wildcard probe signature
#   colonelpanichacks/flock-you — BLE OUI research
#   WiGLE field data — additional verified OUIs
#   judcrandall/lookout.py — Axon BLE detection
#
# Requirements: wlan0mon or wlan1mon for WiFi scanning
#               hci0 for BLE scanning
#               GPS optional — coordinates logged if available
#
# LED BEHAVIOR:
#   SETUP    - Initializing
#   SPECIAL  - Scanning active
#   FINISH   - Detection (with ALERT+RINGTONE for HIGH severity)
#   FAIL     - Error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUI_FILE="$SCRIPT_DIR/stamenscan_oui.txt"
LOOT_DIR="/root/loot/stamenscan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOOT_DIR}/stamenscan_${TIMESTAMP}.csv"
SEEN_FILE="/tmp/stamenscan_seen.txt"
SCAN_INTERVAL=15
BLE_SCAN_TIME=12
WIFI_PASSIVE_TIME=10

# ---- INIT ----

LED SETUP

mkdir -p "$LOOT_DIR"
> "$SEEN_FILE"

# Verify OUI file exists
if [ ! -f "$OUI_FILE" ]; then
    LOG red "OUI database not found: $OUI_FILE"
    LOG red "Place stamenscan_oui.txt alongside payload.sh"
    LED FAIL
    exit 1
fi

GPS_AVAILABLE=0
gps_test=$(GPS_GET 2>/dev/null)
if [ -n "$gps_test" ] && [ "$gps_test" != "0 0 0 0" ]; then
    GPS_AVAILABLE=1
    LOG green "GPS: available"
else
    LOG yellow "GPS: not available — detections logged without coordinates"
fi

OUI_COUNT=$(grep -c "^[^#]" "$OUI_FILE" 2>/dev/null || echo 0)

# Write CSV header
echo "timestamp,gps_lat,gps_lon,mac,oui,category,severity,description,method,rssi" > "$LOG_FILE"

LOG ""
LOG cyan "╔═══════════════════════════════╗"
LOG cyan "║       S T A M E N S C A N     ║"
LOG cyan "║  Surveillance Infrastructure  ║"
LOG cyan "║        Detection v1.0         ║"
LOG cyan "╚═══════════════════════════════╝"
LOG ""
LOG "OUI database: $OUI_COUNT entries"
LOG "Loot: $LOG_FILE"
LOG ""

# ---- GPS HELPER ----

get_gps() {
    [ "$GPS_AVAILABLE" -eq 0 ] && echo "0,0" && return
    local coords
    coords=$(GPS_GET 2>/dev/null)
    if [ -n "$coords" ] && [ "$coords" != "0 0 0 0" ]; then
        echo "$coords" | awk '{print $1","$2}'
    else
        echo "0,0"
    fi
}

# ---- OUI LOOKUP ----

lookup_oui() {
    local mac_upper
    mac_upper=$(echo "$1" | tr 'a-z' 'A-Z')
    local oui
    oui=$(echo "$mac_upper" | cut -c1-8)
    grep "^${oui}|" "$OUI_FILE" 2>/dev/null | head -1
}

# ---- ALERT HANDLER ----

fire_alert() {
    local severity="$1" category="$2" mac="$3" desc="$4" method="$5"

    case "$severity" in
        HIGH)
            LED FINISH
            RINGTONE "alert"
            VIBRATE
            ALERT "${category} DETECTED! ${mac}"
            ;;
        MEDIUM)
            LED SPECIAL
            VIBRATE
            ;;
        LOW)
            # Log only, no alert
            ;;
    esac

    case "$category" in
        FLOCK|FLOCK_BATTERY)
            LOG red    "⚠ [${severity}] FLOCK: $mac — $desc ($method)"
            ;;
        AXON)
            LOG yellow "⚠ [${severity}] AXON: $mac — $desc ($method)"
            ;;
        AXIS|VERKADA|HIKVISION|DAHUA)
            LOG blue   "⚠ [${severity}] ${category}: $mac — $desc ($method)"
            ;;
        FLOCK_LITEON|FLOCK_MODEM)
            LOG cyan   "? [${severity}] POSSIBLE FLOCK: $mac — $desc ($method)"
            ;;
        *)
            LOG        "? [${severity}] ${category}: $mac — $desc ($method)"
            ;;
    esac
}

# ---- LOG DETECTION ----

log_detection() {
    local mac="$1" oui="$2" category="$3" severity="$4" desc="$5" method="$6" rssi="${7:-0}"
    local gps ts
    ts=$(date '+%Y-%m-%dT%H:%M:%S')
    gps=$(get_gps)
    echo "${ts},${gps},${mac},${oui},${category},${severity},${desc},${method},${rssi}" >> "$LOG_FILE"
}

# ---- PROCESS MAC ----

process_mac() {
    local mac="$1" rssi="${2:-0}" method="$3"
    [ -z "$mac" ] && return

    # Skip LAA (locally administered) MACs — randomized, not useful
    local first_octet
    first_octet=$(echo "$mac" | cut -d: -f1 | tr 'a-z' 'A-Z')
    local laa_check=$(( 0x${first_octet} & 0x02 ))
    [ "$laa_check" -ne 0 ] && return

    # Dedup — skip if seen recently
    if grep -q "^${mac}$" "$SEEN_FILE" 2>/dev/null; then
        return
    fi
    echo "$mac" >> "$SEEN_FILE"

    local oui_line
    oui_line=$(lookup_oui "$mac")
    [ -z "$oui_line" ] && return

    local oui category severity desc
    oui=$(echo "$oui_line" | cut -d'|' -f1)
    category=$(echo "$oui_line" | cut -d'|' -f2)
    severity=$(echo "$oui_line" | cut -d'|' -f3)
    desc=$(echo "$oui_line" | cut -d'|' -f4)

    fire_alert "$severity" "$category" "$mac" "$desc" "$method"
    log_detection "$mac" "$oui" "$category" "$severity" "$desc" "$method" "$rssi"
}

# ---- ALSO CHECK SSID NAMES (Flock WiFi) ----

check_ssid_names() {
    local ssid="$1" mac="$2"
    local ssid_lower
    ssid_lower=$(echo "$ssid" | tr 'A-Z' 'a-z')

    case "$ssid_lower" in
        *flock*|*penguin*|*pigvision*|*"fs ext battery"*)
            # Skip if already seen by OUI
            if grep -q "^${mac}$" "$SEEN_FILE" 2>/dev/null; then
                return
            fi
            echo "$mac" >> "$SEEN_FILE"
            local ts gps
            ts=$(date '+%Y-%m-%dT%H:%M:%S')
            gps=$(get_gps)
            LOG red "⚠ [HIGH] FLOCK (SSID): $mac — SSID: $ssid (WIFI)"
            LED FINISH
            RINGTONE "alert"
            VIBRATE
            ALERT "FLOCK SSID DETECTED! $ssid"
            echo "${ts},${gps},${mac},SSID,FLOCK_SSID,HIGH,Flock SSID: ${ssid},WIFI,0" >> "$LOG_FILE"
            ;;
        *axon*|"axon-"*|"x"[0-9][0-9][0-9][0-9][0-9]*)
            if grep -q "^${mac}$" "$SEEN_FILE" 2>/dev/null; then
                return
            fi
            echo "$mac" >> "$SEEN_FILE"
            local ts gps
            ts=$(date '+%Y-%m-%dT%H:%M:%S')
            gps=$(get_gps)
            LOG yellow "⚠ [HIGH] AXON (SSID): $mac — SSID: $ssid (WIFI)"
            LED FINISH
            RINGTONE "alert"
            VIBRATE
            ALERT "AXON SSID DETECTED! $ssid"
            echo "${ts},${gps},${mac},SSID,AXON_SSID,HIGH,Axon SSID: ${ssid},WIFI,0" >> "$LOG_FILE"
            ;;
    esac
}

# ---- BLE SCAN ----

run_ble_scan() {
    LOG cyan "BLE scan (${BLE_SCAN_TIME}s)..."

    hciconfig hci0 down 2>/dev/null
    hciconfig hci0 reset 2>/dev/null
    hciconfig hci0 up 2>/dev/null
    sleep 1

    timeout "${BLE_SCAN_TIME}" hcitool lescan --duplicates 2>/dev/null > /tmp/ss_ble.txt &
    local bt_pid=$!
    sleep "$BLE_SCAN_TIME"
    kill "$bt_pid" 2>/dev/null
    wait "$bt_pid" 2>/dev/null

    if [ -s /tmp/ss_ble.txt ]; then
        while IFS= read -r line; do
            local mac
            mac=$(echo "$line" | awk '{print $1}' | grep -E '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
            [ -z "$mac" ] && continue
            process_mac "$mac" "0" "BLE"
        done < /tmp/ss_ble.txt
    fi
}

# ---- WIFI PASSIVE SCAN ----

run_wifi_scan() {
    local mon_iface=""

    # Find available monitor interface
    for iface in wlan1mon wlan0mon; do
        if ip link show "$iface" >/dev/null 2>&1; then
            mon_iface="$iface"
            break
        fi
    done

    if [ -z "$mon_iface" ]; then
        return
    fi

    LOG cyan "WiFi passive scan (${WIFI_PASSIVE_TIME}s on $mon_iface)..."

    timeout "$WIFI_PASSIVE_TIME" tcpdump -i "$mon_iface" -n \
        'type mgt subtype probe-req or type mgt subtype beacon' \
        2>/dev/null > /tmp/ss_wifi.txt &
    local tcp_pid=$!
    sleep "$WIFI_PASSIVE_TIME"
    kill "$tcp_pid" 2>/dev/null
    wait "$tcp_pid" 2>/dev/null

    if [ -s /tmp/ss_wifi.txt ]; then
        # Extract MACs and SSIDs from probe requests and beacons
        grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' /tmp/ss_wifi.txt | sort -u | while read -r mac; do
            process_mac "$mac" "0" "WIFI"
        done

        # Check SSID names in beacons
        grep -i "Beacon" /tmp/ss_wifi.txt | while IFS= read -r line; do
            local ssid mac
            ssid=$(echo "$line" | grep -oP '(?<=ESSID:")[^"]+' 2>/dev/null || true)
            mac=$(echo "$line" | grep -oE 'SA:([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | cut -d: -f2-)
            [ -n "$ssid" ] && [ -n "$mac" ] && check_ssid_names "$ssid" "$mac"
        done
    fi

    # Also check pager recon DB for Flock-related SSIDs from current scan
    local recon_db="/mmc/root/recon/recon.db"
    if [ -f "$recon_db" ]; then
        local since
        since=$(( $(date +%s) - SCAN_INTERVAL - 5 ))
        sqlite3 "$recon_db" \
            "SELECT bssid, ssid FROM ssid WHERE time >= $since AND ssid != '';" \
            2>/dev/null | while IFS='|' read -r bssid ssid; do
            [ -n "$bssid" ] && process_mac "$bssid" "0" "WIFI"
            [ -n "$ssid" ] && [ -n "$bssid" ] && check_ssid_names "$ssid" "$bssid"
        done
    fi
}

# ---- STATS DISPLAY ----

show_stats() {
    local total
    total=$(grep -c "," "$LOG_FILE" 2>/dev/null || echo 0)
    total=$(( total - 1 ))  # minus header
    [ "$total" -lt 0 ] && total=0
    LOG ""
    LOG cyan "Detections this session: $total"
    LOG cyan "Loot: $LOG_FILE"
    LOG ""
}

# ---- MAIN LOOP ----

LED SPECIAL

LOG green "StamenScan active — press B to stop"
LOG ""

scan_count=0
while true; do
    scan_count=$(( scan_count + 1 ))
    LOG cyan "── Scan #${scan_count} ──────────────────"

    run_ble_scan
    run_wifi_scan

    [ $(( scan_count % 5 )) -eq 0 ] && show_stats

    sleep 3
done

LED FINISH
show_stats
LOG green "StamenScan complete."
