#!/bin/bash
# Title:       StamenScan
# Author:      FusedStamen
# Version:     2.0
# Category:    Reconnaissance
# Description: Passive surveillance infrastructure detection payload.
#              Detects Flock Safety ALPR cameras, Axon body cameras,
#              Axis/Verkada/Hikvision/Dahua cameras, and Raven/ShotSpotter
#              gunshot detection nodes via simultaneous WiFi + BLE scanning.
#
# WiFi detection layers:
#   - addr2 (transmitter) OUI match on all frames
#   - addr1 (receiver) OUI match — catches sleeping cameras (NitekryDPaul)
#   - Wildcard probe signature — probe-req + empty SSID + OUI (DeFlockJoplin)
#   - SSID keyword match
#
# BLE detection layers:
#   - OUI prefix match
#   - Device name keyword match
#   - Manufacturer ID 0x09C8 (XUNTONG/Flock) — Will Greenberg
#   - Raven/ShotSpotter service UUID range 0x3100-0x3500 — GainSec
#
# OUI Research Credits:
#   @NitekryDPaul — 30 Flock WiFi OUIs + addr1 receiver technique
#   Michael/DeFlockJoplin — 31st OUI + wildcard probe signature
#   colonelpanichacks/flock-you — BLE OUI + manufacturer ID research
#   Will Greenberg — BLE manufacturer ID 0x09C8 (XUNTONG) detection
#   GainSec — Raven/ShotSpotter BLE service UUID dataset
#   WiGLE field data — additional verified OUIs
#   judcrandall/lookout.py — Axon BLE OUIs
#
# Requirements: wlan0mon or wlan1mon for WiFi scanning
#               hci0 + btmon for BLE scanning
#               GPS optional
#
# LED BEHAVIOR:
#   SETUP    - Initializing
#   SPECIAL  - Scanning active
#   FINISH   - Detection (ALERT+RINGTONE for HIGH)
#   FAIL     - Error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
[ -z "$SCRIPT_DIR" ] && SCRIPT_DIR="$(dirname "$(readlink -f "$0")" 2>/dev/null)"
[ -z "$SCRIPT_DIR" ] && SCRIPT_DIR="/root/payloads/user/reconnaissance/StamenScan"
OUI_FILE="$SCRIPT_DIR/stamenscan_oui.txt"
[ ! -f "$OUI_FILE" ] && OUI_FILE="/root/payloads/user/reconnaissance/StamenScan/stamenscan_oui.txt"

LOOT_DIR="/root/loot/stamenscan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOOT_DIR}/stamenscan_${TIMESTAMP}.csv"
SEEN_FILE="/tmp/ss_seen.txt"
BTMON_FILE="/tmp/ss_btmon.txt"
WIFI_FILE="/tmp/ss_wifi.txt"

# Scan cycle duration in seconds
SCAN_TIME=12

# Raven service UUID prefixes (custom GainSec dataset)
RAVEN_UUIDS="00003100 00003200 00003300 00003400 00003500"

# ---- INIT ----

LED SETUP
mkdir -p "$LOOT_DIR"
> "$SEEN_FILE"

if [ ! -f "$OUI_FILE" ]; then
    LOG red "OUI database not found: $OUI_FILE"
    LED FAIL
    exit 1
fi

OUI_COUNT=$(grep -c "^[^#]" "$OUI_FILE" 2>/dev/null || echo 0)

# GPS check
GPS_AVAILABLE=0
gps_test=$(GPS_GET 2>/dev/null)
if [ -n "$gps_test" ] && [ "$gps_test" != "0 0 0 0" ]; then
    GPS_AVAILABLE=1
    LOG green "GPS: available"
else
    LOG yellow "GPS: not available — logging 0,0"
fi

# Auto-setup external MediaTek MT7612U (AWUS036ACM) if present
if ! ip link show wlan2mon >/dev/null 2>&1; then
    if lsusb | grep -q "0e8d:7612"; then
        LOG cyan "External MT7612U detected — bringing up wlan2mon..."
        iw phy phy2 interface add wlan2mon type monitor 2>/dev/null
        ip link set wlan2mon up 2>/dev/null
        iw dev wlan2mon set channel 6 2>/dev/null
        ip link show wlan2mon >/dev/null 2>&1 \
            && LOG green "wlan2mon ready" \
            || LOG yellow "wlan2mon setup failed — using internal"
    fi
fi

# Monitor interface — prefer external if available
MON_IFACE=""
for iface in wlan2mon wlan1mon wlan0mon; do
    if ip link show "$iface" >/dev/null 2>&1; then
        MON_IFACE="$iface"
        break
    fi
done

# Write CSV header
echo "timestamp,gps_lat,gps_lon,mac,oui,category,severity,description,method,rssi" > "$LOG_FILE"

LOG ""
LOG cyan "╔═══════════════════════════════╗"
LOG cyan "║       S T A M E N S C A N     ║"
LOG cyan "║  Surveillance Infrastructure  ║"
LOG cyan "║        Detection v2.0         ║"
LOG cyan "╚═══════════════════════════════╝"
LOG ""
LOG "OUI database: $OUI_COUNT entries"
[ -n "$MON_IFACE" ] && LOG green "WiFi: $MON_IFACE" || LOG yellow "WiFi: no monitor interface"
LOG "Loot: $LOG_FILE"
LOG ""

# ---- HELPERS ----

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

is_laa() {
    # Returns 0 (true) if MAC is locally administered/randomized
    local first_octet
    first_octet=$(echo "$1" | cut -d: -f1 | tr 'a-z' 'A-Z')
    [ $(( 0x${first_octet} & 0x02 )) -ne 0 ]
}

is_multicast() {
    local first_octet
    first_octet=$(echo "$1" | cut -d: -f1 | tr 'a-z' 'A-Z')
    [ $(( 0x${first_octet} & 0x01 )) -ne 0 ]
}

lookup_oui() {
    local mac_upper
    mac_upper=$(echo "$1" | tr 'a-z' 'A-Z')
    local oui
    oui=$(echo "$mac_upper" | cut -c1-8)
    grep "^${oui}|" "$OUI_FILE" 2>/dev/null | head -1
}

# ---- ALERT + LOG ----

fire_detection() {
    local mac="$1" category="$2" severity="$3" desc="$4" method="$5" rssi="${6:-0}"

    # Dedup
    local key="${mac}|${method}"
    if grep -q "^${key}$" "$SEEN_FILE" 2>/dev/null; then
        return
    fi
    echo "$key" >> "$SEEN_FILE"

    local ts gps
    ts=$(date '+%Y-%m-%dT%H:%M:%S')
    gps=$(get_gps)
    local oui
    oui=$(echo "$mac" | tr 'a-z' 'A-Z' | cut -c1-8)

    # Log to CSV
    echo "${ts},${gps},${mac},${oui},${category},${severity},${desc},${method},${rssi}" >> "$LOG_FILE"

    # Display
    case "$category" in
        FLOCK|FLOCK_BLE)
            LOG red   "⚠ [${severity}] FLOCK: $mac — $desc ($method)"
            ;;
        FLOCK_MANUFACTURER)
            LOG red   "⚠ [HIGH] FLOCK MFR ID: $mac — manufacturer 0x09C8 ($method)"
            ;;
        RAVEN)
            LOG red   "⚠ [HIGH] RAVEN/SHOTSPOTTER: $mac — $desc ($method)"
            ;;
        AXON)
            LOG yellow "⚠ [${severity}] AXON: $mac — $desc ($method)"
            ;;
        *)
            LOG blue  "⚠ [${severity}] ${category}: $mac — $desc ($method)"
            ;;
    esac

    # Alert
    case "$severity" in
        HIGH)
            LED FINISH
            ALERT "${category} DETECTED! ${mac}"
            RINGTONE "alert"
            VIBRATE
            sleep 1
            RINGTONE "alert"
            VIBRATE
            sleep 1
            RINGTONE "alert"
            VIBRATE
            LED SPECIAL
            ;;
        MEDIUM)
            LED FINISH
            VIBRATE
            LED SPECIAL
            ;;
    esac
}

# ---- OUI MATCH ----

check_oui() {
    local mac="$1" method="$2"
    [ -z "$mac" ] && return
    # Validate MAC format
    echo "$mac" | grep -qE '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' || return
    # Skip LAA and multicast
    is_laa "$mac" && return
    is_multicast "$mac" && return

    local oui_line
    oui_line=$(lookup_oui "$mac")
    [ -z "$oui_line" ] && return

    local category severity desc
    category=$(echo "$oui_line" | cut -d'|' -f2)
    severity=$(echo "$oui_line" | cut -d'|' -f3)
    desc=$(echo "$oui_line" | cut -d'|' -f4)

    fire_detection "$mac" "$category" "$severity" "$desc" "$method"
}

# ---- SSID KEYWORD MATCH ----

check_ssid() {
    local ssid="$1" mac="$2" method="$3"
    [ -z "$ssid" ] && return
    local ssid_lower
    ssid_lower=$(echo "$ssid" | tr 'A-Z' 'a-z')

    case "$ssid_lower" in
        *flock*|*penguin*|*pigvision*|*"fs ext battery"*)
            local key="${mac}|SSID_FLOCK"
            grep -q "^${key}$" "$SEEN_FILE" 2>/dev/null && return
            echo "$key" >> "$SEEN_FILE"
            local ts gps
            ts=$(date '+%Y-%m-%dT%H:%M:%S')
            gps=$(get_gps)
            echo "${ts},${gps},${mac},SSID,FLOCK_SSID,HIGH,Flock SSID: ${ssid},${method},0" >> "$LOG_FILE"
            LOG red "⚠ [HIGH] FLOCK SSID: $mac — $ssid ($method)"
            LED FINISH
            ALERT "FLOCK SSID! $ssid"
            RINGTONE "alert"
            VIBRATE
            sleep 1
            RINGTONE "alert"
            VIBRATE
            sleep 1
            RINGTONE "alert"
            VIBRATE
            LED SPECIAL
            ;;
        *axon*)
            local key="${mac}|SSID_AXON"
            grep -q "^${key}$" "$SEEN_FILE" 2>/dev/null && return
            echo "$key" >> "$SEEN_FILE"
            local ts gps
            ts=$(date '+%Y-%m-%dT%H:%M:%S')
            gps=$(get_gps)
            echo "${ts},${gps},${mac},SSID,AXON_SSID,HIGH,Axon SSID: ${ssid},${method},0" >> "$LOG_FILE"
            LOG yellow "⚠ [HIGH] AXON SSID: $mac — $ssid ($method)"
            LED FINISH
            ALERT "AXON SSID! $ssid"
            RINGTONE "alert"
            VIBRATE
            LED SPECIAL
            ;;
    esac
}

# ---- WIFI PARSER ----
# Pre-filters then processes completed WIFI_FILE

parse_wifi() {
    [ ! -s "$WIFI_FILE" ] && return

    # Extract unique MACs from beacons/probes first for fast OUI check
    grep -oP '(?<=SA:)([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' "$WIFI_FILE" | \
        sort -u | while read -r mac; do
        check_oui "$mac" "wifi_addr2"
    done

    # addr1 — unique RA MACs excluding broadcast
    grep -oP '(?<=RA:)([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' "$WIFI_FILE" | \
        sort -u | grep -v "ff:ff:ff:ff:ff:ff" | while read -r mac; do
        check_oui "$mac" "wifi_addr1"
    done

    # SSID keyword check on beacons
    grep "Beacon" "$WIFI_FILE" | while IFS= read -r line; do
        local mac ssid
        mac=$(echo "$line" | grep -oP '(?<=SA:)([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
        ssid=$(echo "$line" | grep -oP '(?<=Beacon \()[^)]+' | head -1)
        [ -n "$mac" ] && [ -n "$ssid" ] && check_ssid "$ssid" "$mac" "wifi_ssid"
    done

    # Wildcard probe check
    grep "Probe Request ()" "$WIFI_FILE" | while IFS= read -r line; do
        local mac
        mac=$(echo "$line" | grep -oP '(?<=SA:)([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
        [ -n "$mac" ] && check_oui "$mac" "wifi_wildcard_probe"
    done
}

# ---- BLE PARSER ----
# Pre-filters then processes completed BTMON_FILE

parse_ble() {
    [ ! -s "$BTMON_FILE" ] && return

    local filtered="/tmp/ss_ble_filtered.txt"
    grep -E "Address:|Name \(|Company:|0000310|0000320|0000330|0000340|0000350" \
        "$BTMON_FILE" > "$filtered" 2>/dev/null
    [ ! -s "$filtered" ] && return

    # OUI check on all addresses
    grep "Address:" "$filtered" | \
        grep -oP '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | \
        sort -u | while read -r mac; do
        check_oui "$mac" "ble_oui"
    done

    # Name keyword check — Flock
    grep -iE "Name \(.*\):.*flock|Name \(.*\):.*penguin|Name \(.*\):.*pigvision|Name \(.*\):.*fs ext battery" \
        "$filtered" | while IFS= read -r line; do
        local name
        name=$(echo "$line" | sed 's/.*Name ([^)]*): //')
        local key="NAME_FLOCK_${name}"
        grep -q "^${key}$" "$SEEN_FILE" 2>/dev/null && continue
        echo "$key" >> "$SEEN_FILE"
        local ts gps
        ts=$(date '+%Y-%m-%dT%H:%M:%S')
        gps=$(get_gps)
        echo "${ts},${gps},UNKNOWN,NAME,FLOCK_BLE,HIGH,Flock BLE name: ${name},ble_name,0" >> "$LOG_FILE"
        LOG red "⚠ [HIGH] FLOCK BLE NAME: $name"
        LED FINISH; ALERT "FLOCK BLE! $name"
        RINGTONE "alert"; VIBRATE; sleep 1
        RINGTONE "alert"; VIBRATE; sleep 1
        RINGTONE "alert"; VIBRATE; LED SPECIAL
    done

    # Manufacturer ID 0x09C8 = 2504
    if grep -qE "Company:.*\(2504\)|XUNTONG" "$filtered"; then
        local key="MFR_FLOCK_2504"
        grep -q "^${key}$" "$SEEN_FILE" 2>/dev/null || {
            echo "$key" >> "$SEEN_FILE"
            local ts gps
            ts=$(date '+%Y-%m-%dT%H:%M:%S')
            gps=$(get_gps)
            echo "${ts},${gps},UNKNOWN,MFR,FLOCK_MANUFACTURER,HIGH,Flock mfr ID 0x09C8,ble_manufacturer,0" >> "$LOG_FILE"
            LOG red "⚠ [HIGH] FLOCK MFR 0x09C8 DETECTED"
            LED FINISH; ALERT "FLOCK MFR ID 0x09C8!"
            RINGTONE "alert"; VIBRATE; sleep 1
            RINGTONE "alert"; VIBRATE; sleep 1
            RINGTONE "alert"; VIBRATE; LED SPECIAL
        }
    fi

    # Raven service UUIDs
    if grep -qE "0000310[0-9]-|0000320[0-9]-|0000330[0-9]-|0000340[0-9]-|0000350[0-9]-" "$filtered"; then
        local key="UUID_RAVEN"
        grep -q "^${key}$" "$SEEN_FILE" 2>/dev/null || {
            echo "$key" >> "$SEEN_FILE"
            local ts gps
            ts=$(date '+%Y-%m-%dT%H:%M:%S')
            gps=$(get_gps)
            echo "${ts},${gps},UNKNOWN,UUID,RAVEN,HIGH,Raven/ShotSpotter service UUID,ble_uuid,0" >> "$LOG_FILE"
            LOG red "⚠ [HIGH] RAVEN/SHOTSPOTTER DETECTED"
            LED FINISH; ALERT "RAVEN DETECTED!"
            RINGTONE "alert"; VIBRATE; sleep 1
            RINGTONE "alert"; VIBRATE; sleep 1
            RINGTONE "alert"; VIBRATE; LED SPECIAL
        }
    fi

    rm -f "$filtered"
}

# ---- STATS ----

show_stats() {
    local total
    total=$(grep -c "," "$LOG_FILE" 2>/dev/null || echo 0)
    total=$(( total - 1 ))
    [ "$total" -lt 0 ] && total=0
    LOG ""
    LOG cyan "Detections this session: $total"
    LOG ""
}

# ---- MAIN ----

cleanup() {
    kill $BTMON_PID $BT_PID $TCP_PID 2>/dev/null
    wait $BTMON_PID $BT_PID $TCP_PID 2>/dev/null
    rm -f "$BTMON_FILE" "$WIFI_FILE" "$SEEN_FILE"
    LOG ""
    show_stats
    LOG green "StamenScan stopped."
    LED SETUP
    exit 0
}
trap cleanup INT TERM EXIT

LED SPECIAL
LOG green "StamenScan v2.0 active — press B to stop"
LOG ""

scan_count=0
BTMON_PID="" BT_PID="" TCP_PID=""

while true; do
    scan_count=$(( scan_count + 1 ))
    LOG cyan "── Scan #${scan_count} ──────────────────"

    # Clear temp files
    > "$BTMON_FILE"
    > "$WIFI_FILE"
    TCP_PID=""

    # Start btmon
    btmon > "$BTMON_FILE" 2>/dev/null &
    BTMON_PID=$!

    # Start BLE scan
    (echo "power on"; sleep 1; echo "scan on"; sleep "$SCAN_TIME"; echo "scan off") \
        | bluetoothctl 2>/dev/null &
    BT_PID=$!

    # Start WiFi capture — filter at capture time for relevant frames only
    if [ -n "$MON_IFACE" ]; then
        tcpdump -i "$MON_IFACE" -n -e \
            'type mgt subtype probe-req or type mgt subtype beacon or type data' \
            2>/dev/null > "$WIFI_FILE" &
        TCP_PID=$!
    fi

    # Wait for scan cycle
    sleep $(( SCAN_TIME + 2 ))

    # Kill scan processes
    kill $BTMON_PID $BT_PID 2>/dev/null
    [ -n "$TCP_PID" ] && kill $TCP_PID 2>/dev/null
    wait $BT_PID $BTMON_PID 2>/dev/null
    [ -n "$TCP_PID" ] && wait $TCP_PID 2>/dev/null

    # Process captured data
    [ -n "$MON_IFACE" ] && parse_wifi
    parse_ble

    [ $(( scan_count % 5 )) -eq 0 ] && show_stats

    sleep 2
done
