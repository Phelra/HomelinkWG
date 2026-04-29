#!/usr/bin/env bash
###############################################################################
# HomelinkWG - health check
# Version: 3.1 (2026-04-26)
#
# Reads config.json and verifies each configured port + the VPN tunnel.
# Exit code = number of failed checks (0 = healthy). Suitable for cron/monitoring.
###############################################################################
if [ -z "${BASH_VERSION:-}" ]; then
    echo "[ERREUR] Ce script doit être lancé avec bash, pas sh."
    echo "  Utilise : bash health-check.sh"
    exit 1
fi
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/config.json"

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'; NC=$'\033[0m'
else
    RED="" GREEN="" YELLOW="" BLUE="" NC=""
fi

FAILED=0
QUIET=0

is_docker_runtime() {
    [[ "${HomelinkWG_RUNTIME:-}" == "docker" || -S /tmp/supervisor.sock || -f /.dockerenv ]]
}

title() { printf '\n%s== %s ==%s\n' "${BLUE}" "$1" "${NC}"; }
pass()  { (( QUIET )) || printf '%s  ✓%s %s\n' "${GREEN}" "${NC}" "$*"; }
fail()  { printf '%s  ✗%s %s\n' "${RED}"    "${NC}" "$*"; FAILED=$((FAILED+1)); }
warn()  { (( QUIET )) || printf '%s  !%s %s\n' "${YELLOW}" "${NC}" "$*"; }

require() {
    command -v "$1" >/dev/null 2>&1 || { fail "missing tool: $1"; exit 1; }
}

supervisor_program_name() {
    local unit="${1%.service}"
    if [[ "${unit}" == homelinkwg-socat-* ]]; then
        printf 'socat-%s\n' "${unit#homelinkwg-socat-}"
    elif [[ "${unit}" == "homelinkwg-dashboard" ]]; then
        printf 'dashboard\n'
    else
        printf '%s\n' "${unit}"
    fi
}

service_is_active() {
    local unit="$1"
    if is_docker_runtime; then
        local program
        program="$(supervisor_program_name "${unit}")"
        supervisorctl -s unix:///tmp/supervisor.sock status "${program}" 2>/dev/null | grep -q RUNNING
    else
        systemctl is-active --quiet "${unit}"
    fi
}

tcp_probe() {
    # tcp_probe host port timeout_seconds
    timeout "$3" bash -c ":</dev/tcp/$1/$2" 2>/dev/null
}

# ---------------------------------------------------------------------------
parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            -q|--quiet) QUIET=1 ;;
            -h|--help)
                cat <<EOF
Usage: $0 [-q|--quiet]

Exit code equals the number of failed checks (0 = healthy).
EOF
                exit 0
                ;;
            *) fail "unknown flag: $1"; exit 2 ;;
        esac
        shift
    done
}

check_prereqs() {
    title "Prerequisites"
    require jq
    require ip
    if is_docker_runtime; then
        require supervisorctl
    else
        require systemctl
    fi
    [[ -f "${CONFIG_FILE}" ]] || { fail "config.json missing"; return; }
    jq empty "${CONFIG_FILE}" 2>/dev/null || { fail "config.json invalid"; return; }
    pass "tools & config available"
}

check_vpn() {
    local iface; iface=$(jq -r '.vpn.interface // "wg0"' "${CONFIG_FILE}")
    title "VPN (${iface})"

    if ! ip link show "${iface}" >/dev/null 2>&1; then
        fail "interface ${iface} does not exist"
        return
    fi
    if ip link show "${iface}" | grep -qE 'state (UP|UNKNOWN)'; then
        pass "${iface} is up"
    else
        fail "${iface} is down"
    fi

    if command -v wg >/dev/null 2>&1; then
        local handshake
        handshake=$(wg show "${iface}" latest-handshakes 2>/dev/null | awk '{print $2}' | head -n1 || echo "")
        if [[ -n "${handshake}" && "${handshake}" -gt 0 ]]; then
            local age=$(( $(date +%s) - handshake ))
            if (( age < 180 )); then
                pass "handshake is fresh (${age}s ago)"
            else
                warn "handshake is stale (${age}s ago)"
            fi
        else
            warn "no handshake yet"
        fi
    fi
}

check_port() {
    local lp="$1" rh="$2" rp="$3" name="$4"
    local unit="homelinkwg-socat-${lp}"

    if service_is_active "${unit}"; then
        pass "${name}: service ${unit} active"
    else
        fail "${name}: service ${unit} not active"
    fi

    if tcp_probe 127.0.0.1 "${lp}" 1; then
        pass "${name}: local port ${lp} accepts connections"
    else
        fail "${name}: local port ${lp} not listening"
    fi

    if tcp_probe "${rh}" "${rp}" 2; then
        pass "${name}: remote ${rh}:${rp} reachable"
    else
        warn "${name}: remote ${rh}:${rp} unreachable (VPN issue?)"
    fi
}

check_ports() {
    title "Port forwards"
    local count=0
    while IFS=$'\t' read -r lp rh rp name enabled; do
        [[ "${enabled}" == "true" ]] || { warn "${name}: disabled in config"; continue; }
        check_port "${lp}" "${rh}" "${rp}" "${name}"
        count=$((count+1))
    done < <(jq -r '.ports[] | [.local_port, .remote_host, .remote_port, .name, (.enabled // true)] | @tsv' "${CONFIG_FILE}")
    (( count == 0 )) && warn "no enabled ports"
}

check_network() {
    title "Network (streaming performance)"

    local default_iface
    default_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')

    if [[ -z "${default_iface}" ]]; then
        fail "no default network interface found"
        return
    fi

    # Ethernet vs WiFi
    if [[ "${default_iface}" == eth* || "${default_iface}" == en* ]]; then
        local speed
        speed=$(cat "/sys/class/net/${default_iface}/speed" 2>/dev/null || echo "?")
        pass "Ethernet actif (${default_iface}) — ${speed} Mbps"
    elif [[ "${default_iface}" == wlan* || "${default_iface}" == wl* ]]; then
        local bit_rate
        bit_rate=$(iwconfig "${default_iface}" 2>/dev/null | awk -F'[=\ ]' '/Bit Rate/{print $3" "$4}' || echo "?")
        # WiFi est dégradé pour du streaming mais ne doit PAS faire échouer le
        # health-check : le tunnel reste fonctionnel et un fail déclenche un
        # restart de service inutile via cron.
        warn "WiFi actif (${default_iface}) — débit lien : ${bit_rate}"
        warn "→ Le WiFi limite le streaming vidéo. Branche un câble Ethernet pour de meilleures performances."

        # Vérifie si un port Ethernet existe mais n'est pas branché
        local eth_iface
        eth_iface=$(ip link show 2>/dev/null | awk -F': ' '/^[0-9]+: eth/{print $2; exit}')
        if [[ -n "${eth_iface}" ]]; then
            local eth_state
            eth_state=$(ip link show "${eth_iface}" | grep -oE 'state \S+' | awk '{print $2}')
            if [[ "${eth_state}" == "DOWN" ]]; then
                warn "→ Port Ethernet (${eth_iface}) disponible mais non branché."
            fi
        fi
    else
        warn "Interface réseau inconnue : ${default_iface}"
    fi

    # Température & throttling (Raspberry Pi uniquement)
    if command -v vcgencmd >/dev/null 2>&1; then
        local temp throttled
        temp=$(vcgencmd measure_temp 2>/dev/null | grep -oE '[0-9.]+')
        throttled=$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2)
        if [[ -n "${temp}" ]]; then
            if (( $(echo "${temp} > 80" | bc -l 2>/dev/null || echo 0) )); then
                fail "Température critique : ${temp}°C — throttling probable"
            elif (( $(echo "${temp} > 70" | bc -l 2>/dev/null || echo 0) )); then
                warn "Température élevée : ${temp}°C"
            else
                pass "Température OK : ${temp}°C"
            fi
        fi
        if [[ "${throttled}" != "0x0" && -n "${throttled}" ]]; then
            fail "Throttling CPU actif (${throttled}) — fréquence bridée, ajoute un dissipateur"
        else
            pass "Pas de throttling CPU"
        fi

        # Mémoire GPU
        local gpu_mem
        gpu_mem=$(vcgencmd get_mem gpu 2>/dev/null | grep -oE '[0-9]+')
        if [[ -n "${gpu_mem}" ]] && (( gpu_mem < 128 )); then
            warn "Mémoire GPU : ${gpu_mem}MB — insuffisant pour la vidéo (recommandé : 128MB)"
            warn "→ Ajoute gpu_mem=128 dans /boot/firmware/config.txt puis redémarre"
        else
            pass "Mémoire GPU : ${gpu_mem}MB"
        fi
    fi

    # TeamViewer en fond
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet teamviewerd 2>/dev/null; then
        warn "TeamViewer actif — consomme ~13%% CPU en permanence"
        warn "→ sudo systemctl disable --now teamviewerd"
    fi

    # Processus socat en double
    local socat_count
    socat_count=$(pgrep -c -f "socat.*TCP-LISTEN" 2>/dev/null || echo 0)
    if (( socat_count > 2 )); then
        warn "${socat_count} processus socat détectés — possible accumulation (attendu : 1 par port)"
        warn "→ sudo systemctl restart homelinkwg-socat-*"
    else
        pass "Processus socat : ${socat_count} (normal)"
    fi
}

check_dashboard() {
    title "Dashboard"
    local port; port=$(jq -r '.dashboard.port // 5555' "${CONFIG_FILE}")
    if is_docker_runtime; then
        if service_is_active homelinkwg-dashboard; then
            pass "dashboard supervisor program active"
        else
            fail "dashboard supervisor program not active"
        fi
        if tcp_probe 127.0.0.1 "${port}" 1; then
            pass "dashboard listening on :${port}"
        else
            fail "dashboard not reachable on :${port}"
        fi
    elif [[ -f /etc/systemd/system/homelinkwg-dashboard.service ]]; then
        if service_is_active homelinkwg-dashboard; then
            pass "homelinkwg-dashboard active"
            if tcp_probe 127.0.0.1 "${port}" 1; then
                pass "dashboard listening on :${port}"
            else
                fail "dashboard not reachable on :${port}"
            fi
        else
            fail "homelinkwg-dashboard not active"
        fi
    else
        warn "dashboard not installed"
    fi
}

summary() {
    title "Summary"
    if (( FAILED == 0 )); then
        printf '%sAll checks passed%s\n' "${GREEN}" "${NC}"
    else
        printf '%s%d check(s) failed%s\n' "${RED}" "${FAILED}" "${NC}"
    fi
}

main() {
    parse_args "$@"
    check_prereqs
    check_network
    check_vpn
    check_ports
    check_dashboard
    summary
    exit "${FAILED}"
}

main "$@"
