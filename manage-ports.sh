#!/usr/bin/env bash
###############################################################################
# HomelinkWG - port management helper
# Version: 3.1 (2026-04-26)
#
# Adds, removes or lists port forwards. Edits config.json atomically and
# reconciles the systemd units by delegating to deploy.sh.
###############################################################################
if [ -z "${BASH_VERSION:-}" ]; then
    echo "[ERREUR] Ce script doit être lancé avec bash, pas sh."
    echo "  Utilise : sudo bash manage-ports.sh   ou   sudo ./manage-ports.sh"
    exit 1
fi
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/config.json"
readonly LOCK_FILE="/var/lock/homelinkwg-config.lock"

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'; NC=$'\033[0m'
else
    RED="" GREEN="" YELLOW="" BLUE="" NC=""
fi

log_info()    { printf '%s[INFO]%s %s\n' "${BLUE}"   "${NC}" "$*"; }
log_success() { printf '%s[ OK ]%s %s\n' "${GREEN}"  "${NC}" "$*"; }
log_warning() { printf '%s[WARN]%s %s\n' "${YELLOW}" "${NC}" "$*"; }
log_error()   { printf '%s[FAIL]%s %s\n' "${RED}"    "${NC}" "$*" >&2; }

# ---------------------------------------------------------------------------
require_root() {
    [[ $EUID -eq 0 ]] || { log_error "run with sudo"; exit 1; }
}

require_deps() {
    local missing=()
    for c in jq systemctl; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    if (( ${#missing[@]} > 0 )); then
        log_error "Missing dependencies: ${missing[*]}. Run deploy.sh first."
        exit 1
    fi
    [[ -f "${CONFIG_FILE}" ]] || { log_error "config.json not found"; exit 1; }
    jq empty "${CONFIG_FILE}" || { log_error "config.json is invalid JSON"; exit 1; }
}

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
valid_host() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9._-][A-Za-z0-9._\ -]{0,63}$ ]]; }

# Run a callback under a flock so parallel invocations don't corrupt config
with_lock() {
    exec 9>"${LOCK_FILE}"
    flock -w 10 9 || { log_error "Could not acquire lock ${LOCK_FILE}"; exit 1; }
    "$@"
}

# ---------------------------------------------------------------------------
cmd_list() {
    jq -r '.ports[] | "  • \(.name): :\(.local_port) -> \(.remote_host):\(.remote_port) (enabled=\(.enabled // true))"' "${CONFIG_FILE}"
}

cmd_status() {
    local any_shown=0
    while IFS= read -r lp; do
        any_shown=1
        local unit="homelinkwg-socat-${lp}"
        if systemctl is-active --quiet "${unit}" 2>/dev/null; then
            printf '  port %-5s %s✓ active%s (%s)\n'   "${lp}" "${GREEN}" "${NC}" "${unit}"
        else
            printf '  port %-5s %s✗ inactive%s (%s)\n' "${lp}" "${RED}"   "${NC}" "${unit}"
        fi
    done < <(jq -r '.ports[].local_port' "${CONFIG_FILE}")
    (( any_shown == 0 )) && log_warning "No ports configured."
}

cmd_add() {
    local local_port="$1" remote_host="$2" remote_port="$3" name="$4"
    local description="${5:-${name}}"

    valid_port "${local_port}"  || { log_error "Invalid local_port: ${local_port}"; exit 1; }
    valid_port "${remote_port}" || { log_error "Invalid remote_port: ${remote_port}"; exit 1; }
    valid_host "${remote_host}" || { log_error "Invalid remote_host: ${remote_host}"; exit 1; }
    valid_name "${name}"        || { log_error "Invalid name: ${name}"; exit 1; }

    if jq -e --argjson lp "${local_port}" '.ports[] | select(.local_port == $lp)' \
           "${CONFIG_FILE}" >/dev/null; then
        log_error "Port ${local_port} is already configured."
        exit 1
    fi

    local tmp
    tmp=$(mktemp --tmpdir="${SCRIPT_DIR}" .config.XXXXXX.json)
    trap 'rm -f "${tmp:-}"' EXIT

    jq --argjson lp "${local_port}" \
       --arg     rh "${remote_host}" \
       --argjson rp "${remote_port}" \
       --arg     nm "${name}" \
       --arg     de "${description}" \
       '.ports += [{"local_port":$lp,"remote_host":$rh,"remote_port":$rp,"name":$nm,"description":$de,"enabled":true}]' \
       "${CONFIG_FILE}" >"${tmp}"

    mv "${tmp}" "${CONFIG_FILE}"
    log_success "Added ${name} (:${local_port} -> ${remote_host}:${remote_port})"

    log_info "Running deploy.sh to reconcile services..."
    "${SCRIPT_DIR}/deploy.sh"
}

cmd_remove() {
    local local_port="$1"
    valid_port "${local_port}" || { log_error "Invalid port: ${local_port}"; exit 1; }

    if ! jq -e --argjson lp "${local_port}" '.ports[] | select(.local_port == $lp)' \
           "${CONFIG_FILE}" >/dev/null; then
        log_warning "Port ${local_port} not in config.json."
    fi

    local tmp
    tmp=$(mktemp --tmpdir="${SCRIPT_DIR}" .config.XXXXXX.json)
    trap 'rm -f "${tmp:-}"' EXIT

    jq --argjson lp "${local_port}" \
       'del(.ports[] | select(.local_port == $lp))' \
       "${CONFIG_FILE}" >"${tmp}"
    mv "${tmp}" "${CONFIG_FILE}"

    log_success "Removed port ${local_port} from config.json"
    log_info "Running deploy.sh to reconcile services..."
    "${SCRIPT_DIR}/deploy.sh"
}

cmd_enable()  { _toggle "$1" true  ; }
cmd_disable() { _toggle "$1" false ; }

_toggle() {
    local local_port="$1" flag="$2"
    valid_port "${local_port}" || { log_error "Invalid port: ${local_port}"; exit 1; }
    local tmp
    tmp=$(mktemp --tmpdir="${SCRIPT_DIR}" .config.XXXXXX.json)
    trap 'rm -f "${tmp:-}"' EXIT
    jq --argjson lp "${local_port}" --argjson en "${flag}" \
       '(.ports[] | select(.local_port == $lp) | .enabled) = $en' \
       "${CONFIG_FILE}" >"${tmp}"
    mv "${tmp}" "${CONFIG_FILE}"
    log_success "Set enabled=${flag} on port ${local_port}"
    "${SCRIPT_DIR}/deploy.sh"
}

show_usage() {
    cat <<EOF
HomelinkWG port manager

Usage: sudo $0 <command> [args]

Commands:
  list                                              List all ports
  status                                            Show systemd status per port
  add <local> <host> <remote> <name> [description] Add a new port forward
  remove <local>                                    Remove a port forward
  enable  <local>                                   Enable an existing port
  disable <local>                                   Disable (keep config, stop service)
  help                                              Show this help

All mutating commands re-run deploy.sh to reconcile systemd services.
EOF
}

main() {
    require_root
    require_deps

    local cmd="${1:-help}"; shift || true
    case "${cmd}" in
        list)     cmd_list ;;
        status)   cmd_status ;;
        add)
            (( $# >= 4 )) || { log_error "add needs: <local> <host> <remote> <name> [desc]"; exit 1; }
            with_lock cmd_add "$@"
            ;;
        remove)
            (( $# >= 1 )) || { log_error "remove needs: <local>"; exit 1; }
            with_lock cmd_remove "$@"
            ;;
        enable)
            (( $# >= 1 )) || { log_error "enable needs: <local>"; exit 1; }
            with_lock cmd_enable "$@"
            ;;
        disable)
            (( $# >= 1 )) || { log_error "disable needs: <local>"; exit 1; }
            with_lock cmd_disable "$@"
            ;;
        help|-h|--help) show_usage ;;
        *) log_error "unknown command: ${cmd}"; show_usage; exit 1 ;;
    esac
}

main "$@"
