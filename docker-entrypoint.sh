#!/usr/bin/env bash
###############################################################################
# HomelinkWG - docker-entrypoint.sh
#
# Responsibilities:
#   1. Validate required env vars
#   2. Generate /app/analytics.conf  (auth config read by dashboard.py)
#   3. Copy config.json to a writable location and apply env overrides
#   4. Symlink the SQLite DB into the persistent data volume
#   5. Bring up WireGuard (if a config file is mounted)
#   6. Build a supervisord config with one socat process per port forward
#   7. Hand off to supervisord (PID 1)
###############################################################################
set -Eeuo pipefail

log()  { printf '\e[34m[entrypoint]\e[0m %s\n' "$*"; }
warn() { printf '\e[33m[entrypoint] WARN:\e[0m %s\n' "$*"; }
die()  { printf '\e[31m[entrypoint] ERROR:\e[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Affichage de la configuration au démarrage
# ---------------------------------------------------------------------------
printf '\n\e[34m╔══════════════════════════════════════════════╗\e[0m\n'
printf '\e[34m║       HomelinkWG — démarrage container       ║\e[0m\n'
printf '\e[34m╚══════════════════════════════════════════════╝\e[0m\n\n'
printf '  %-28s %s\n' "ADMIN_PASSWORD"       "${ADMIN_PASSWORD:+✅ défini (sera hashé)}${ADMIN_PASSWORD:-— (non défini)}"
printf '  %-28s %s\n' "ADMIN_PASSWORD_HASH"  "${ADMIN_PASSWORD_HASH:+✅ défini}${ADMIN_PASSWORD_HASH:-— (non défini)}"
printf '  %-28s %s\n' "DASHBOARD_PORT"       "${DASHBOARD_PORT:-5555 (défaut)}"
printf '  %-28s %s\n' "DASHBOARD_HOST"       "${DASHBOARD_HOST:-0.0.0.0 (défaut)}"
printf '  %-28s %s\n' "WG_INTERFACE"         "${WG_INTERFACE:-wg0 (défaut)}"
printf '  %-28s %s\n' "WG_CONFIG_FILE"       "${WG_CONFIG_FILE:-/etc/wireguard/wg0.conf (défaut)}"
printf '  %-28s %s\n' "ANALYTICS_ENABLED"    "${ANALYTICS_ENABLED:-true (défaut)}"
printf '  %-28s %s\n' "LIGHT_MODE"           "${LIGHT_MODE:-false (défaut)}"
printf '  %-28s %s\n' "ULTRA_LIGHT"          "${ULTRA_LIGHT:-false (défaut)}"
printf '  %-28s %s\n' "TZ"                   "${TZ:-UTC (défaut)}"
printf '  %-28s %s\n' "LOG_LEVEL"            "${LOG_LEVEL:-info (défaut)}"
printf '\n'

# ---------------------------------------------------------------------------
# 1. Validate required environment variables
# ---------------------------------------------------------------------------
# Accepte soit ADMIN_PASSWORD (texte clair, hashé au démarrage)
# soit ADMIN_PASSWORD_HASH (hash bcrypt pré-généré, pour les avancés)
if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
    log "Hashage du mot de passe admin..."
    ADMIN_PASSWORD_HASH=$(python3 -c \
        "import bcrypt, sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())" \
        "${ADMIN_PASSWORD}")
    unset ADMIN_PASSWORD  # ne pas garder le mot de passe en clair en mémoire
elif [[ -z "${ADMIN_PASSWORD_HASH:-}" ]]; then
    die "ADMIN_PASSWORD ou ADMIN_PASSWORD_HASH est requis.
  Exemple : -e ADMIN_PASSWORD=monmotdepasse"
fi

# ---------------------------------------------------------------------------
# 2. Gérer /app/analytics.conf (auth + settings configurés via le dashboard)
#
#    Ce fichier est stocké dans le volume persistant /app/data/ pour survivre
#    aux redémarrages. Les réglages TOTP sont gérés depuis le dashboard — on
#    ne les écrase jamais. On met seulement à jour ADMIN_PASSWORD_HASH,
#    LIGHT_MODE et ULTRA_LIGHT au démarrage.
# ---------------------------------------------------------------------------
ANALYTICS_CONF_PERSISTENT="/app/data/analytics.conf"
ANALYTICS_CONF="/app/analytics.conf"

# Symlink vers le volume persistant (survive aux redémarrages)
ln -sf "${ANALYTICS_CONF_PERSISTENT}" "${ANALYTICS_CONF}"

if [[ ! -f "${ANALYTICS_CONF_PERSISTENT}" ]]; then
    # Premier démarrage : créer le fichier avec les valeurs de base
    log "Création de analytics.conf (premier démarrage)..."
    cat > "${ANALYTICS_CONF_PERSISTENT}" <<EOF
# Géré par docker-entrypoint.sh et le dashboard HomelinkWG
# Les réglages TOTP sont configurés depuis l'interface web — ne pas éditer manuellement.
ADMIN_PASSWORD=${ADMIN_PASSWORD_HASH}
LIGHT_MODE=${LIGHT_MODE:-false}
ULTRA_LIGHT=${ULTRA_LIGHT:-false}
EOF
else
    # Démarrages suivants : mettre à jour uniquement ADMIN_PASSWORD + modes
    # sans toucher aux réglages TOTP configurés depuis le dashboard
    log "Mise à jour de analytics.conf (ADMIN_PASSWORD + modes)..."
    tmp=$(mktemp)
    # Mettre à jour ou ajouter chaque clé sans écraser les autres (ex: TOTP_*)
    update_kv() {
        local key="$1" val="$2" file="$3"
        if grep -q "^${key}=" "${file}"; then
            sed -i "s|^${key}=.*|${key}=${val}|" "${file}"
        else
            echo "${key}=${val}" >> "${file}"
        fi
    }
    cp "${ANALYTICS_CONF_PERSISTENT}" "${tmp}"
    update_kv "ADMIN_PASSWORD"  "${ADMIN_PASSWORD_HASH}"    "${tmp}"
    update_kv "LIGHT_MODE"      "${LIGHT_MODE:-false}"      "${tmp}"
    update_kv "ULTRA_LIGHT"     "${ULTRA_LIGHT:-false}"     "${tmp}"
    mv "${tmp}" "${ANALYTICS_CONF_PERSISTENT}"
fi
chmod 640 "${ANALYTICS_CONF_PERSISTENT}"

# ---------------------------------------------------------------------------
# 3. Prepare a writable config.json with optional env overrides
#    The mounted config.json may be read-only, so we work on a copy.
# ---------------------------------------------------------------------------
SOURCE_CONFIG="/app/config.source.json"
RUNTIME_CONFIG="/app/config.json"

[[ -f "${SOURCE_CONFIG}" ]] \
    || die "config.json not found. Mount it with:
  -v /path/to/your/config.json:/app/config.source.json:ro"

log "Copying config.json to writable runtime location..."
cp "${SOURCE_CONFIG}" "${RUNTIME_CONFIG}"

# Apply optional overrides from env vars
if [[ -n "${DASHBOARD_PORT:-}" ]]; then
    log "  Overriding dashboard.port -> ${DASHBOARD_PORT}"
    tmp=$(mktemp)
    jq ".dashboard.port = (\"${DASHBOARD_PORT}\" | tonumber)" "${RUNTIME_CONFIG}" > "${tmp}"
    mv "${tmp}" "${RUNTIME_CONFIG}"
fi

if [[ -n "${DASHBOARD_HOST:-}" ]]; then
    log "  Overriding dashboard.bind_address -> ${DASHBOARD_HOST}"
    tmp=$(mktemp)
    jq ".dashboard.bind_address = \"${DASHBOARD_HOST}\"" "${RUNTIME_CONFIG}" > "${tmp}"
    mv "${tmp}" "${RUNTIME_CONFIG}"
fi

if [[ -n "${ANALYTICS_ENABLED:-}" ]]; then
    log "  Overriding analytics.enabled -> ${ANALYTICS_ENABLED}"
    tmp=$(mktemp)
    jq ".analytics.enabled = (\"${ANALYTICS_ENABLED}\" == \"true\")" "${RUNTIME_CONFIG}" > "${tmp}"
    mv "${tmp}" "${RUNTIME_CONFIG}"
fi

if [[ -n "${WG_INTERFACE:-}" ]]; then
    log "  Overriding vpn.interface -> ${WG_INTERFACE}"
    tmp=$(mktemp)
    jq ".vpn.interface = \"${WG_INTERFACE}\"" "${RUNTIME_CONFIG}" > "${tmp}"
    mv "${tmp}" "${RUNTIME_CONFIG}"
fi

# Toujours mettre à jour vpn.config_file pour pointer vers le chemin réel dans le container.
# Le dashboard lit ce chemin pour extraire les AllowedIPs et vérifier les routes.
WG_IFACE_NAME="${WG_INTERFACE:-wg0}"
WG_CONF_PATH="${WG_CONFIG_FILE:-/etc/wireguard/${WG_IFACE_NAME}.conf}"
log "  Overriding vpn.config_file -> ${WG_CONF_PATH}"
tmp=$(mktemp)
jq ".vpn.config_file = \"${WG_CONF_PATH}\"" "${RUNTIME_CONFIG}" > "${tmp}"
mv "${tmp}" "${RUNTIME_CONFIG}"

# ---------------------------------------------------------------------------
# 4. Symlink SQLite DB into the persistent /app/data volume
#    dashboard.py writes to SCRIPT_DIR/homelinkwg-metrics.db = /app/homelinkwg-metrics.db
# ---------------------------------------------------------------------------
DB_PATH="/app/data/homelinkwg-metrics.db"
DB_LINK="/app/homelinkwg-metrics.db"
log "Linking SQLite DB: ${DB_LINK} -> ${DB_PATH}"
ln -sf "${DB_PATH}" "${DB_LINK}"

# ---------------------------------------------------------------------------
# 5. Bring up WireGuard
# ---------------------------------------------------------------------------
WG_IFACE="${WG_INTERFACE:-wg0}"
WG_CONF="${WG_CONFIG_FILE:-/etc/wireguard/${WG_IFACE}.conf}"

if [[ -f "${WG_CONF}" ]]; then
    log "Bringing up WireGuard interface ${WG_IFACE} from ${WG_CONF}..."
    # Remove any stale interface first (idempotent restart)
    wg-quick down "${WG_CONF}" 2>/dev/null || true
    if wg-quick up "${WG_CONF}" 2>&1; then
        log "WireGuard interface ${WG_IFACE} is up."
    else
        warn "wg-quick failed — dashboard will start but VPN status will show as DOWN."
    fi
else
    warn "No WireGuard config found at ${WG_CONF}."
    warn "Mount one with: -v /path/to/wg0.conf:/etc/wireguard/wg0.conf:ro"
    warn "Dashboard will start but VPN status will show as DOWN."
fi

# ---------------------------------------------------------------------------
# 6. Build supervisord configuration
#    - one [program:dashboard] block for Flask
#    - one [program:socat-PORT] block per enabled port forward in config.json
# ---------------------------------------------------------------------------
SUPERVISOR_CONF="/etc/supervisor/supervisord.conf"
DASHBOARD_PORT_VAL="${DASHBOARD_PORT:-5555}"

log "Generating supervisord configuration..."
cat > "${SUPERVISOR_CONF}" <<SUPEOF
[supervisord]
nodaemon=true
logfile=/dev/stdout
logfile_maxbytes=0
loglevel=${LOG_LEVEL:-info}
pidfile=/tmp/supervisord.pid
user=root

[unix_http_server]
file=/tmp/supervisor.sock
chmod=0700

[supervisorctl]
serverurl=unix:///tmp/supervisor.sock

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

; ── Flask dashboard ────────────────────────────────────────────────────────
[program:dashboard]
command=python3 /app/dashboard.py
directory=/app
autostart=true
autorestart=true
startretries=5
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
environment=PYTHONUNBUFFERED="1",HomelinkWG_RUNTIME="docker"

SUPEOF

# Validate config.json structure before parsing port forwards.
if ! jq -e '.ports | type == "array"' /app/config.json >/dev/null 2>&1; then
    die "config.json: '.ports' must be a JSON array"
fi

# Reject duplicate local_port values (otherwise supervisord/socat would fight each other)
DUP_PORTS=$(jq -r '.ports[].local_port' /app/config.json | sort | uniq -d)
if [[ -n "${DUP_PORTS}" ]]; then
    die "config.json: duplicate local_port values detected: $(echo "${DUP_PORTS}" | tr '\n' ' ')"
fi

# Parse config.json and add one socat block per enabled port forward
PORT_COUNT=0
SKIPPED=0
while IFS=$'\t' read -r local_port remote_host remote_port name enabled; do
    # Per-row validation — skip the row instead of crashing the whole startup
    if ! [[ "${local_port}" =~ ^[0-9]+$ ]] || (( local_port < 1 || local_port > 65535 )); then
        warn "Skipping port forward '${name}': invalid local_port '${local_port}' (must be 1-65535)."
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    if ! [[ "${remote_port}" =~ ^[0-9]+$ ]] || (( remote_port < 1 || remote_port > 65535 )); then
        warn "Skipping port forward '${name}': invalid remote_port '${remote_port}' (must be 1-65535)."
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    if [[ -z "${remote_host}" || "${remote_host}" == "null" ]]; then
        warn "Skipping port forward '${name}' (${local_port}): missing remote_host."
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    # Hostname/IP charset sanity check — reject obvious garbage and shell metacharacters
    if [[ ! "${remote_host}" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
        warn "Skipping port forward '${name}' (${local_port}): remote_host '${remote_host}' contains invalid characters."
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    if [[ "${enabled}" != "true" ]]; then
        warn "Port forward '${name}' (${local_port}) is disabled in config.json — skipping."
        continue
    fi
    log "  Registering socat: 0.0.0.0:${local_port} -> ${remote_host}:${remote_port}  (${name})"
    cat >> "${SUPERVISOR_CONF}" <<SUPEOF
; ── socat: ${name} ────────────────────────────────────────────────────────
[program:socat-${local_port}]
command=socat TCP-LISTEN:${local_port},fork,reuseaddr TCP:${remote_host}:${remote_port}
autostart=true
autorestart=true
startretries=10
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

SUPEOF
    PORT_COUNT=$((PORT_COUNT + 1))
done < <(jq -r '.ports[] | [(.local_port | tostring), .remote_host, (.remote_port | tostring), .name, ((.enabled // true) | tostring)] | @tsv' /app/config.json)

log "Registered ${PORT_COUNT} socat port forward(s) (skipped ${SKIPPED} invalid)."
if (( PORT_COUNT == 0 )); then
    warn "No valid port forwards registered — dashboard will start but no socat services will run."
fi

# ---------------------------------------------------------------------------
# 7. Hand off to supervisord (becomes PID 1)
# ---------------------------------------------------------------------------
log "Starting supervisord (dashboard on :${DASHBOARD_PORT_VAL})..."
exec /usr/bin/supervisord -c "${SUPERVISOR_CONF}"
