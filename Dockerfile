###############################################################################
# HomelinkWG - Multi-stage Dockerfile
# WireGuard VPN dashboard & port-forward manager
###############################################################################

# Stage 1: Builder - compile Python dependencies
FROM python:3.11-slim as builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime - minimal final image
FROM python:3.11-slim

LABEL description="HomelinkWG - WireGuard dashboard & socat port-forward manager"

# Copy only compiled Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# System dependencies, iptables config, DNS workaround
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    socat \
    iproute2 \
    iptables \
    iputils-ping \
    netcat-openbsd \
    jq \
    supervisor \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy \
    && printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/resolvconf \
    && chmod +x /usr/local/bin/resolvconf

# ---------------------------------------------------------------------------
# Application files
# ---------------------------------------------------------------------------
WORKDIR /app
COPY dashboard.py .
COPY images/ ./images/
COPY RELEASE_NOTES.md .
COPY health-check.sh .
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN mkdir -p /app/data /var/log/supervisor /etc/supervisor/conf.d /etc/wireguard \
    && chmod +x /app/health-check.sh /usr/local/bin/entrypoint.sh

# ---------------------------------------------------------------------------
# Expose & volumes
# ---------------------------------------------------------------------------
EXPOSE 5555
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python3 -c \
        "import urllib.request, os; \
         p = os.environ.get('DASHBOARD_PORT', '5555'); \
         urllib.request.urlopen(f'http://localhost:{p}/api/livez')" \
    || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
