# Cerberus v2 — backend (core scanner + embedded API server)
#
# Runs with --network host and NET_RAW/NET_ADMIN capabilities (see
# docker-compose.yml) because real ARP scanning needs to see the
# actual LAN, not Docker's isolated bridge network — a bridge-mode
# container would only ever see itself and other containers, never
# your real devices.
FROM python:3.11-slim

# nmap: the actual scanning binary python-nmap wraps.
# iproute2: gives netifaces-plus something to introspect for interface/
#   gateway detection inside the container.
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cerberus/ ./cerberus/
COPY cerberus_main.py .

# npcap_installer.py is deliberately NOT copied — see .dockerignore.
# It's Windows-only and irrelevant inside a Linux container; the
# import in cerberus_main.py is defensive specifically for this case
# (see the try/except around it there)

RUN mkdir -p data logs config

CMD ["python", "cerberus_main.py"]