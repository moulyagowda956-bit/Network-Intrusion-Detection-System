#!/usr/bin/env bash
# =====================================================================
#  Network Intrusion Detection System - automated setup (Suricata)
#  Tested on Ubuntu / Debian. Run on the SENSOR machine.
#
#  Usage:
#    sudo ./setup_nids.sh                    # normal: two machines (sensor + attacker)
#    sudo ./setup_nids.sh --single-machine   # demo on ONE machine (monitors loopback)
#    sudo ./setup_nids.sh --iface ens33      # force a specific interface
#    sudo ./setup_nids.sh --home-net 10.0.0.0/24
#
#  Only use on machines/networks you own.
# =====================================================================
set -euo pipefail

SURICATA_YAML="/etc/suricata/suricata.yaml"
RULES_DIR="/etc/suricata/rules"
LOCAL_RULES="$RULES_DIR/local.rules"
SINGLE=0
IFACE=""
HOME_NET=""

# ---------- argument parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --single-machine) SINGLE=1; shift ;;
    --iface)          IFACE="$2"; shift 2 ;;
    --home-net)       HOME_NET="$2"; shift 2 ;;
    -h|--help)        sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

log()  { echo -e "\n\033[1;34m[+] $*\033[0m"; }
warn() { echo -e "\033[1;33m[!] $*\033[0m"; }
die()  { echo -e "\033[1;31m[x] $*\033[0m"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root:  sudo $0"

# ---------- Step 1: install ----------
log "Step 1/7: Installing Suricata, jq and a test web server"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y software-properties-common curl jq apache2 openssh-server
if ! command -v suricata >/dev/null 2>&1; then
  add-apt-repository -y ppa:oisf/suricata-stable || warn "PPA not available, using distro package"
  apt-get update -y
  apt-get install -y suricata
fi
suricata --build-info | head -n 5

# ---------- Step 2: detect interface & network ----------
log "Step 2/7: Detecting network settings"
if [[ $SINGLE -eq 1 ]]; then
  IFACE="lo"
  HOME_NET="127.0.0.0/8"
  warn "Single-machine mode: monitoring loopback (lo). Attack 127.0.0.1 with run_attacks.sh"
else
  [[ -n "$IFACE" ]] || IFACE="$(ip route | awk '/default/ {print $5; exit}')"
  [[ -n "$IFACE" ]] || die "Could not detect interface. Use --iface <name>"
  if [[ -z "$HOME_NET" ]]; then
    HOME_NET="$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | head -n1)"
    # convert host address (e.g. 192.168.1.10/24) to network address
    HOME_NET="$(python3 - "$HOME_NET" <<'PY'
import ipaddress, sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)"
  fi
fi
echo "    Interface : $IFACE"
echo "    HOME_NET  : $HOME_NET"

# ---------- Step 3: configure suricata.yaml ----------
log "Step 3/7: Configuring $SURICATA_YAML"
[[ -f "$SURICATA_YAML" ]] || die "$SURICATA_YAML not found"
cp -n "$SURICATA_YAML" "$SURICATA_YAML.orig.bak" || true

# HOME_NET
sed -i "s|^\(\s*\)HOME_NET:.*|\1HOME_NET: \"[$HOME_NET]\"|" "$SURICATA_YAML"
# capture interface (first af-packet entry)
sed -i "0,/- interface: .*/s//- interface: $IFACE/" "$SURICATA_YAML"
# register local.rules (absolute path so default-rule-path does not matter)
if ! grep -q "$LOCAL_RULES" "$SURICATA_YAML"; then
  sed -i "0,/^\(\s*\)- suricata.rules/s||&\n\1- $LOCAL_RULES|" "$SURICATA_YAML"
fi
grep -nE "HOME_NET:|- interface:|local.rules" "$SURICATA_YAML" | head

# ---------- Step 4: download community rules ----------
log "Step 4/7: Downloading Emerging Threats Open rules (suricata-update)"
suricata-update || warn "suricata-update failed (offline?). Custom rules will still work."

# ---------- Step 5: custom rules ----------
log "Step 5/7: Writing custom rules to $LOCAL_RULES"
mkdir -p "$RULES_DIR"
cat > "$LOCAL_RULES" <<'RULES'
# ================= LOCAL CUSTOM RULES (SID 1,000,000+) =================

# 1. ICMP ping detected
alert icmp any any -> $HOME_NET any (msg:"LOCAL ICMP ping detected"; itype:8; sid:1000001; rev:1;)

# 2. SSH brute force: 5+ new connections to port 22 in 60s from one source
alert tcp any any -> $HOME_NET 22 (msg:"LOCAL SSH brute force attempt"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000002; rev:1;)

# 3. Port scan: 20+ SYNs from one source in 10s
alert tcp any any -> $HOME_NET any (msg:"LOCAL Possible port scan"; flags:S; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:1000003; rev:1;)

# 4. SQL injection in URL
alert http any any -> $HOME_NET any (msg:"LOCAL SQL injection attempt"; flow:established,to_server; http.uri; content:"union"; nocase; content:"select"; nocase; distance:0; classtype:web-application-attack; sid:1000004; rev:1;)

# 5. Directory traversal
alert http any any -> $HOME_NET any (msg:"LOCAL Directory traversal attempt"; flow:established,to_server; http.uri; content:"../"; classtype:web-application-attack; sid:1000005; rev:1;)

# 6. Telnet (cleartext protocol)
alert tcp any any -> $HOME_NET 23 (msg:"LOCAL Telnet connection attempt"; flow:to_server; flags:S; sid:1000006; rev:1;)
RULES
echo "    $(grep -c '^alert' "$LOCAL_RULES") custom rules written."

# ---------- Step 6: validate ----------
log "Step 6/7: Validating configuration and rules (suricata -T)"
if suricata -T -c "$SURICATA_YAML" -v; then
  echo -e "\033[1;32m    Configuration test PASSED\033[0m"
else
  die "Configuration test FAILED - read the errors above"
fi

# ---------- Step 7: start ----------
log "Step 7/7: Starting Suricata"
systemctl enable suricata >/dev/null 2>&1 || true
systemctl restart suricata
sleep 5
systemctl --no-pager status suricata | head -n 12 || true

cat <<EOF

====================================================================
 SETUP COMPLETE
 Interface : $IFACE      HOME_NET : $HOME_NET
 Sensor IP : $(hostname -I 2>/dev/null | awk '{print $1}')

 Next steps
   1. Watch alerts :  sudo ./show_alerts.sh live
   2. Attack       :  sudo ./run_attacks.sh <sensor-ip>     (from attacker machine)
                      sudo ./run_attacks.sh 127.0.0.1       (if --single-machine)
   3. Summary      :  sudo ./show_alerts.sh summary
   Take screenshots of each step for your report.
====================================================================
EOF
