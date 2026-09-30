#!/usr/bin/env bash
# =====================================================================
#  Alert viewer for Suricata logs (run on the SENSOR).
#
#  Usage:
#    sudo ./show_alerts.sh live      # stream alerts as they happen (fast.log)
#    sudo ./show_alerts.sh recent    # last 30 alerts, readable table
#    sudo ./show_alerts.sh summary   # count of alerts per signature + per source IP
#    sudo ./show_alerts.sh local     # only the LOCAL custom-rule alerts
#    sudo ./show_alerts.sh notify you@example.com   # email each new alert (needs mailutils)
# =====================================================================
FAST=/var/log/suricata/fast.log
EVE=/var/log/suricata/eve.json
MODE="${1:-recent}"

command -v jq >/dev/null || { echo "Install jq:  sudo apt install jq"; exit 1; }
[[ -f "$FAST" ]] || { echo "No $FAST yet - is Suricata running? (systemctl status suricata)"; exit 1; }

case "$MODE" in
  live)
    echo "Streaming alerts (Ctrl+C to stop)..."
    tail -Fn0 "$FAST"
    ;;
  recent)
    jq -r 'select(.event_type=="alert") |
      [.timestamp[0:19], .src_ip, .dest_ip, .alert.signature] | @tsv' "$EVE" \
      | tail -n 30 | column -t -s $'\t'
    ;;
  summary)
    echo "=== Alerts per signature ==="
    jq -r 'select(.event_type=="alert") | .alert.signature' "$EVE" | sort | uniq -c | sort -rn | head -n 15
    echo
    echo "=== Alerts per source IP ==="
    jq -r 'select(.event_type=="alert") | .src_ip' "$EVE" | sort | uniq -c | sort -rn | head -n 10
    ;;
  local)
    grep "LOCAL" "$FAST" | tail -n 50
    ;;
  notify)
    ADDR="${2:-}"; [[ -n "$ADDR" ]] || { echo "Usage: $0 notify you@example.com"; exit 1; }
    command -v mail >/dev/null || { echo "Install mail:  sudo apt install mailutils"; exit 1; }
    echo "Emailing new alerts to $ADDR (Ctrl+C to stop)..."
    tail -Fn0 "$FAST" | while read -r line; do
      echo "$line" | mail -s "Suricata Alert" "$ADDR"
    done
    ;;
  *)
    sed -n '2,11p' "$0"; exit 1 ;;
esac
