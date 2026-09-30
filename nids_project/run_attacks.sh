#!/usr/bin/env bash
# =====================================================================
#  Attack simulator - triggers every custom Suricata rule.
#  Run from the ATTACKER machine (or same machine with 127.0.0.1
#  if the sensor was set up with --single-machine).
#
#  Usage:  sudo ./run_attacks.sh <sensor-ip>
#
#  Only run against machines you own.
# =====================================================================
set -uo pipefail

TARGET="${1:-}"
[[ -n "$TARGET" ]] || { echo "Usage: sudo $0 <sensor-ip>"; exit 1; }

step() { echo -e "\n\033[1;34m[TEST $1] $2\033[0m"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "Target: $TARGET"
echo "Make sure Suricata is running on the target and 'sudo ./show_alerts.sh live' is open there."
read -r -p "Press ENTER to start the attacks..." _

# 1. ICMP ping -> LOCAL ICMP ping detected
step 1 "ICMP ping"
ping -c 4 "$TARGET"
sleep 2

# 2. Port scan -> LOCAL Possible port scan
step 2 "Port scan (SYN scan of ports 1-1000)"
if have nmap; then
  nmap -sS -p 1-1000 "$TARGET" || nmap -sT -p 1-1000 "$TARGET"
else
  echo "nmap missing - using bash fallback (150 fast connections)"
  for p in $(seq 1 150); do (timeout 0.2 bash -c "echo > /dev/tcp/$TARGET/$p" 2>/dev/null &) ; done
  wait
fi
sleep 3

# 3. SSH brute force -> LOCAL SSH brute force attempt
step 3 "SSH brute force (10 rapid connections to port 22)"
for i in $(seq 1 10); do
  timeout 2 bash -c "echo > /dev/tcp/$TARGET/22" 2>/dev/null
done
if have hydra; then
  printf "admin\nroot\n123456\npassword\ntest\nletmein\n" > /tmp/nids_wordlist.txt
  echo "Running hydra as well..."
  hydra -l test -P /tmp/nids_wordlist.txt "ssh://$TARGET" -t 4 2>/dev/null | tail -n 3
fi
sleep 3

# 4. SQL injection -> LOCAL SQL injection attempt
step 4 "SQL injection in URL"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://$TARGET/?id=1%20UNION%20SELECT%201,2"
sleep 2

# 5. Directory traversal -> LOCAL Directory traversal attempt
step 5 "Directory traversal"
curl -s -o /dev/null -w "HTTP %{http_code}\n" --path-as-is "http://$TARGET/../../etc/passwd"
sleep 2

# 6. Telnet -> LOCAL Telnet connection attempt
step 6 "Telnet connection to port 23"
timeout 2 bash -c "echo > /dev/tcp/$TARGET/23" 2>/dev/null || echo "(port closed - the SYN was still sent)"
sleep 2

# 7. Community-rule sanity test (needs internet on the machine running it)
step 7 "Emerging Threats sanity test (testmynids.org)"
curl -s -m 10 http://testmynids.org/uid/index.html || echo "(no internet - skipped)"

echo -e "\n\033[1;32mAll tests sent.\033[0m Now check alerts on the sensor:"
echo "   sudo ./show_alerts.sh recent"
