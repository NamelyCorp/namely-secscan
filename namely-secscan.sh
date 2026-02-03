#!/usr/bin/env bash
# Namely SecScan
# Version: 1.0.0
# A safe, read-only VPS security scanner with full reporting

set -euo pipefail

OUT_BASE="/root/security-reports"
APACHE_LOG_DIR="/var/log/apache2"
AUTH_LOG="/var/log/auth.log"

SIG_REGEX='eval\(|base64_decode\(|gzinflate\(|shell_exec\(|system\(|passthru\(|popen\(|proc_open\(|assert\(|preg_replace\(.*/e|`whoami`|`id`|chmod\ 777|curl\ .*sh|wget\ .*sh'
SENSITIVE_URL_REGEX='(/\.env\b|/\.git\b|/wp-config\.php\b|/composer\.json\b|/vendor/|/phpinfo\.php\b)'

ts() { date +"%Y-%m-%d_%H%M%S"; }
have() { command -v "$1" >/dev/null 2>&1; }

[[ $EUID -ne 0 ]] && echo "Run as root (sudo)" && exit 1

HOST=$(hostname)
NOW=$(ts)
OUT_DIR="${OUT_BASE}/${HOST}_${NOW}"
mkdir -p "$OUT_DIR/raw"

REPORT="$OUT_DIR/REPORT.md"
SUMMARY="$OUT_DIR/SUMMARY.txt"

echo "# Namely SecScan Report" > "$REPORT"
echo "- Host: $HOST" >> "$REPORT"
echo "- Timestamp: $NOW" >> "$REPORT"
echo "" >> "$REPORT"

run() {
  local title="$1"; shift
  local file="$1"; shift
  {
    echo "## $title"
    echo '```'
    "$@" || true
    echo '```'
    echo
  } >> "$REPORT"
  "$@" > "$file" 2>&1 || true
}

run "System Info" "$OUT_DIR/raw/system.txt" uname -a
run "Uptime" "$OUT_DIR/raw/uptime.txt" uptime
run "Disk Usage" "$OUT_DIR/raw/df.txt" df -hT
run "Memory" "$OUT_DIR/raw/memory.txt" free -h
run "Top CPU Processes" "$OUT_DIR/raw/ps_cpu.txt" bash -c "ps aux --sort=-%cpu | head -25"
run "Listening Ports" "$OUT_DIR/raw/ports.txt" ss -tulpn
run "Logged-in Users" "$OUT_DIR/raw/who.txt" w
run "Recent Logins" "$OUT_DIR/raw/last.txt" bash -c "last -a | head -30"
run "UID 0 Accounts" "$OUT_DIR/raw/uid0.txt" awk -F: '($3==0){print}' /etc/passwd
run "Root Cron" "$OUT_DIR/raw/cron_root.txt" crontab -l || true
run "Enabled systemd Units" "$OUT_DIR/raw/systemd.txt" systemctl list-unit-files --state=enabled

if [[ -f "$AUTH_LOG" ]]; then
  run "SSH Accepted Logins" "$OUT_DIR/raw/ssh_ok.txt" grep -i "Accepted " "$AUTH_LOG"
  run "SSH Failed Logins" "$OUT_DIR/raw/ssh_fail.txt" grep -i "Failed " "$AUTH_LOG"
fi

if [[ -d "$APACHE_LOG_DIR" ]]; then
  run "Apache Sensitive URL Probes" "$OUT_DIR/raw/apache_sensitive.txt" bash -c "grep -R \"$SENSITIVE_URL_REGEX\" $APACHE_LOG_DIR || true"
  run "Apache .env Probes" "$OUT_DIR/raw/apache_env.txt" bash -c "grep -R '\\.env' $APACHE_LOG_DIR || true"
fi

run "Webshell Signature Scan" "$OUT_DIR/raw/webshells.txt" bash -c "grep -RInE \"$SIG_REGEX\" /var/www 2>/dev/null || true"

if have clamscan; then
  run "ClamAV Scan (/var/www)" "$OUT_DIR/raw/clamav.txt" clamscan -r --infected /var/www || true
fi

if have rkhunter; then
  run "rkhunter" "$OUT_DIR/raw/rkhunter.txt" rkhunter --check --sk --rwo || true
fi

if have chkrootkit; then
  run "chkrootkit" "$OUT_DIR/raw/chkrootkit.txt" chkrootkit || true
fi

echo "Namely SecScan Summary" > "$SUMMARY"
echo "Host: $HOST" >> "$SUMMARY"
echo "When: $NOW" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Review REPORT.md for full details." >> "$SUMMARY"

tar -czf "${OUT_DIR}.tar.gz" -C "$OUT_BASE" "$(basename "$OUT_DIR")"

echo "Scan complete."
