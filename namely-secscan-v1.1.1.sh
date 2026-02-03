#!/usr/bin/env bash
# Namely SecScan v1.1.1
# Read-only VPS security scanner that generates a full audit report.
# Repo: namely-secscan
#
# v1.1.1 hotfix:
# - Fixed AIDE initialization hanging issue
# - Added warning about AIDE init taking 5-30+ minutes
# - Made AIDE initialization optional during install
# - Added progress messages for all tool installations
#
# v1.1.0 improvements:
# - Fixed ASCII art to properly say "NamelyCorp"
# - Added progress indicators for each scan stage
# - Enhanced summary with actual findings and actionable insights
# - Added dependency checking with install prompts
# - Improved REPORT.md with detailed section explanations
#
set -euo pipefail

VERSION="1.1.1"
SCRIPT_NAME="$(basename "$0")"

# ---------------------------
# Defaults (override via args)
# ---------------------------
MODE="quick"                           # quick | deep
OUT_BASE="/var/reports/namely-secscan" # team-friendly default
WEBROOT="/var/www"                     # typical webroot; override if needed
MAKE_JSON="false"

# Interactive UX defaults
INTERACTIVE="auto"   # auto | true | false
ASSUME_YES="false"   # if true, answer "yes" to all prompts
NO_COLOR="false"

# Module toggles (may be prompted)
DO_SYSTEM="true"
DO_USERS="true"
DO_NETWORK="true"
DO_WEBROOT="true"
DO_LOGS="true"
DO_PERSISTENCE="true"
DO_MALWARE="false"   # default off unless deep or user says yes
DO_SUID="false"      # deep only unless user says yes

# Progress tracking
TOTAL_STEPS=0
CURRENT_STEP=0

# Findings tracking
declare -A FINDINGS
FINDINGS[critical]=0
FINDINGS[warning]=0
FINDINGS[info]=0
FINDINGS[details]=""

# ---------------
# Helper functions
# ---------------
die() { echo "ERROR: $*" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

color() { # $1=code $2=text
  if [[ "$NO_COLOR" == "true" ]]; then echo -e "$2"; else echo -e "\033[${1}m${2}\033[0m"; fi
}
hr() { printf "%s\n" "$(color "2" "────────────────────────────────────────────────────────────────────────")"; }

banner() {
  cat <<'EOF'
 _   _                      _        _____                
| \ | |                    | |      / ____|               
|  \| | __ _ _ __ ___   ___| |_   _| |     ___  _ __ _ __  
| . ` |/ _` | '_ ` _ \ / _ \ | | | | |    / _ \| '__| '_ \ 
| |\  | (_| | | | | | |  __/ | |_| | |___| (_) | |  | |_) |
|_| \_|\__,_|_| |_| |_|\___|_|\__, |\_____\___/|_|  | .__/ 
                               __/ |                | |    
                              |___/                 |_|    

              NamelyCorp • Security Scanner
EOF
}

info() { echo "$(color "1;34" "[INFO]") $*"; }
warn() { echo "$(color "1;33" "[WARN]") $*"; }
good() { echo "$(color "1;32" "[ OK ]") $*"; }
head1() { hr; echo "$(color "1;36" "▶ $*")"; hr; }

progress() {
  CURRENT_STEP=$((CURRENT_STEP + 1))
  local percent=$((CURRENT_STEP * 100 / TOTAL_STEPS))
  local bar_length=40
  local filled=$((percent * bar_length / 100))
  local empty=$((bar_length - filled))
  
  printf "\r$(color "1;36" "Progress:") ["
  printf "%${filled}s" | tr ' ' '█'
  printf "%${empty}s" | tr ' ' '░'
  printf "] %3d%% (%d/%d) - %s" "$percent" "$CURRENT_STEP" "$TOTAL_STEPS" "$1"
  
  if [[ $CURRENT_STEP -eq $TOTAL_STEPS ]]; then
    echo ""
  fi
}

add_finding() {
  local severity="$1"  # critical, warning, info
  local message="$2"
  
  FINDINGS[$severity]=$((FINDINGS[$severity] + 1))
  FINDINGS[details]+="[$severity] $message"$'\n'
}

sanitize_text() {
  # Redact common secret patterns from REPORT.md (best-effort)
  sed -E \
    -e 's/(AWS(_| )?ACCESS(_| )?KEY(_| )?ID|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9\/+=._-]+/\1: [REDACTED]/Ig' \
    -e 's/(OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|API_KEY|SECRET_KEY|PRIVATE_KEY)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1: [REDACTED]/Ig' \
    -e 's/(Bearer)[[:space:]]+[A-Za-z0-9\._=-]+/\1 [REDACTED]/g' \
    -e 's/(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/[REDACTED_JWT]/g'
}

safe_mkdir() { mkdir -p "$1"; }

write_section_header() {
  local title="$1"
  local description="$2"
  
  cat >>"$REPORT_MD" <<EOF

---

## ${title}

**Purpose:** ${description}

**What to look for:**
EOF
}

# Execute once; write to human report (redacted) and raw file (unredacted)
run() {
  local title="$1"; shift
  local fname="$1"; shift
  local description="$1"; shift
  local lookfor="$1"; shift
  local cmd=( "$@" )

  write_section_header "$title" "$description"
  
  echo "" >>"$REPORT_MD"
  echo "$lookfor" >>"$REPORT_MD"
  echo "" >>"$REPORT_MD"
  echo "**Command:** \`${cmd[*]}\`" >>"$REPORT_MD"
  echo "" >>"$REPORT_MD"
  echo '```' >>"$REPORT_MD"

  set +e
  local output
  output="$("${cmd[@]}" 2>&1)"
  local rc=$?
  set -e

  printf "%s\n" "$output" >"${RAW_DIR}/${fname}"
  printf "%s\n" "$output" | sanitize_text >>"$REPORT_MD"

  echo '```' >>"$REPORT_MD"
  echo "" >>"$REPORT_MD"
  echo "**Exit code:** ${rc}" >>"$REPORT_MD"
  
  # Analyze output for findings
  analyze_output "$title" "$fname" "$output" "$rc"
  
  return 0
}

analyze_output() {
  local title="$1"
  local fname="$2"
  local output="$3"
  local exitcode="$4"
  
  # System checks
  if [[ "$fname" == "uid0.txt" ]] && [[ $(echo "$output" | wc -l) -gt 1 ]]; then
    add_finding "warning" "Multiple UID 0 accounts found (check ${fname})"
  fi
  
  # Web exposure checks
  if [[ "$fname" == "webroot-find.txt" ]]; then
    local env_count=$(echo "$output" | grep -c "\.env" 2>/dev/null || true)
    local git_count=$(echo "$output" | grep -c "\.git" 2>/dev/null || true)
    local backup_count=$(echo "$output" | grep -c -E "\.(bak|old|backup)" 2>/dev/null || true)
    
    if [[ $env_count -gt 0 ]]; then
      add_finding "critical" "Found $env_count .env file(s) in webroot - IMMEDIATE ACTION REQUIRED"
    fi
    if [[ $git_count -gt 0 ]]; then
      add_finding "critical" "Found $git_count .git director(y/ies) in webroot - source code exposure risk"
    fi
    if [[ $backup_count -gt 0 ]]; then
      add_finding "warning" "Found $backup_count backup file(s) in webroot - potential info disclosure"
    fi
  fi
  
  # SSH security
  if [[ "$fname" == "ssh-fails.txt" ]]; then
    local fail_count=$(echo "$output" | wc -l)
    if [[ $fail_count -gt 100 ]]; then
      add_finding "warning" "High SSH brute force activity: $fail_count failed attempts from top IPs"
    fi
  fi
  
  # Web probes
  if [[ "$fname" =~ web-probes.*\.txt ]]; then
    local probe_count=$(echo "$output" | wc -l)
    if [[ $probe_count -gt 50 ]]; then
      add_finding "warning" "High web scanning activity: $probe_count suspicious requests detected"
    fi
  fi
  
  # Malware scans
  if [[ "$fname" == "clamav-scan.txt" ]] && echo "$output" | grep -q "FOUND"; then
    add_finding "critical" "ClamAV detected potential malware - review ${fname} immediately"
  fi
  
  if [[ "$fname" == "rkhunter-check.txt" ]] && echo "$output" | grep -q "Warning"; then
    add_finding "warning" "rkhunter detected warnings - review ${fname}"
  fi
  
  # SUID findings
  if [[ "$fname" == "suid-sgid.txt" ]]; then
    local unusual_suid=$(echo "$output" | grep -vE "(sudo|su|ping|mount|umount|passwd)" | wc -l)
    if [[ $unusual_suid -gt 5 ]]; then
      add_finding "info" "Found $unusual_suid unusual SUID/SGID binaries - review for legitimacy"
    fi
  fi
}

write_kv() { printf "%-32s %s\n" "$1" "$2" >>"$SUMMARY_TXT"; }

is_tty() { [[ -t 0 && -t 1 ]]; }

ask_yn() {
  # ask_yn "Question?" default(Y/N) -> returns 0 for yes, 1 for no
  local q="$1"
  local def="${2:-Y}"
  local prompt def_show
  if [[ "$def" == "Y" ]]; then def_show="Y/n"; else def_show="y/N"; fi

  if [[ "$ASSUME_YES" == "true" ]]; then
    good "$q -> yes (assume-yes)"
    return 0
  fi

  if [[ "$INTERACTIVE" == "false" ]]; then
    # non-interactive: use default
    if [[ "$def" == "Y" ]]; then return 0; else return 1; fi
  fi

  while true; do
    read -r -p "$(color "1;35" "?") $q [$def_show]: " prompt || true
    prompt="${prompt:-$def}"
    case "${prompt,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

# ----------------
# Dependency check
# ----------------
check_dependencies() {
  echo ""
  head1 "Dependency Check"
  
  local missing=()
  local optional=()
  
  # Core tools (should be present)
  for tool in grep sed awk find ss systemctl; do
    if ! have "$tool"; then
      missing+=("$tool")
    fi
  done
  
  # Security scanning tools (optional but recommended)
  declare -A optional_tools=(
    ["clamscan"]="ClamAV - Antivirus scanner"
    ["rkhunter"]="rkhunter - Rootkit hunter"
    ["chkrootkit"]="chkrootkit - Rootkit checker"
    ["aide"]="AIDE - File integrity checker"
  )
  
  echo ""
  echo "$(color "1;37" "Core tools check:")"
  for tool in grep sed awk find ss systemctl; do
    if have "$tool"; then
      good "$tool is installed"
    else
      warn "$tool is MISSING"
    fi
  done
  
  echo ""
  echo "$(color "1;37" "Security scanning tools:")"
  for tool in "${!optional_tools[@]}"; do
    if have "$tool"; then
      good "$tool is installed - ${optional_tools[$tool]}"
    else
      warn "$tool is not installed - ${optional_tools[$tool]}"
      optional+=("$tool")
    fi
  done
  
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo ""
    die "Missing required tools: ${missing[*]}. Please install them first."
  fi
  
  if [[ ${#optional[@]} -gt 0 ]] && [[ "$INTERACTIVE" == "true" ]]; then
    echo ""
    echo "$(color "1;33" "Optional security tools are missing.")"
    echo "These tools provide additional malware and rootkit detection capabilities."
    echo ""
    
    if ask_yn "Would you like installation commands for missing tools?" "Y"; then
      echo ""
      echo "$(color "1;36" "Installation commands:")"
      echo ""
      
      # Detect package manager
      if have apt-get; then
        echo "# Debian/Ubuntu:"
        for tool in "${optional[@]}"; do
          case "$tool" in
            clamscan) echo "  sudo apt-get install -y clamav clamav-daemon && sudo freshclam" ;;
            rkhunter) echo "  sudo apt-get install -y rkhunter" ;;
            chkrootkit) echo "  sudo apt-get install -y chkrootkit" ;;
            aide) echo "  sudo apt-get install -y aide && sudo aideinit" ;;
          esac
        done
      elif have yum; then
        echo "# RHEL/CentOS:"
        for tool in "${optional[@]}"; do
          case "$tool" in
            clamscan) echo "  sudo yum install -y clamav clamav-update && sudo freshclam" ;;
            rkhunter) echo "  sudo yum install -y rkhunter" ;;
            chkrootkit) echo "  sudo yum install -y chkrootkit" ;;
            aide) echo "  sudo yum install -y aide && sudo aide --init" ;;
          esac
        done
      fi
      echo ""
      
      if ask_yn "Install missing tools now?" "N"; then
        echo ""
        info "Installing missing security tools..."
        
        # Check if AIDE is in the list and warn about init time
        local has_aide=false
        for tool in "${optional[@]}"; do
          if [[ "$tool" == "aide" ]]; then
            has_aide=true
            break
          fi
        done
        
        if [[ "$has_aide" == "true" ]]; then
          echo ""
          warn "AIDE requires initialization which scans ALL files on your system."
          warn "This can take 5-30 minutes or longer depending on system size."
          echo ""
        fi
        
        if have apt-get; then
          for tool in "${optional[@]}"; do
            case "$tool" in
              clamscan)
                info "Installing ClamAV..."
                sudo apt-get update && sudo apt-get install -y clamav clamav-daemon
                info "Updating virus definitions (this may take a minute)..."
                sudo freshclam || warn "freshclam failed, but clamav is installed"
                good "ClamAV installed"
                ;;
              rkhunter) 
                info "Installing rkhunter..."
                sudo apt-get install -y rkhunter
                good "rkhunter installed"
                ;;
              chkrootkit) 
                info "Installing chkrootkit..."
                sudo apt-get install -y chkrootkit
                good "chkrootkit installed"
                ;;
              aide) 
                info "Installing AIDE..."
                sudo apt-get install -y aide
                good "AIDE package installed"
                echo ""
                warn "AIDE needs initialization before use. This scans all files and takes 5-30+ minutes."
                if ask_yn "Initialize AIDE database now? (You can skip and run 'sudo aideinit' later)" "N"; then
                  info "Initializing AIDE database... This will take a while. Please be patient."
                  sudo aideinit || warn "aideinit failed, but aide is installed. Run 'sudo aideinit' manually later."
                  good "AIDE initialized"
                else
                  warn "AIDE installed but not initialized. Run 'sudo aideinit' before using AIDE."
                fi
                ;;
            esac
          done
        elif have yum; then
          for tool in "${optional[@]}"; do
            case "$tool" in
              clamscan)
                info "Installing ClamAV..."
                sudo yum install -y clamav clamav-update
                info "Updating virus definitions..."
                sudo freshclam || warn "freshclam failed, but clamav is installed"
                good "ClamAV installed"
                ;;
              rkhunter) 
                info "Installing rkhunter..."
                sudo yum install -y rkhunter
                good "rkhunter installed"
                ;;
              chkrootkit) 
                info "Installing chkrootkit..."
                sudo yum install -y chkrootkit
                good "chkrootkit installed"
                ;;
              aide)
                info "Installing AIDE..."
                sudo yum install -y aide
                good "AIDE package installed"
                echo ""
                warn "AIDE needs initialization before use. This scans all files and takes 5-30+ minutes."
                if ask_yn "Initialize AIDE database now? (You can skip and run 'sudo aide --init' later)" "N"; then
                  info "Initializing AIDE database... This will take a while. Please be patient."
                  sudo aide --init || warn "aide init failed, but aide is installed. Run 'sudo aide --init' manually later."
                  good "AIDE initialized"
                else
                  warn "AIDE installed but not initialized. Run 'sudo aide --init' before using AIDE."
                fi
                ;;
            esac
          done
        fi
        
        echo ""
        good "Installation complete! Re-run the scan to use new tools."
        echo ""
      fi
    fi
  fi
  
  echo ""
}

# ----------------
# Argument parsing
# ----------------
usage() {
  cat <<EOF
Namely SecScan v${VERSION}

Usage:
  sudo bash ${SCRIPT_NAME} [options]

Core options:
  --quick             Fast checks (default)
  --deep              Includes heavier checks (suggested for incident response)
  --out PATH          Output base directory (default: ${OUT_BASE})
  --webroot PATH      Web root to scan for .env/.git/backup exposure patterns (default: ${WEBROOT})
  --json              Produce a machine-readable summary.json in the report directory

UI / interactive:
  --interactive       Force Y/N prompts
  --no-interactive    Disable prompts (use defaults)
  --yes               Assume "yes" to prompts (useful for automation)
  --no-color          Disable ANSI colors

Examples:
  sudo bash ${SCRIPT_NAME} --quick
  sudo bash ${SCRIPT_NAME} --deep --interactive
  sudo bash ${SCRIPT_NAME} --deep --webroot /var/www --out /var/reports/namely-secscan --json
  sudo bash ${SCRIPT_NAME} --no-interactive --deep --yes

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) MODE="quick"; shift ;;
    --deep) MODE="deep"; shift ;;
    --out) OUT_BASE="${2:-}"; [[ -n "$OUT_BASE" ]] || die "--out requires a path"; shift 2 ;;
    --webroot) WEBROOT="${2:-}"; [[ -n "$WEBROOT" ]] || die "--webroot requires a path"; shift 2 ;;
    --json) MAKE_JSON="true"; shift ;;
    --interactive) INTERACTIVE="true"; shift ;;
    --no-interactive) INTERACTIVE="false"; shift ;;
    --yes) ASSUME_YES="true"; shift ;;
    --no-color) NO_COLOR="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (try --help)" ;;
  esac
done

# Decide interactive default
if [[ "$INTERACTIVE" == "auto" ]]; then
  if is_tty; then INTERACTIVE="true"; else INTERACTIVE="false"; fi
fi

# Default deep-mode module toggles
if [[ "$MODE" == "deep" ]]; then
  DO_MALWARE="true"
  DO_SUID="true"
fi

# -------------------------
# Root check
# -------------------------
[[ $EUID -ne 0 ]] && die "This script must be run as root (sudo)"

# -------------------------
# Banner and dependency check
# -------------------------
if [[ "$INTERACTIVE" == "true" ]]; then
  echo ""
  banner
  hr
  echo "Mode: $(color "1;36" "$MODE")    Output base: $(color "1;36" "$OUT_BASE")    Webroot: $(color "1;36" "$WEBROOT")"
  hr
fi

check_dependencies

# -------------------------
# Prompt for modules (TTY)
# -------------------------
if [[ "$INTERACTIVE" == "true" ]]; then
  echo ""
  echo "$(color "1;37" "Choose scan modules (recommended defaults shown):")"
  echo ""

  ask_yn "System overview checks?" "Y" && DO_SYSTEM="true" || DO_SYSTEM="false"
  ask_yn "Users + SSH hardening checks?" "Y" && DO_USERS="true" || DO_USERS="false"
  ask_yn "Network exposure checks (ports/firewall)?" "Y" && DO_NETWORK="true" || DO_NETWORK="false"
  ask_yn "Webroot exposure scan (.env/.git/backups)?" "Y" && DO_WEBROOT="true" || DO_WEBROOT="false"
  ask_yn "Log analysis (SSH + web probes)?" "Y" && DO_LOGS="true" || DO_LOGS="false"
  ask_yn "Persistence checks (cron/systemd)?" "Y" && DO_PERSISTENCE="true" || DO_PERSISTENCE="false"

  if ask_yn "Malware/rootkit tools (ClamAV/rkhunter/chkrootkit) if installed? (slower)" "$( [[ "$MODE" == "deep" ]] && echo Y || echo N )"; then
    DO_MALWARE="true"
  else
    DO_MALWARE="false"
  fi

  if ask_yn "SUID/SGID sweep (can take time)?" "$( [[ "$MODE" == "deep" ]] && echo Y || echo N )"; then
    DO_SUID="true"
  else
    DO_SUID="false"
  fi
fi

# -------------------------
# Calculate total steps for progress bar
# -------------------------
TOTAL_STEPS=0
[[ "$DO_SYSTEM" == "true" ]] && TOTAL_STEPS=$((TOTAL_STEPS + 5))
[[ "$DO_USERS" == "true" ]] && TOTAL_STEPS=$((TOTAL_STEPS + 4))
[[ "$DO_NETWORK" == "true" ]] && TOTAL_STEPS=$((TOTAL_STEPS + 3))
[[ "$DO_WEBROOT" == "true" ]] && TOTAL_STEPS=$((TOTAL_STEPS + 2))
[[ "$DO_LOGS" == "true" ]] && TOTAL_STEPS=$((TOTAL_STEPS + 6))
[[ "$DO_PERSISTENCE" == "true" ]] && TOTAL_STEPS=$((TOTAL_STEPS + 5))
[[ "$DO_SUID" == "true" ]] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
[[ "$DO_MALWARE" == "true" ]] && TOTAL_STEPS=$((TOTAL_STEPS + 3))
TOTAL_STEPS=$((TOTAL_STEPS + 1)) # Summary step

# -------------------------
# Set up output paths
# -------------------------
RUN_ID="$(hostname -s)_$(date -u +"%Y%m%d_%H%M%S")"
OUT_DIR="${OUT_BASE}/${RUN_ID}"
RAW_DIR="${OUT_DIR}/raw"
REPORT_MD="${OUT_DIR}/REPORT.md"
SUMMARY_TXT="${OUT_DIR}/SUMMARY.txt"
SUMMARY_JSON="${OUT_DIR}/summary.json"

safe_mkdir "$OUT_DIR"
safe_mkdir "$RAW_DIR"

# -------------------------
# Initialize REPORT.md
# -------------------------
cat >"$REPORT_MD" <<EOF
# Namely SecScan Security Report

**Generated:** $(ts)  
**Version:** v${VERSION}  
**Host:** $(hostname -f 2>/dev/null || hostname)  
**Mode:** ${MODE}  
**Webroot:** ${WEBROOT}  

---

## Executive Summary

This report provides a comprehensive security audit of your VPS server. Each section below examines different aspects of system security, from basic configuration to potential compromise indicators.

**How to use this report:**
1. Start with sections marked with ⚠️ CRITICAL or WARNING findings
2. Review each section's "What to look for" guidance
3. Cross-reference suspicious findings with raw output files in the \`raw/\` directory
4. Consult SUMMARY.txt for quick overview and action items

**Report Sections:**
- System Overview: Basic system health and configuration
- User Security: Account security and SSH hardening
- Network Security: Port exposure and firewall configuration
- Webroot Exposure: Sensitive file detection in web-accessible areas
- Log Analysis: Authentication attempts and web probes
- Persistence Mechanisms: Cron jobs and systemd services
- Advanced Scans: SUID binaries and malware detection (if enabled)

---
EOF

# -------------------------
# Start scanning
# -------------------------
echo ""
head1 "Starting security scan"
echo ""

# -------------------------
# System checks
# -------------------------
if [[ "$DO_SYSTEM" == "true" ]]; then
  head1 "System overview"
  
  progress "System info"
  run "System Information" "system.txt" \
    "Basic system information including kernel version and hardware architecture." \
    "- Verify the kernel version is current and receiving security updates
- Check for any unusual architecture or configuration" \
    uname -a

  progress "Uptime and load"
  run "System Uptime and Load Average" "uptime.txt" \
    "Shows how long the system has been running and current load average." \
    "- Unusual recent restarts may indicate compromise or system issues
- High load average could indicate resource exhaustion or cryptomining" \
    uptime

  progress "Disk usage"
  run "Disk Usage" "df.txt" \
    "Filesystem usage across all mounted volumes." \
    "- Look for filesystems approaching 90%+ capacity
- Unexplained disk usage growth may indicate log flooding or malware
- Check for unusual mounted filesystems" \
    df -hT

  progress "Memory usage"
  run "Memory Usage" "memory.txt" \
    "Current RAM and swap utilization." \
    "- High swap usage may indicate memory pressure or performance issues
- Sudden memory consumption changes could indicate resource-intensive malware" \
    free -h

  progress "Top CPU processes"
  run "Top CPU Processes" "ps_cpu.txt" \
    "Processes consuming the most CPU resources." \
    "- Look for unfamiliar process names or unusual resource consumption
- Multiple instances of web servers or unusual binaries may be suspicious
- Check for known cryptominer process names (xmrig, minergate, etc.)" \
    bash -lc "ps aux --sort=-%cpu | head -25"
fi

# -------------------------
# User + SSH checks
# -------------------------
if [[ "$DO_USERS" == "true" ]]; then
  head1 "User security + SSH hardening"
  
  progress "UID 0 accounts"
  run "Accounts with UID 0 (Root Privileges)" "uid0.txt" \
    "Lists all accounts with root privileges (UID 0)." \
    "- There should typically be ONLY the 'root' account with UID 0
- Multiple UID 0 accounts are a serious security concern
- Any non-root UID 0 account indicates potential compromise" \
    awk -F: '($3==0){print $0}' /etc/passwd

  progress "Password policies"
  run "Password Policy Settings" "login.defs.txt" \
    "System password aging and complexity requirements." \
    "- PASS_MAX_DAYS should be ≤90 for password expiration
- PASS_MIN_DAYS should be ≥1 to prevent rapid password changes
- PASS_MIN_LEN should be ≥12 for adequate complexity" \
    grep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)" /etc/login.defs

  progress "Currently logged in users"
  run "Currently Logged-In Users" "who.txt" \
    "Active user sessions on the system." \
    "- Verify you recognize all logged-in users
- Check for suspicious login times (middle of night, etc.)
- Multiple concurrent root sessions may be unusual" \
    w

  progress "Recent login history"
  run "Recent Login History" "last.txt" \
    "Historical record of user logins and system boots." \
    "- Look for logins from unfamiliar IP addresses
- Check for login attempts during unusual hours
- Multiple failed login attempts followed by success may indicate brute-force
- System reboots should align with known maintenance windows" \
    bash -lc "last -a | head -50"
fi

# -------------------------
# Network checks
# -------------------------
if [[ "$DO_NETWORK" == "true" ]]; then
  head1 "Network exposure (ports + firewall)"
  
  progress "Listening ports"
  run "Listening Network Ports" "ports.txt" \
    "All services listening for network connections." \
    "- Verify you recognize all listening services
- Common secure ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
- Unexpected ports may indicate backdoors or unauthorized services
- Pay attention to services listening on 0.0.0.0 (all interfaces) vs 127.0.0.1 (localhost only)
- Database ports (3306, 5432, etc.) should NOT be exposed to 0.0.0.0 in production" \
    ss -tulpn

  progress "IPTables firewall"
  run "Firewall: iptables Rules" "iptables.txt" \
    "Current iptables firewall configuration." \
    "- Policy should be DROP or REJECT for INPUT chain (default deny)
- Verify only necessary ports are ACCEPT
- Look for unusual ACCEPT rules or suspicious IP addresses
- Empty ruleset means no firewall protection" \
    bash -lc 'iptables -L -n -v 2>/dev/null || echo "iptables not available or not configured"'

  progress "NFTables firewall"
  run "Firewall: nftables Rules" "nft.txt" \
    "Current nftables firewall configuration (modern replacement for iptables)." \
    "- Similar to iptables, default policy should be drop
- Verify ruleset matches your security requirements
- Empty output means nftables is not in use" \
    bash -lc 'nft list ruleset 2>/dev/null || echo "nftables not available or not configured"'
fi

# -------------------------
# Webroot exposure
# -------------------------
if [[ "$DO_WEBROOT" == "true" ]]; then
  head1 "Webroot exposure scan"
  
  progress "Searching for sensitive files"
  run "Webroot: Sensitive Files Detection" "webroot-find.txt" \
    "Searches webroot for exposed configuration files, repositories, and backups." \
    "- ⚠️ .env files contain secrets (API keys, passwords) - CRITICAL if found
- .git directories expose source code - CRITICAL security risk
- .svn, .hg - other version control systems that shouldn't be web-accessible
- wp-config.php, phpinfo.php - WordPress and PHP info files with sensitive data
- .bak, .old, .backup, .zip, .tar.gz - backup files may contain old credentials or code
- ANY findings here require immediate remediation" \
    bash -lc '
root="'"$WEBROOT"'"
[[ -d "$root" ]] || { echo "Webroot not found: $root"; exit 0; }
find "$root" -maxdepth 6 \( \
  -name ".env" -o -name ".env.*" -o -name ".git" -o -name ".svn" -o -name ".hg" \
  -o -name "wp-config.php" -o -name "phpinfo.php" \
  -o -iname "*.bak" -o -iname "*.old" -o -iname "*.backup" -o -iname "*.zip" -o -iname "*.tar.gz" \
\) 2>/dev/null | sed "s|^|FOUND: |" || echo "No sensitive files found (good!)"
'

  progress "Checking .htaccess protection"
  run "Webroot: .htaccess Protection Review" "htaccess-sample.txt" \
    "Reviews .htaccess files for security directives protecting sensitive files." \
    "- Look for 'Deny from all' or 'Require all denied' for .env, .git, etc.
- FilesMatch directives should block access to sensitive file patterns
- If sensitive files were found above, .htaccess should be protecting them
- Missing protection rules are a security concern if sensitive files exist" \
    bash -lc '
root="'"$WEBROOT"'"
[[ -d "$root" ]] || { echo "Webroot not found: $root"; exit 0; }
find "$root" -maxdepth 6 -name ".htaccess" 2>/dev/null | head -n 50 | while read -r f; do
  echo "== $f =="
  egrep -in "deny from all|require all denied|filesmatch|\\\.env|\\\.git" "$f" || echo "No protective rules found in this file"
  echo
done
'
fi

# -------------------------
# Log analysis
# -------------------------
AUTH_LOG=""
if [[ -f /var/log/auth.log ]]; then AUTH_LOG="/var/log/auth.log"; fi
if [[ -z "$AUTH_LOG" && -f /var/log/secure ]]; then AUTH_LOG="/var/log/secure"; fi

APACHE_ACCESS="/var/log/apache2/access.log"
NGINX_ACCESS="/var/log/nginx/access.log"

if [[ "$DO_LOGS" == "true" ]]; then
  head1 "Log analysis (SSH + web probes)"
  
  if [[ -n "$AUTH_LOG" ]]; then
    progress "SSH failed attempts"
    run "SSH Failed Login Attempts (Top Source IPs)" "ssh-fails.txt" \
      "Analyzes authentication logs for failed SSH login attempts." \
      "- High counts from single IPs indicate brute-force attacks
- Distributed attacks may show many IPs with few attempts each
- Consider implementing fail2ban if seeing high attack volume
- Legitimate failed attempts happen, but look for patterns
- Top attacking IPs should be blocked or rate-limited" \
      bash -lc '
log="'"$AUTH_LOG"'"
echo "Analyzing: $log"
files=("$log" "$log".1)
for f in "${files[@]}"; do [[ -f "$f" ]] || continue; cat "$f"; done \
| egrep -h "Failed password|Invalid user|authentication failure" \
| awk "{for(i=1;i<=NF;i++){if(\$i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){print \$i}}}" \
| sort | uniq -c | sort -nr | head -n 20 || echo "No failed SSH attempts found (excellent!)"
'

    progress "SSH successful logins"
    run "SSH Successful Logins (Recent)" "ssh-success.txt" \
      "Recent successful SSH authentication events." \
      "- Verify you recognize all source IPs that successfully logged in
- Check timestamps - logins during unusual hours may be suspicious
- Look for logins to accounts that shouldn't have SSH access
- Pay special attention to root logins (should be disabled ideally)
- Successful login after many failures may indicate compromised credentials" \
      bash -lc '
log="'"$AUTH_LOG"'"
echo "Analyzing: $log"
files=("$log" "$log".1)
for f in "${files[@]}"; do [[ -f "$f" ]] || continue; cat "$f"; done \
| egrep -h "Accepted (password|publickey)" | tail -n 100 || echo "No successful SSH logins found in recent logs"
'
  else
    progress "SSH logs (journalctl)"
    run "SSH Failed Attempts (journalctl fallback)" "ssh-fails.txt" \
      "SSH failed authentication attempts from systemd journal." \
      "Same as above - look for brute-force patterns and unfamiliar IPs" \
      bash -lc '
journalctl -u ssh -u sshd --no-pager -n 5000 2>/dev/null \
| egrep "Failed password|Invalid user|authentication failure" \
| awk "{for(i=1;i<=NF;i++){if(\$i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){print \$i}}}" \
| sort | uniq -c | sort -nr | head -n 20 || echo "No SSH logs available"
'

    progress "SSH successful logins (journalctl)"
    run "SSH Successful Logins (journalctl fallback)" "ssh-success.txt" \
      "SSH successful authentication from systemd journal." \
      "Verify you recognize all successful login sources and times" \
      bash -lc '
journalctl -u ssh -u sshd --no-pager -n 5000 2>/dev/null \
| egrep "Accepted (password|publickey)" | tail -n 100 || echo "No SSH logs available"
'
  fi

  if [[ -f "$APACHE_ACCESS" ]]; then
    progress "Web probes (Apache)"
    run "Web Access: Suspicious Probes (Apache)" "web-probes-apache.txt" \
      "HTTP requests targeting common vulnerability patterns." \
      "- Requests for .env, .git, wp-config.php indicate reconnaissance
- /admin, /login attempts may be brute-force or credential stuffing
- High volume from single IPs should be investigated
- Many probes are automated scanners, but they reveal attack vectors
- If these succeed (HTTP 200), you have a serious exposure problem" \
      bash -lc '
log="'"$APACHE_ACCESS"'"
egrep -h "(/\.env|/\.git|wp-config\.php|phpinfo\.php|/cgi-bin/|/vendor/|/admin|/login|/\.well-known)" "$log" \
| tail -n 200 || echo "No suspicious web probes detected in Apache logs"
'

    progress "Web probe IPs (Apache)"
    run "Web Access: Top IPs Targeting .env/.git (Apache)" "web-probes-apache-topips.txt" \
      "Source IPs attempting to access sensitive files." \
      "- These IPs are actively probing for exposed secrets
- Consider blocking repeat offenders
- CloudFlare or similar WAF can help mitigate" \
      bash -lc '
log="'"$APACHE_ACCESS"'"
egrep -h "(/\.env|/\.git)" "$log" \
| awk "{print \$1}" | sort | uniq -c | sort -nr | head -n 20 || echo "No .env/.git probes detected (good!)"
'
  fi

  if [[ -f "$NGINX_ACCESS" ]]; then
    progress "Web probes (Nginx)"
    run "Web Access: Suspicious Probes (Nginx)" "web-probes-nginx.txt" \
      "HTTP requests targeting common vulnerability patterns (Nginx)." \
      "Same guidance as Apache probes above" \
      bash -lc '
log="'"$NGINX_ACCESS"'"
egrep -h "(/\.env|/\.git|wp-config\.php|phpinfo\.php|/cgi-bin/|/vendor/|/admin|/login|/\.well-known)" "$log" \
| tail -n 200 || echo "No suspicious web probes detected in Nginx logs"
'

    progress "Web probe IPs (Nginx)"
    run "Web Access: Top IPs Targeting .env/.git (Nginx)" "web-probes-nginx-topips.txt" \
      "Source IPs attempting to access sensitive files (Nginx)." \
      "Same guidance as Apache probe IPs above" \
      bash -lc '
log="'"$NGINX_ACCESS"'"
egrep -h "(/\.env|/\.git)" "$log" \
| awk "{print \$1}" | sort | uniq -c | sort -nr | head -n 20 || echo "No .env/.git probes detected (good!)"
'
  fi
fi

# -------------------------
# Persistence checks
# -------------------------
if [[ "$DO_PERSISTENCE" == "true" ]]; then
  head1 "Persistence checks (cron + systemd)"
  
  progress "Cron directories"
  run "Cron: System Cron Directories" "cron-dirs.txt" \
    "Lists files in system cron directories where scheduled tasks are defined." \
    "- /etc/cron.* directories contain system-wide scheduled tasks
- Look for unfamiliar scripts or suspicious commands
- Attackers often use cron for persistence (reboot/hourly tasks to maintain access)
- Pay attention to any scripts calling curl/wget, especially to download and execute
- Verify all cron entries are legitimate and documented" \
    bash -lc 'ls -la /etc/cron.* /var/spool/cron 2>/dev/null || echo "No system cron directories found"'

  progress "Root crontab"
  run "Cron: Root Crontab" "cron-root.txt" \
    "Scheduled tasks running as root user." \
    "- Root cron jobs have full system privileges
- Look for any entries you didn't create
- Suspicious: downloads (curl/wget), reverse shells, or encoded commands
- Empty is common and fine if you don't use root cron" \
    bash -lc 'crontab -l 2>/dev/null || echo "No root crontab configured"'

  progress "User crontabs"
  run "Cron: User Crontabs" "cron-users.txt" \
    "Scheduled tasks for individual user accounts." \
    "- Check each user's crontab for legitimacy
- Web server users (www-data, nginx, apache) shouldn't typically have crontabs
- Look for the same suspicious patterns as root crontab above" \
    bash -lc '
for u in $(getent passwd | awk -F: '"'"'$3>=1000{print $1}'"'"'); do
  echo "== User: $u =="
  crontab -u "$u" -l 2>/dev/null || echo "No crontab for $u"
  echo
done
'

  progress "Systemd enabled units"
  run "Systemd: Enabled Services" "systemd-enabled.txt" \
    "Systemd services configured to start automatically." \
    "- These services start on boot and may persist after reboots
- Verify you recognize all enabled services
- Look for services with unusual names or locations
- Attackers may create services for backdoors or cryptominers
- Research any unfamiliar service names before assuming they're malicious" \
    bash -lc 'systemctl list-unit-files --state=enabled 2>/dev/null | head -n 300 || echo "Unable to list systemd units"'

  progress "Systemd timers"
  run "Systemd: Timers" "systemd-timers.txt" \
    "Systemd timer units (similar to cron, but managed by systemd)." \
    "- Timers are modern alternative to cron jobs
- Check what each timer activates (linked .service file)
- Look for suspicious timer names or schedules
- Verify timer targets are legitimate services" \
    bash -lc 'systemctl list-timers --all 2>/dev/null || echo "No systemd timers configured"'
fi

# -------------------------
# SUID sweep
# -------------------------
if [[ "$DO_SUID" == "true" ]]; then
  head1 "SUID/SGID sweep (deep)"
  
  progress "Finding SUID/SGID binaries"
  run "SUID/SGID Binaries (Privilege Escalation Risks)" "suid-sgid.txt" \
    "Executables with SUID/SGID bits that run with elevated privileges." \
    "- SUID binaries run with owner's permissions (often root)
- Common legitimate SUID: sudo, su, ping, mount, passwd
- Unexpected SUID binaries can be privilege escalation vectors
- Look for SUID on shell interpreters (bash, python, perl) - these are HIGH RISK
- Check SUID binaries in /tmp, /var/tmp, or user home directories - likely malicious
- Research any unfamiliar SUID binaries before assuming compromise" \
    bash -lc 'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%p\n" 2>/dev/null | sort | head -n 200'
fi

# -------------------------
# Malware/rootkit tools
# -------------------------
if [[ "$DO_MALWARE" == "true" ]]; then
  head1 "Malware/rootkit tools (deep, if installed)"
  
  if have clamscan; then
    progress "ClamAV scan"
    run "ClamAV: Virus/Malware Scan" "clamav-scan.txt" \
      "Antivirus scan of webroot and temp directories." \
      "- 'FOUND' indicates detected malware - requires immediate investigation
- ClamAV catches known malware signatures
- Clean scan doesn't guarantee no compromise (zero-day, custom malware)
- Focus on webroot (/var/www) and /tmp as common malware locations" \
      bash -lc '
root="'"$WEBROOT"'"
targets=()
[[ -d "$root" ]] && targets+=("$root")
targets+=("/tmp")
clamscan -r --infected --log=/dev/stdout "${targets[@]}" 2>&1 | tail -n 5000
' || true
  else
    warn "clamscan not found; skipping ClamAV scan."
  fi

  if have rkhunter; then
    progress "rkhunter scan"
    run "rkhunter: Rootkit Hunter Scan" "rkhunter-check.txt" \
      "Scans for rootkits and other local exploits." \
      "- Warnings may be false positives but should be investigated
- Pay attention to: suspicious files, network issues, hidden processes
- Check 'Possible rootkits' section carefully
- Update rkhunter database regularly: rkhunter --update" \
      bash -lc 'rkhunter --check --sk --rwo --nocolors 2>&1 | tail -n 4000 || true'
  else
    warn "rkhunter not found; skipping."
  fi

  if have chkrootkit; then
    progress "chkrootkit scan"
    run "chkrootkit: Rootkit Detection" "chkrootkit.txt" \
      "Alternative rootkit detection tool." \
      "- INFECTED results require immediate investigation
- May have false positives, cross-reference with other tools
- Checks for: trojaned binaries, LKM (kernel module) rootkits, hidden processes" \
      bash -lc 'chkrootkit 2>&1 | tail -n 4000 || true'
  else
    warn "chkrootkit not found; skipping."
  fi
fi

# -------------------------
# Generate Summary
# -------------------------
progress "Generating summary"

head1 "Generating Summary Report"

# Calculate metrics
ENV_HITS=0
if [[ -f "$APACHE_ACCESS" ]]; then
  ENV_HITS=$(egrep -c "(/\.env)" "$APACHE_ACCESS" 2>/dev/null || true)
elif [[ -f "$NGINX_ACCESS" ]]; then
  ENV_HITS=$(egrep -c "(/\.env)" "$NGINX_ACCESS" 2>/dev/null || true)
fi

SSH_FAILS=0
if [[ -n "$AUTH_LOG" && -f "$AUTH_LOG" ]]; then
  SSH_FAILS=$(egrep -h "Failed password|Invalid user|authentication failure" "$AUTH_LOG" "$AUTH_LOG.1" 2>/dev/null | wc -l | tr -d " " || true)
fi

# Count exposed files
EXPOSED_FILES=0
if [[ -f "${RAW_DIR}/webroot-find.txt" ]]; then
  EXPOSED_FILES=$(grep -c "FOUND:" "${RAW_DIR}/webroot-find.txt" 2>/dev/null || true)
fi

# Count SUID binaries
SUID_COUNT=0
if [[ -f "${RAW_DIR}/suid-sgid.txt" ]]; then
  SUID_COUNT=$(wc -l < "${RAW_DIR}/suid-sgid.txt" 2>/dev/null || true)
fi

# Write comprehensive summary
cat >"$SUMMARY_TXT" <<EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║                      NAMELY SECSCAN SUMMARY REPORT                           ║
║                           Security Audit Results                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

SCAN INFORMATION
─────────────────────────────────────────────────────────────────────────────
Version:                        v${VERSION}
Run ID:                         ${RUN_ID}
Timestamp:                      $(ts)
Scan Mode:                      ${MODE}
Host:                           $(hostname -f 2>/dev/null || hostname)
Webroot:                        ${WEBROOT}
Output Directory:               ${OUT_DIR}

FINDINGS OVERVIEW
─────────────────────────────────────────────────────────────────────────────
Critical Findings:              ${FINDINGS[critical]}
Warnings:                       ${FINDINGS[warning]}
Informational:                  ${FINDINGS[info]}

KEY METRICS
─────────────────────────────────────────────────────────────────────────────
Exposed Files in Webroot:       ${EXPOSED_FILES}
.env Access Attempts (logs):    ${ENV_HITS}
SSH Failed Login Attempts:      ${SSH_FAILS}
SUID/SGID Binaries Found:       ${SUID_COUNT}

DETAILED FINDINGS
─────────────────────────────────────────────────────────────────────────────
EOF

if [[ ${FINDINGS[critical]} -gt 0 ]] || [[ ${FINDINGS[warning]} -gt 0 ]] || [[ ${FINDINGS[info]} -gt 0 ]]; then
  echo "${FINDINGS[details]}" >>"$SUMMARY_TXT"
else
  echo "No automated findings detected." >>"$SUMMARY_TXT"
  echo "This doesn't mean the system is 100% secure - manual review is still needed." >>"$SUMMARY_TXT"
fi

cat >>"$SUMMARY_TXT" <<EOF

SECURITY ASSESSMENT
─────────────────────────────────────────────────────────────────────────────
EOF

# Overall risk assessment
RISK_LEVEL="LOW"
RISK_COLOR="32"  # green

if [[ ${FINDINGS[critical]} -gt 0 ]]; then
  RISK_LEVEL="CRITICAL"
  RISK_COLOR="31"  # red
elif [[ $EXPOSED_FILES -gt 0 ]] || [[ $ENV_HITS -gt 50 ]]; then
  RISK_LEVEL="HIGH"
  RISK_COLOR="31"  # red
elif [[ ${FINDINGS[warning]} -gt 3 ]] || [[ $SSH_FAILS -gt 500 ]]; then
  RISK_LEVEL="MEDIUM"
  RISK_COLOR="33"  # yellow
elif [[ ${FINDINGS[warning]} -gt 0 ]] || [[ $SSH_FAILS -gt 100 ]]; then
  RISK_LEVEL="LOW-MEDIUM"
  RISK_COLOR="33"  # yellow
fi

echo "Overall Risk Level:             $(color "$RISK_COLOR" "$RISK_LEVEL")" >>"$SUMMARY_TXT"

cat >>"$SUMMARY_TXT" <<EOF

IMMEDIATE ACTION ITEMS
─────────────────────────────────────────────────────────────────────────────
EOF

if [[ ${FINDINGS[critical]} -gt 0 ]]; then
  cat >>"$SUMMARY_TXT" <<EOF
⚠️  CRITICAL ISSUES DETECTED - IMMEDIATE ACTION REQUIRED!

1. Review all CRITICAL findings listed above
2. If .env files are exposed in webroot:
   - Move them outside web-accessible directories immediately
   - Add .htaccess deny rules or equivalent
   - Rotate ALL credentials (API keys, database passwords, secrets)
   - Check logs for successful access attempts
3. If source code (.git) is exposed:
   - Remove .git directories from webroot
   - Review code for embedded secrets
   - Rotate any credentials found in code
4. If malware was detected:
   - Isolate the server from network if possible
   - Preserve logs for forensic analysis
   - Contact security team or professional incident response
   - Do NOT remove malware until analysis is complete

EOF
elif [[ $EXPOSED_FILES -gt 0 ]]; then
  cat >>"$SUMMARY_TXT" <<EOF
⚠️  SENSITIVE FILES DETECTED IN WEBROOT

1. Review webroot-find.txt for complete list
2. Move sensitive files outside web-accessible areas
3. Add proper .htaccess or web server deny rules
4. Verify files were not successfully accessed via logs

EOF
fi

if [[ ${FINDINGS[warning]} -gt 2 ]] || [[ $SSH_FAILS -gt 200 ]]; then
  cat >>"$SUMMARY_TXT" <<EOF
⚠️  SECURITY WARNINGS REQUIRE ATTENTION

1. Review all WARNING findings listed above
2. High SSH brute-force activity detected:
   - Consider implementing fail2ban
   - Review SSH configuration hardening
   - Disable password authentication (use keys only)
   - Change default SSH port if appropriate
3. Review web access logs for successful exploitation attempts
4. Verify all listening ports and services are necessary

EOF
fi

cat >>"$SUMMARY_TXT" <<EOF

RECOMMENDED NEXT STEPS
─────────────────────────────────────────────────────────────────────────────
1. Review REPORT.md - Start with sections that have findings
2. Examine raw output files in raw/ directory for detailed data
3. Cross-reference findings with your known system configuration
4. Key files to review:
   - ssh-fails.txt + ssh-success.txt → Authentication security
   - webroot-find.txt → Exposed sensitive files
   - web-probes-*.txt → Reconnaissance activity
   - ports.txt → Network exposure
   - systemd-enabled.txt + cron-*.txt → Persistence mechanisms
   - suid-sgid.txt → Privilege escalation vectors (if scanned)
   - clamav-scan.txt + rkhunter-check.txt → Malware detection (if scanned)

5. If you suspect compromise:
   - Do NOT immediately remediate - preserve evidence first
   - Document all findings and timeline
   - Consider professional incident response assistance
   - Isolate affected systems
   - Review backups for clean restore points

6. General security hardening:
   - Keep system and packages updated
   - Enable automatic security updates
   - Implement fail2ban for SSH protection
   - Use SSH keys instead of passwords
   - Review and minimize listening services
   - Implement proper firewall rules
   - Regular security audits with this tool

REPORT FILES
─────────────────────────────────────────────────────────────────────────────
📄 Detailed Report:             ${REPORT_MD}
🧾 This Summary:                ${SUMMARY_TXT}
EOF

[[ "$MAKE_JSON" == "true" ]] && echo "🧩 JSON Data:                   ${SUMMARY_JSON}" >>"$SUMMARY_TXT"

cat >>"$SUMMARY_TXT" <<EOF
📁 Raw Outputs:                 ${RAW_DIR}

NEED HELP?
─────────────────────────────────────────────────────────────────────────────
For professional security assistance and incident response:
🌐 Contact: NamelyCorp.com
📧 Security team can help with:
   - Incident response and forensics
   - Security hardening consultation
   - Penetration testing
   - Compliance audits

EOF

# Add final summary to REPORT.md
cat >>"$REPORT_MD" <<EOF

---

## Scan Summary

**Scan completed:** $(ts)

**Key Metrics:**
- Critical findings: ${FINDINGS[critical]}
- Warnings: ${FINDINGS[warning]}
- Informational: ${FINDINGS[info]}
- Exposed files: ${EXPOSED_FILES}
- .env access attempts: ${ENV_HITS}
- SSH failed attempts: ${SSH_FAILS}

**Overall Risk Level:** ${RISK_LEVEL}

See SUMMARY.txt for detailed findings and recommended actions.

---

*Report generated by Namely SecScan v${VERSION} - NamelyCorp Security Tools*
EOF

# Generate JSON if requested
if [[ "$MAKE_JSON" == "true" ]]; then
  cat >"$SUMMARY_JSON" <<EOF
{
  "version": "v${VERSION}",
  "run_id": "${RUN_ID}",
  "timestamp_utc": "$(ts)",
  "mode": "${MODE}",
  "host": "$(hostname -f 2>/dev/null || hostname)",
  "webroot": "${WEBROOT}",
  "out_dir": "${OUT_DIR}",
  "modules": {
    "system": ${DO_SYSTEM},
    "users": ${DO_USERS},
    "network": ${DO_NETWORK},
    "webroot": ${DO_WEBROOT},
    "logs": ${DO_LOGS},
    "persistence": ${DO_PERSISTENCE},
    "malware": ${DO_MALWARE},
    "suid": ${DO_SUID}
  },
  "findings": {
    "critical": ${FINDINGS[critical]},
    "warning": ${FINDINGS[warning]},
    "info": ${FINDINGS[info]}
  },
  "metrics": {
    "exposed_files_webroot": ${EXPOSED_FILES},
    "env_hits_access_log": ${ENV_HITS},
    "ssh_failed_attempts_approx": ${SSH_FAILS},
    "suid_sgid_count": ${SUID_COUNT}
  },
  "risk_level": "${RISK_LEVEL}"
}
EOF
fi

# Determine exit code
EXIT_CODE=0
if [[ ${FINDINGS[critical]} -gt 0 ]]; then 
  EXIT_CODE=2
elif [[ $EXPOSED_FILES -gt 0 ]] || [[ $ENV_HITS -gt 50 ]]; then 
  EXIT_CODE=1
elif [[ ${FINDINGS[warning]} -gt 0 ]] || [[ $SSH_FAILS -gt 200 ]]; then 
  EXIT_CODE=1
fi

# -------------------------
# Final output
# -------------------------
echo ""
good "Scan complete!"
hr
echo ""
echo "$(color "1;36" "📊 SCAN RESULTS:")"
echo ""
echo "  Risk Level:        $(color "$RISK_COLOR" "$RISK_LEVEL")"
echo "  Critical Findings: $(color "1;31" "${FINDINGS[critical]}")"
echo "  Warnings:          $(color "1;33" "${FINDINGS[warning]}")"
echo "  Info:              $(color "1;34" "${FINDINGS[info]}")"
echo ""
hr
echo "$(color "1;36" "📄 Report Files:")"
echo "  • Detailed Report:  ${REPORT_MD}"
echo "  • Quick Summary:    ${SUMMARY_TXT}"
[[ "$MAKE_JSON" == "true" ]] && echo "  • JSON Data:        ${SUMMARY_JSON}"
echo "  • Raw Outputs:      ${RAW_DIR}/"
hr
echo ""
echo "$(color "1;37" "Next Steps:")"
echo "  1) Read SUMMARY.txt for quick overview and action items"
echo "  2) Review REPORT.md for detailed findings"
echo "  3) Investigate any CRITICAL or WARNING findings immediately"
echo "  4) Cross-reference with raw/ outputs for full details"
echo ""

if [[ ${FINDINGS[critical]} -gt 0 ]] || [[ $EXPOSED_FILES -gt 0 ]]; then
  echo "$(color "1;31" "⚠️  CRITICAL ISSUES DETECTED - IMMEDIATE ACTION REQUIRED!")"
  echo ""
fi

echo "$(color "1;37" "Need professional help?")"
echo "  Contact: $(color "1;32" "NamelyCorp.com")"
echo ""

exit "$EXIT_CODE"
