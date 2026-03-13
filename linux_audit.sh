#!/bin/bash

# ==============================================================================
# Linux Security Audit Tool (ISO 27001, NIST 800-53, SOC 2)
# ==============================================================================
# Description: This script performs a comprehensive security audit of a Linux 
# system to evaluate compliance with major security standards.
#
# Usage: sudo ./linux_audit.sh
# ==============================================================================

# --- Configuration & Initialization ---
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="audit_report_${TIMESTAMP}.log"
JSON_REPORT="audit_report_${TIMESTAMP}.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root to access sensitive system files.${NC}"
   exit 1
fi

# Redirect all output to report file and console
exec > >(tee -i "$REPORT_FILE") 2>&1

echo "================================================================================"
echo "                   LINUX SECURITY AUDIT REPORT                                  "
echo "================================================================================"
echo "Date:       $(date)"
echo "Hostname:   $(hostname)"
echo "OS Distro:  $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo "Kernel:     $(uname -r)"
echo "================================================================================"

# --- Helper Functions ---
log_section() {
    echo -e "\n${YELLOW}[ SECTION: $1 ]${NC}"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# --- 1. Identity and Access Management (ISO A.9, NIST AC-2, SOC 2 CC6.1) ---
audit_iam() {
    log_section "Identity and Access Management"

    # Check for empty passwords
    EMPTY_PW=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
    if [ -z "$EMPTY_PW" ]; then
        log_pass "No accounts found with empty passwords."
    else
        log_fail "Accounts with empty passwords detected: $EMPTY_PW"
    fi

    # Check for UID 0 accounts other than root
    EXTRA_ADMINS=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
    if [ -z "$EXTRA_ADMINS" ]; then
        log_pass "Only 'root' has UID 0."
    else
        log_fail "Non-root accounts with UID 0 detected: $EXTRA_ADMINS"
    fi

    # Password Policy (login.defs)
    echo "Password Aging Policies (/etc/login.defs):"
    grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE" /etc/login.defs | sed 's/^/  /'

    # Check for orphaned files (files without owners)
    ORPHANED=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 5)
    if [ -z "$ORPHANED" ]; then
        log_pass "No orphaned files found (files without owner/group)."
    else
        log_warn "Orphaned files detected (showing first 5):"
        echo "$ORPHANED"
    fi
}

# --- 2. System Hardening (ISO A.12, NIST CM-6, SOC 2 CC7.1) ---
audit_hardening() {
    log_section "System Hardening & Configuration"

    # SSH Hardening
    SSH_CONFIG="/etc/ssh/sshd_config"
    if [ -f "$SSH_CONFIG" ]; then
        echo "SSH Security Settings:"
        grep -E "^PermitRootLogin|^PasswordAuthentication|^Protocol|^MaxAuthTries|^X11Forwarding" "$SSH_CONFIG" | sed 's/^/  /'
        
        # Specific SSH Checks
        grep -q "^PermitRootLogin no" "$SSH_CONFIG" && log_pass "Root SSH login disabled." || log_fail "Root SSH login enabled or not explicitly disabled."
        grep -q "^PasswordAuthentication no" "$SSH_CONFIG" && log_pass "SSH password authentication disabled." || log_warn "SSH password authentication enabled."
    else
        log_fail "SSH configuration file not found at $SSH_CONFIG"
    fi

    # Core Dumps
    if grep -q "* hard core 0" /etc/security/limits.conf; then
        log_pass "Core dumps are restricted in limits.conf."
    else
        log_warn "Core dumps are not restricted in /etc/security/limits.conf."
    fi

    # SELinux/AppArmor Status
    if command -v getenforce >/dev/null; then
        log_pass "SELinux Status: $(getenforce)"
    elif [ -d /etc/apparmor.d ]; then
        log_pass "AppArmor is present (Check 'aa-status' for details)."
    else
        log_fail "No MAC (SELinux/AppArmor) detected."
    fi
}

# --- 3. Logging and Auditing (ISO A.12.4, NIST AU-2, SOC 2 CC7.2) ---
audit_logging() {
    log_section "Logging and Auditing"

    # auditd
    if systemctl is-active --quiet auditd; then
        log_pass "auditd service is running."
    else
        log_fail "auditd service is NOT running."
    fi

    # syslog
    if systemctl is-active --quiet rsyslog || systemctl is-active --quiet syslog-ng; then
        log_pass "System logging service (rsyslog/syslog-ng) is running."
    else
        log_fail "No active system logging service found."
    fi

    # Log Rotation
    if [ -f /etc/logrotate.conf ]; then
        log_pass "logrotate is configured."
    else
        log_fail "logrotate configuration missing."
    fi
}

# --- 4. Network Security (ISO A.13, NIST SC-7, SOC 2 CC6.6) ---
audit_network() {
    log_section "Network Security"

    # Firewall
    if command -v ufw >/dev/null && ufw status | grep -q "active"; then
        log_pass "UFW Firewall is active."
    elif command -v firewalld >/dev/null && systemctl is-active --quiet firewalld; then
        log_pass "Firewalld is active."
    elif iptables -L -n | grep -q "Chain INPUT (policy DROP)"; then
        log_pass "iptables is active with DROP policy."
    else
        log_fail "No active firewall detected or default policy is permissive."
    fi

    # Listening Ports
    echo "Active Listening Ports (Review for unauthorized services):"
    ss -tuln | grep LISTEN | sed 's/^/  /'

    # IP Forwarding
    IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward)
    if [ "$IP_FWD" -eq 0 ]; then
        log_pass "IPv4 forwarding is disabled."
    else
        log_warn "IPv4 forwarding is ENABLED (Check if this is a router/gateway)."
    fi
}

# --- 5. File System & Data Protection (ISO A.18, NIST CP-9, SOC 2 CC6.7) ---
audit_filesystem() {
    log_section "File System & Data Protection"

    # Sensitive File Permissions
    check_perm() {
        PERM=$(stat -c "%a" "$1" 2>/dev/null)
        if [ "$PERM" == "$2" ]; then
            log_pass "Permissions for $1 are correct ($2)."
        else
            log_fail "Permissions for $1 are $PERM (Expected $2)."
        fi
    }

    check_perm "/etc/shadow" "600"
    check_perm "/etc/passwd" "644"
    check_perm "/etc/gshadow" "600"
    check_perm "/etc/group" "644"

    # World-Writable Files
    WW_FILES=$(find / -xdev -type f -perm -0002 2>/dev/null | head -n 5)
    if [ -z "$WW_FILES" ]; then
        log_pass "No world-writable files found in root filesystem."
    else
        log_warn "World-writable files detected (showing first 5):"
        echo "$WW_FILES" | sed 's/^/  /'
    fi
}

# --- 6. Vulnerability Management (ISO A.12.6, NIST SI-2, SOC 2 CC7.1) ---
audit_vulnerabilities() {
    log_section "Vulnerability Management"

    # Pending Updates
    if command -v apt >/dev/null; then
        UPDATES=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
        if [ "$UPDATES" -eq 0 ]; then
            log_pass "No pending security updates (APT)."
        else
            log_warn "$UPDATES pending updates detected. Run 'apt list --upgradable' to review."
        fi
    elif command -v yum >/dev/null; then
        UPDATES=$(yum check-update --quiet | wc -l)
        if [ "$UPDATES" -eq 0 ]; then
            log_pass "No pending security updates (YUM)."
        else
            log_warn "Pending updates detected (YUM)."
        fi
    fi
}

# --- 7. Git Integration (Optional) ---
push_report_to_git() {
    if [ -d ".git" ]; then
        echo -e "\n${YELLOW}[ Git Integration ]${NC}"
        read -p "Do you want to commit and push the audit report to the current repository? (y/n): " PUSH_CONFIRM
        if [[ "$PUSH_CONFIRM" =~ ^[Yy]$ ]]; then
            git add "$REPORT_FILE"
            git commit -m "chore: Add security audit report for $TIMESTAMP"
            git push origin $(git rev-parse --abbrev-ref HEAD)
            log_pass "Report pushed to Git successfully."
        else
            echo "Skipping Git push."
        fi
    fi
}

# --- Execution ---
audit_iam
audit_hardening
audit_logging
audit_network
audit_filesystem
audit_vulnerabilities
push_report_to_git

echo -e "\n================================================================================"
echo "Audit Complete."
echo "Full Report: $REPORT_FILE"
echo "================================================================================"
