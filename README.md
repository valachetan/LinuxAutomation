# Linux Security Audit Tool

A comprehensive Bash script designed to audit Linux systems against security standards including **ISO 27001**, **NIST 800-53**, and **SOC 2**.

## Features

This script performs read-only checks across several critical security domains:

- **Identity & Access Management (IAM):** Checks for empty passwords, non-root UID 0 accounts, and password aging policies.
- **System Hardening:** Evaluates SSH configurations, core dump restrictions, and MAC (SELinux/AppArmor) status.
- **Logging & Auditing:** Verifies the status of `auditd`, `rsyslog`, and log rotation.
- **Network Security:** Inspects firewall status, listening ports, and IP forwarding settings.
- **File System Protection:** Audits permissions on sensitive files (like `/etc/shadow`) and identifies world-writable files.
- **Vulnerability Management:** Checks for pending system updates (supports APT and YUM).

## Usage

1. **Download/Create the script:**
   Save the `linux_audit.sh` file to your Linux server.

2. **Make it executable:**
   ```bash
   chmod +x linux_audit.sh
   ```

3. **Run with root privileges:**
   ```bash
   sudo ./linux_audit.sh
   ```

## Output

The script provides real-time color-coded feedback in the terminal and generates a detailed log file named `audit_report_YYYYMMDD_HHMMSS.log` for future reference and compliance documentation.

## Standards Mapping

| Standard | Domain | Script Check |
| :--- | :--- | :--- |
| **ISO 27001** | A.9 Access Control | IAM, SSH Hardening |
| **ISO 27001** | A.12.4 Logging | Logging & Auditing |
| **NIST 800-53** | AC-2 Account Management | IAM (UID 0, Passwords) |
| **NIST 800-53** | CM-6 Configuration Settings | System Hardening, File Perms |
| **SOC 2** | CC6.1 Access | IAM, Password Policies |
| **SOC 2** | CC7.1 Vulnerability Mgmt | Pending Updates |

---
**Note:** This tool is for auditing purposes only and does not automatically apply fixes. Always review findings before making changes to a production system.
