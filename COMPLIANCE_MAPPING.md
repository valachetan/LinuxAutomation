# Detailed Compliance Standards Report

This document provides a technical mapping between the `linux_audit.sh` script checks and the specific controls required by international security standards.

---

## 1. Identity and Access Management (IAM)

| Check Name | ISO 27001:2022 | NIST 800-53 Rev 5 | SOC 2 (TSC 2017) |
| :--- | :--- | :--- | :--- |
| **Empty Passwords** | A.8.2, A.8.5 | IA-2, IA-5 | CC6.1, CC6.2 |
| **Non-root UID 0** | A.8.2 (Privileged Access) | AC-2, AC-6 | CC6.3 |
| **Password Aging** | A.8.5 (Authentication) | IA-5 (1) | CC6.1 |
| **Orphaned Files** | A.8.1 (User Endpoints) | AC-2 (i) | CC6.1 |

**Technical Rationale:**
- **ISO A.8.2/A.8.5:** Requires management of privileged access rights and secure authentication.
- **NIST AC-6:** Principle of Least Privilege. Only authorized users should have administrative (UID 0) capabilities.
- **SOC 2 CC6.1:** Requires the entity to implement logical access security software, infrastructure, and architectures.

---

## 2. System Hardening & Configuration

| Check Name | ISO 27001:2022 | NIST 800-53 Rev 5 | SOC 2 (TSC 2017) |
| :--- | :--- | :--- | :--- |
| **SSH Hardening** | A.8.14 (Network Security) | CM-6, CM-7 | CC6.6, CC7.1 |
| **Core Dumps** | A.8.31 (Secure Coding) | SI-11 (Error Handling) | CC7.1 |
| **MAC Status** | A.8.22 (Segregation) | AC-3, CM-6 | CC7.1 |

**Technical Rationale:**
- **NIST CM-6:** Configuration Settings. Hardening the SSH daemon and disabling core dumps reduces the "attack surface" and prevents information leakage during crashes.
- **ISO A.8.22:** Segregation in networks and systems. MAC (SELinux/AppArmor) provides granular control over system processes.

---

## 3. Logging and Auditing

| Check Name | ISO 27001:2022 | NIST 800-53 Rev 5 | SOC 2 (TSC 2017) |
| :--- | :--- | :--- | :--- |
| **auditd Status** | A.8.15 (Logging) | AU-2, AU-12 | CC7.2 |
| **Syslog Status** | A.8.15, A.8.16 | AU-6, AU-9 | CC7.2 |
| **Log Rotation** | A.8.15 (Storage) | AU-4 (Capacity) | CC7.1, CC7.2 |

**Technical Rationale:**
- **ISO A.8.15:** Requires logging of events and reviewing their evidence.
- **NIST AU-12:** Audit Generation. The system must be capable of auditing events defined by the organization.
- **SOC 2 CC7.2:** The entity monitors the system and takes action on any deviations from security policies.

---

## 4. Network Security

| Check Name | ISO 27001:2022 | NIST 800-53 Rev 5 | SOC 2 (TSC 2017) |
| :--- | :--- | :--- | :--- |
| **Firewall Status** | A.8.14, A.8.21 | SC-7 (Boundary Prot.) | CC6.6 |
| **Listening Ports** | A.8.14 (Network) | CM-7 (Least Function) | CC6.6 |
| **IP Forwarding** | A.8.14, A.8.21 | SC-7, AC-4 | CC6.6 |

**Technical Rationale:**
- **NIST CM-7:** Least Functionality. Reviewing listening ports ensures only necessary services are running.
- **SOC 2 CC6.6:** Implements logical access security over software, infrastructure, and architectures (includes network boundary protection).

---

## 5. File System & Data Protection

| Check Name | ISO 27001:2022 | NIST 800-53 Rev 5 | SOC 2 (TSC 2017) |
| :--- | :--- | :--- | :--- |
| **Shadow/Passwd Perms**| A.8.1, A.8.2 | AC-3, CM-6 | CC6.1, CC6.7 |
| **World-Writable** | A.8.1 (Asset Protection) | AC-3, CM-6 | CC6.7 |

**Technical Rationale:**
- **ISO A.8.1:** Protection of assets. Sensitive files like `/etc/shadow` contain hashed passwords and must be restricted.
- **SOC 2 CC6.7:** The entity restricts the transmission, movement, and removal of information to authorized personnel.

---

## 6. Vulnerability Management

| Check Name | ISO 27001:2022 | NIST 800-53 Rev 5 | SOC 2 (TSC 2017) |
| :--- | :--- | :--- | :--- |
| **Pending Updates** | A.8.8 (Vulnerability) | SI-2 (Flaw Remediation)| CC7.1 |

**Technical Rationale:**
- **NIST SI-2:** Flaw Remediation. Requires organizations to identify, report, and correct system flaws (patching).
- **ISO A.8.8:** Management of technical vulnerabilities. Regular assessment and patching of systems.

---

## Summary of Coverage

| Standard | Coverage Type | Key Objective |
| :--- | :--- | :--- |
| **ISO 27001** | Risk-Based | Ensure Confidentiality, Integrity, and Availability (CIA) through A.8 control set. |
| **NIST 800-53** | Catalog-Based | Provide a robust framework for federal information systems (Rev 5). |
| **SOC 2** | Trust Services | Focus on Security, Availability, and Confidentiality for service providers. |
