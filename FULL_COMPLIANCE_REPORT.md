# Master Security Compliance Audit Report
## Mapping: ISO 27001:2022 | NIST 800-53 Rev 5 | SOC 2 (2017)

This report provides the exhaustive legal and technical clauses required for formal auditing and certification processes.

---

## I. Identity and Access Management (IAM)

### 1.1 Account Integrity & Privilege Management
*   **Audit Check:** Empty Passwords & Non-root UID 0 Accounts.
*   **ISO 27001:2022 Clause:** 
    *   **A.8.2 (Privileged access rights):** "The allocation and use of privileged access rights shall be restricted and managed."
    *   **A.8.5 (Secure authentication):** "Secure authentication information shall be managed in accordance with the organization’s topic-specific policy."
*   **NIST 800-53 Rev 5 Clause:**
    *   **AC-2 (Account Management):** "Manage system accounts, including establishing, activating, modifying, disabling, and removing accounts."
    *   **IA-2 (Identification and Authentication):** "Uniquely identify and authenticate users (or processes acting on behalf of users)."
*   **SOC 2 Trust Services Criteria:**
    *   **CC6.1:** "The entity restricts logical access to confidential information, software, and infrastructure."
    *   **CC6.3:** "The entity modifies, or removes access when an individual's relationship with the entity changes."

---

## II. System Hardening & Configuration Management

### 2.1 Baseline Hardening (SSH & Core Dumps)
*   **Audit Check:** SSH Configuration & Core Dump Restrictions.
*   **ISO 27001:2022 Clause:**
    *   **A.8.9 (Configuration management):** "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed."
*   **NIST 800-53 Rev 5 Clause:**
    *   **CM-6 (Configuration Settings):** "Establish and document configuration settings for information technology products employed within the system."
    *   **CM-7 (Least Functionality):** "Configure the system to provide only essential capabilities."
*   **SOC 2 Trust Services Criteria:**
    *   **CC7.1:** "The entity performs configuration management for infrastructure and software."

### 2.2 Mandatory Access Control (MAC)
*   **Audit Check:** SELinux / AppArmor Status.
*   **ISO 27001:2022 Clause:**
    *   **A.8.3 (Information access restriction):** "Access to information and other associated assets shall be restricted in accordance with the topic-specific policy on access control."
*   **NIST 800-53 Rev 5 Clause:**
    *   **AC-3 (Access Enforcement):** "The system enforces approved authorizations for logical access to information and system resources."

---

## III. Logging and Monitoring (Continuous Audit)

### 3.1 Event Logging & Retention
*   **Audit Check:** auditd status, syslog configuration, and log rotation.
*   **ISO 27001:2022 Clause:**
    *   **A.8.15 (Logging):** "Logs that record activities, exceptions, faults and other relevant events shall be produced, kept and periodically reviewed."
    *   **A.8.16 (Monitoring activities):** "Networks, systems and applications shall be monitored for anomalous behavior and appropriate actions taken."
*   **NIST 800-53 Rev 5 Clause:**
    *   **AU-2 (Event Logging):** "Determine that the system is capable of logging the following events..."
    *   **AU-6 (Audit Record Review, Analysis, and Reporting):** "Review and analyze system audit records for indications of unusual activity."
*   **SOC 2 Trust Services Criteria:**
    *   **CC7.2:** "The entity evaluates and responds to security incidents."

---

## IV. Network Security & Boundary Protection

### 4.1 Traffic Filtering & Service Minimization
*   **Audit Check:** Firewall status and Listening Port analysis.
*   **ISO 27001:2022 Clause:**
    *   **A.8.14 (Information security in network services):** "Security mechanisms, service levels and management requirements of all network services shall be identified, implemented and monitored."
*   **NIST 800-53 Rev 5 Clause:**
    *   **SC-7 (Boundary Protection):** "The system monitors and controls communications at the external boundary and at key internal boundaries."
*   **SOC 2 Trust Services Criteria:**
    *   **CC6.6:** "The entity implements logical access security software, infrastructure, and architectures over protected information assets."

---

## V. Data Protection & File Integrity

### 5.1 Sensitive File Security
*   **Audit Check:** Permissions on /etc/shadow, /etc/passwd, and World-Writable files.
*   **ISO 27001:2022 Clause:**
    *   **A.8.1 (User endpoint devices):** "Information stored on, processed by or passing through user endpoint devices shall be protected."
    *   **A.8.12 (Data leakage prevention):** "Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information."
*   **NIST 800-53 Rev 5 Clause:**
    *   **SC-28 (Protection of Information at Rest):** "Protect the confidentiality and integrity of information at rest."
*   **SOC 2 Trust Services Criteria:**
    *   **CC6.7:** "The entity restricts the transmission, movement, and removal of information to authorized personnel."

---

## VI. Vulnerability and Patch Management

### 6.1 Remediation & Updating
*   **Audit Check:** System update status (APT/YUM).
*   **ISO 27001:2022 Clause:**
    *   **A.8.8 (Management of technical vulnerabilities):** "Information about technical vulnerabilities of information systems being used shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated and appropriate measures shall be taken."
*   **NIST 800-53 Rev 5 Clause:**
    *   **SI-2 (Flaw Remediation):** "Identify, report, and correct system flaws; and test software and firmware updates before installation."
*   **SOC 2 Trust Services Criteria:**
    *   **CC7.1:** "The entity identifies and manages vulnerabilities in infrastructure and software."

---

## Compliance Summary Table

| Control Family | NIST 800-53 Rev 5 | ISO 27001:2022 | SOC 2 CC Series |
| :--- | :--- | :--- | :--- |
| **Access Control** | AC-2, AC-3, AC-6 | A.5.15, A.8.2, A.8.3 | CC6.1, CC6.3 |
| **Audit & Accountability** | AU-2, AU-6, AU-12 | A.8.15, A.8.16 | CC7.2, CC7.3 |
| **Config Management** | CM-6, CM-7, CM-8 | A.8.9, A.8.19 | CC7.1 |
| **System Protection** | SC-7, SC-28 | A.8.14, A.8.21 | CC6.6, CC6.7 |
| **Risk Remediation** | SI-2, SI-11 | A.8.8, A.8.31 | CC7.1 |
