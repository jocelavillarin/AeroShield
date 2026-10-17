# AeroShield • Aviation Database Security Dashboard
> **Course:** IT 414 • Aviation Database Administration  
> **Level:** 4th Year IT | Design • Prototype • Demonstrate  
> **Challenge:** Creative UI/UX Prototype Challenge  
> **Brand Identity:** AeroShield • Cyber Defense & Zone Isolation for Airport Core Databases

---

## 🛫 Mission & Overview

Airport IT staff struggle to identify:
1. **Who accesses sensitive aviation records** (Passenger Manifest PNR, Flight Dispatch Plans, ATC radar telemetry).
2. **Which users have excessive permissions** (Privilege creep across ground ramp staff, contractors, and flight crews).
3. **When suspicious network activity occurs** (Off-hours database queries, brute force authentication from airport terminal kiosks).

**AeroShield** is a purpose-built security dashboard designed to make airport database security **visible, intuitive, and actionable**.

---

## 🛡️ The Five Required Dashboard Sections

AeroShield integrates all five required sections within a single cohesive aerospace-themed interface:

### 1. Security Overview
* **Key Metrics:** Real-time tracking of Active DB Users (128), Active Sessions (82), Blocked Unauthorized Queries (17), and Open Security Alerts (04).
* **Interactive Access Activity Chart:** Recreated from the laboratory design specifications showing hourly query loads across Gate Kiosks, AOC Dispatch, and Ramp Tablets with filterable time windows (`Today 24h`, `Peak Flights`, `Red-Eye Shift`).
* **High Priority Alert Card:** Instant callout of critical incidents (e.g., 15 failed logins via Gate C-12 Terminal) with one-click quarantine buttons.
* **Database Cluster Health:** Live status monitors for Oracle/PostgreSQL cluster engines (Flight Dispatch Core, Passenger PNR, ATC Telemetry, Baggage Recon).

### 2. Identity & Access Management (IAM)
* **Aviation Staff Directory:** Fictional aviation employees spanning Flight Dispatchers, Air Traffic Controllers, Ramp Operations Leads, Avionics Architects, and TSA Liaison Officers.
* **Clearance Tier Model:**
  * `TIER 1 • AIRSIDE SECRET`: ATC telemetry, Flight Dispatch master, Avionics firmware.
  * `TIER 2 • PASSENGER PII CONFIDENTIAL`: Passenger names, passports, Customs/TSA watchlist.
  * `TIER 3 • OPERATIONS STANDARD`: Gate assignments, baggage weight/balance, jet-fuel dispatch.
* **Granular Privilege Matrix:** Display of table-level grants (`SELECT`, `INSERT`, `UPDATE`, `ADMIN`).
* **Account Controls:** Ability to filter by role and status, suspend accounts, reactivate, or provision new aviation personnel.

### 3. Network Protection & Zone Firewalls
* **Segregated Airport VLAN Zones:**
  * **Zone 1: Airside Core** (ATC & Flight Plan DB — Strict Airgap & TLS 1.3 Mutual Authentication).
  * **Zone 2: Terminal Concourse** (Gate Kiosks & Baggage Sorting — VLAN 204).
  * **Zone 3: Landside Public DMZ** (Check-In Terminals — WAF Rate Limiting).
* **Authorized Endpoint Inventory:** Hardware MAC address verification, physical gate locations, IP subnets, and mTLS cryptographic certificate states.
* **Firewall Rules Matrix:** Ingress/Egress inspection policies filtering raw socket connections and blocking suspicious payloads.

### 4. Threat Monitoring & Active Response
* **Real-Time Threat Feed:** Categorized by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* **Detailed Violation Payloads:** Displays target database table, originating IP/terminal, and raw SQL query payload.
* **Actionable Defense Buttons:**
  * `Mitigate / Block`: Automatically isolates the offending endpoint and revokes compromised permissions.
  * `Acknowledge`: Records officer acknowledgment.
  * `Deep Inspect`: Opens full security forensic modal.
* **Simulated Threat Injection:** Button to inject live SQL injection and probe attacks into the streaming feed.

### 5. Immutable Audit Logs
* **Comprehensive Trail:** Captures *Who* did *What*, *When* (UTC), *Where* (IP/Location), and the *Allowed/Denied Result*.
* **Multi-Parameter Filtering:** Filter by Result (`ALLOWED` / `DENIED`), Target Database Table, or free-text search.
* **One-Click CSV Export:** Generates an official downloadable CSV audit report (`aeroshield_audit_trail_YYYY-MM-DD.csv`).

---

## ✨ Original Innovative Features (Exceeding Requirements)

Beyond the five mandatory sections, AeroShield includes three original features tailored specifically to airport cybersecurity:

### 1. 🔍 Zero-Trust Least-Privilege & Excessive Permission Scanner
* **Problem:** Ramp agents often accumulate unneeded database permissions over time (privilege creep).
* **Feature:** AeroShield continuously scans assigned grants against actual job duties. It automatically flagged user **David Kim (Ramp Operations Lead)** who had unauthorized `READ` privileges on the `passenger_manifest_pnr` database.
* **Action:** Includes a one-click **"Revoke Excessive Grant"** button that immediately enforces the Principle of Least Privilege and records the remediation in the audit log.

### 2. 🗺️ Interactive Restricted Airport Network-Zone Matrix
* **Visual Airport Map:** An interactive vector SVG map displaying physical and logical airport network boundaries (Airside Secure Zone, Terminal Concourse, Landside DMZ).
* **Live Pulsating Threat Beacons:** Visualizes compromised or suspicious terminals (e.g., Gate C-18 Kiosk) with real-time quarantine toggle controls.

### 3. 🚨 DEFCON-1 Emergency Airport Database Lockdown
* **Top Bar Control:** One-click emergency cyber lockdown trigger.
* **Behavior:** Immediately quarantines all untrusted landside DMZ queries, switches flight dispatch and passenger databases to read-only replica failover, preserves life-safety ATC telemetry, and activates a system-wide HUD warning.

---

## 🧪 Demonstration & Lab Evaluation Guide

To demonstrate the working prototype to an instructor or panel:

1. **Access Violation Walkthrough:**
   * Click the **"Simulate Access Violation"** button in the top banner.
   * Observe the critical incident alert: *Ramp Lead attempting unauthorized off-hours access to passenger manifest at Gate C-18*.
   * Click **"Execute Mitigation (Quarantine IP & Revoke Role)"**.
   * Notice that:
     * The Gate C-18 device is immediately quarantined on VLAN 999.
     * David Kim's excessive privileges are revoked and his account is suspended.
     * The Audit Log logs the `DENIED` violation and the corresponding administrative remediation.
     * The Airport Zone Map updates the beacon to isolated status.

2. **Surprise Challenge Demonstration (15 Failed Logins - Slide 6):**
   * Click **"Surprise Challenge (15 Logins)"** in the top banner or select **"15 Failed Logins Response"** in the sidebar.
   * Observe all 4 required components:
     1. **Alert Severity & Affected Account:** `CRITICAL` alert affecting `capt.chen` (`flight_dispatch_master`) originating from Gate C-12 Public Terminal (IP: 192.168.42.88).
     2. **Event History & Recommended Action:** Chronological 15-attempt brute-force probe timeline with recommended perimeter WAF drop and port shutdown.
     3. **Active Access/Network Controls:** Click **"Enforce Complete Defense"** to immediately drop IP 192.168.42.88, disable physical switch port `Gi1/0/14`, and lock the account.
     4. **Forensic Record for Investigation:** Click **"Export Forensic JSON Dossier"** to generate the official incident report file.
   * Review the real-system enforcement notes (PAM lockout, WAF token-bucket rate limiting, 802.1X port security, SIEM/SOAR playbooks).

3. **Least-Privilege Remediation Demonstration:**
   * Navigate to **Least-Privilege Engine** in the sidebar.
   * View the detected excessive grant on `passenger_manifest_pnr`.
   * Click **"Revoke Excessive Grant"** to see compliance reach 100%.

4. **Audit Trail Inspection & CSV Export:**
   * Navigate to **5. Audit Logs**.
   * Use the filter dropdown to view only **DENIED** events.
   * Click **"Export Audit CSV"** to download the official audit log file.

5. **5–7 Minute Defense Guide & 100-Point Rubric (Slide 7):**
   * Navigate to **Presentation & Rubric** in the sidebar.
   * Review the minute-by-minute speech script for your group, short design rationale, and rubric self-assessment (30 pts Creativity, 20 pts UI/UX, 20 pts Security Concepts, 15 pts Functionality, 10 pts Aviation Relevance, 5 pts Presentation).
   * Click **"Print / Save Defense PDF"** to produce documentation for grading.

6. **Emergency Lockdown Demonstration:**
   * Click **"Emergency Lockdown"** in the top banner to simulate a DEFCON-1 airport cyber response.
   * Click **"Lift Lockdown"** to restore normal flight operations.

7. **Reset Demo:**
   * Click **"Reset Demo"** in the top right at any time to return the dashboard to its initial clean presentation state.

---

## 🚀 How to Run Locally

### Option A: Direct Browser Launch (No Installation Required)
Simply double-click [`index.html`](file:///C:/Users/Windows/.gemini/antigravity/scratch/AeroShield/index.html) in your file explorer or open it in Google Chrome, Microsoft Edge, Firefox, or Safari.

### Option B: Local Python Web Server
Open a terminal in the project directory and run:
```bash
python -m http.server 8080
```
Then visit: `http://localhost:8080` in your web browser.

---

## 🔒 Academic Safety Disclaimer

> [!NOTE]  
> **Academic Laboratory Activity (IT 414 • Aviation Database Administration):**  
> All employee names, aircraft identifiers, flight numbers, IP addresses, and database schemas in this prototype are entirely fictional. This software is designed solely for educational demonstration of database access control, network segregation, and threat response concepts.  
> *Do not connect to production airport systems or claim simulated controls stop real attacks.*
