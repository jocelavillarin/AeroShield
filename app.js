/**
 * AeroShield • Aviation Database Security Dashboard
 * Course: IT 414 • Aviation Database Administration
 * 4th Year IT Laboratory Prototype
 */

(function () {
  'use strict';

  // ==========================================================================
  // INITIAL MOCK DATASETS (Fictional Aviation Database Environment)
  // ==========================================================================

  const INITIAL_STATE = {
    users: [
      {
        id: "AV-1092",
        name: "Capt. James Chen",
        department: "Flight Operations",
        role: "Flight Dispatcher",
        clearance: "TIER 1 • AIRSIDE SECRET",
        permissions: ["flight_dispatch_master (READ/WRITE)", "atc_radar_telemetry (READ)"],
        status: "Active",
        riskScore: 12,
        hasExcessivePrivileges: false
      },
      {
        id: "AV-2041",
        name: "Elena Rostova",
        department: "Avionics Engineering",
        role: "Avionics Database Architect",
        clearance: "TIER 1 • AIRSIDE SECRET",
        permissions: ["flight_dispatch_master (ADMIN)", "atc_radar_telemetry (ADMIN)", "avionics_firmware (WRITE)"],
        status: "Active",
        riskScore: 8,
        hasExcessivePrivileges: false
      },
      {
        id: "AV-3819",
        name: "Marcus Vance",
        department: "Ground Services",
        role: "Baggage Handling Supervisor",
        clearance: "TIER 3 • OPERATIONS STANDARD",
        permissions: ["baggage_weight_balance (READ/WRITE)", "flight_schedules (READ)"],
        status: "Active",
        riskScore: 18,
        hasExcessivePrivileges: false
      },
      {
        id: "AV-4402",
        name: "David Kim",
        department: "Ramp Services",
        role: "Ramp Operations Lead",
        clearance: "TIER 3 • OPERATIONS STANDARD",
        permissions: ["jet_fuel_allocation (READ/WRITE)", "passenger_manifest_pnr (READ - UNAPPROVED)"],
        status: "Flagged",
        riskScore: 88,
        hasExcessivePrivileges: true,
        excessiveDetails: "Assigned unapproved READ access to Passenger PII Manifest (`passenger_manifest_pnr`). Violates FAA / GDPR Least-Privilege principle."
      },
      {
        id: "AV-5190",
        name: "Sarah Al-Mansoor",
        department: "Airport Security & Customs",
        role: "TSA Liaison Officer",
        clearance: "TIER 2 • PASSENGER PII CONFIDENTIAL",
        permissions: ["passenger_manifest_pnr (READ)", "customs_watchlist (READ/WRITE)"],
        status: "Active",
        riskScore: 15,
        hasExcessivePrivileges: false
      },
      {
        id: "AV-6288",
        name: "Maya Patel",
        department: "Air Traffic Control",
        role: "Air Traffic Controller",
        clearance: "TIER 1 • AIRSIDE SECRET",
        permissions: ["atc_radar_telemetry (READ/WRITE)", "runway_surface_radar (READ)"],
        status: "Active",
        riskScore: 5,
        hasExcessivePrivileges: false
      },
      {
        id: "AV-7014",
        name: "Liam O'Connor",
        department: "Terminal Operations",
        role: "Ground Gate Controller",
        clearance: "TIER 3 • OPERATIONS STANDARD",
        permissions: ["gate_assignments (READ/WRITE)", "flight_schedules (READ)"],
        status: "Active",
        riskScore: 20,
        hasExcessivePrivileges: false
      },
      {
        id: "AV-8831",
        name: "Viktor Novikov",
        department: "Airport IT Security",
        role: "Airport IT Admin",
        clearance: "TIER 1 • AIRSIDE SECRET",
        permissions: ["security_audit_vault (READ/WRITE)", "db_firewall_rules (WRITE)"],
        status: "Active",
        riskScore: 10,
        hasExcessivePrivileges: false
      }
    ],

    devices: [
      {
        id: "DEV-T1-K09",
        name: "Gate C-18 Self-Service Terminal",
        type: "Interactive Kiosk",
        location: "Terminal 2, Concourse C, Gate C-18",
        zone: "Zone 2 (Concourse)",
        ip: "192.168.42.88",
        mac: "00:1A:2B:3C:4D:5E",
        mtls: "VALID (Expires in 42d)",
        status: "Quarantine Recommended"
      },
      {
        id: "DEV-ATC-01",
        name: "ATC Tower Main Console A",
        type: "Workstation",
        location: "Air Traffic Control Tower, Level 8",
        zone: "Zone 1 (Airside Core)",
        ip: "10.0.12.5",
        mac: "44:38:39:FF:00:11",
        mtls: "VALID (Hardware TPM 2.0)",
        status: "Authorized"
      },
      {
        id: "DEV-DISP-04",
        name: "Dispatch Master Console #4",
        type: "Server Blade",
        location: "Aviation Operations Center (AOC)",
        zone: "Zone 1 (Airside Core)",
        ip: "10.0.12.18",
        mac: "52:54:00:12:34:56",
        mtls: "VALID (mTLS Strict)",
        status: "Authorized"
      },
      {
        id: "DEV-RAMP-TAB-07",
        name: "Ramp Marshalling Tablet #7",
        type: "Rugged Panasonic Tablet",
        location: "Apron Stand F-04",
        zone: "Zone 2 (Concourse / Ramp)",
        ip: "192.168.42.104",
        mac: "A0:C5:89:12:77:99",
        mtls: "VALID (WPA3-Enterprise)",
        status: "Authorized"
      },
      {
        id: "DEV-CHK-33",
        name: "Terminal 1 Public Bag-Drop #33",
        type: "Automated Kiosk",
        location: "Terminal 1 Concourse Landside",
        zone: "Zone 3 (Landside DMZ)",
        ip: "172.16.50.33",
        mac: "00:15:5D:88:99:AA",
        mtls: "ISOLATED (DMZ Rate-Limited)",
        status: "Authorized"
      }
    ],

    firewallRules: [
      {
        id: "FW-RULE-101",
        origin: "Zone 1: Airside Core",
        target: "atc_radar_telemetry",
        portProtocol: "TCP / 5432 (TLS 1.3)",
        payload: "Strict Protobuf / JSON",
        state: "Active (Strict)",
        action: "ALLOW"
      },
      {
        id: "FW-RULE-102",
        origin: "Zone 2: Terminal Concourse",
        target: "passenger_manifest_pnr",
        portProtocol: "TCP / 443 (mTLS Required)",
        payload: "REST API (HMAC Signed)",
        state: "Active (Inspected)",
        action: "ALLOW"
      },
      {
        id: "FW-RULE-103",
        origin: "Zone 3: Landside DMZ",
        target: "Direct Database Listener",
        portProtocol: "ANY",
        payload: "Raw SQL / Direct Sockets",
        state: "Permanent Drop",
        action: "BLOCK & LOG"
      },
      {
        id: "FW-RULE-104",
        origin: "Any Unregistered Wi-Fi MAC",
        target: "flight_dispatch_master",
        portProtocol: "ANY",
        payload: "Any Ingress Query",
        state: "Enforced Quarantine",
        action: "REJECT"
      }
    ],

    threats: [
      {
        id: "THREAT-9941",
        severity: "CRITICAL",
        status: "OPEN",
        timestamp: "03:19:12 UTC",
        title: "Unauthorized Off-Hours Access Attempt to Passenger PII Manifest",
        sourceUser: "david.kim (Ramp Services)",
        sourceIp: "192.168.42.88 (Gate C-18 Kiosk)",
        targetTable: "passenger_manifest_pnr",
        sqlQuery: "SELECT passenger_name, passport_no, dob FROM passenger_manifest_pnr WHERE flight_no='AF-892';",
        violationType: "Privilege Boundary Breach & Segregation of Duty Violation",
        mitigated: false
      },
      {
        id: "THREAT-9938",
        severity: "HIGH",
        status: "OPEN",
        timestamp: "03:14:05 UTC",
        title: "15 Failed Logins on Flight Dispatch Master via Gate Kiosk",
        sourceUser: "UNKNOWN_GUEST_ACCT",
        sourceIp: "192.168.42.88 (Gate C-12 Terminal)",
        targetTable: "flight_dispatch_master",
        sqlQuery: "AUTH_ATTEMPT --brute_force_dictionary_probe",
        violationType: "Credential Stuffing & Unapproved Endpoint",
        mitigated: false
      },
      {
        id: "THREAT-9932",
        severity: "MEDIUM",
        status: "OPEN",
        timestamp: "02:45:20 UTC",
        title: "Unscheduled Bulk Schema Read on Baggage Weight & Balance",
        sourceUser: "marcus.vance",
        sourceIp: "192.168.42.102 (Baggage Sorting Office)",
        targetTable: "baggage_weight_balance",
        sqlQuery: "SELECT * FROM baggage_weight_balance LIMIT 5000;",
        violationType: "Anomalous Volume Query (> normal threshold 50 rows)",
        mitigated: false
      },
      {
        id: "THREAT-9925",
        severity: "LOW",
        status: "ACKNOWLEDGED",
        timestamp: "01:10:48 UTC",
        title: "mTLS Certificate Grace Expiration Warning",
        sourceUser: "SYSTEM_MONITOR",
        sourceIp: "192.168.42.104 (Ramp Marshalling Tablet #7)",
        targetTable: "TLS_HANDSHAKE_VAULT",
        sqlQuery: "N/A (Certificate expires in 42 hours)",
        violationType: "PKI Key Rotation Due",
        mitigated: false
      }
    ],

    auditLogs: [
      {
        timestamp: "03:19:12 UTC",
        user: "david.kim (AV-4402)",
        role: "Ramp Operations Lead",
        table: "passenger_manifest_pnr",
        action: "SELECT (PII Query)",
        location: "192.168.42.88 (Gate C-18 Kiosk)",
        result: "DENIED",
        reason: "Access rule #204 violated: Role lacks Tier 2 clearance."
      },
      {
        timestamp: "03:18:40 UTC",
        user: "capt.chen (AV-1092)",
        role: "Flight Dispatcher",
        table: "flight_dispatch_master",
        action: "UPDATE (Flight AF-892 Fuel Trim)",
        location: "10.0.12.18 (AOC Dispatch Console)",
        result: "ALLOWED",
        reason: "Valid dispatch session with active license verification."
      },
      {
        timestamp: "03:15:22 UTC",
        user: "elena.rostova (AV-2041)",
        role: "Avionics DB Architect",
        table: "atc_radar_telemetry",
        action: "SELECT (Telemetry Health Sync)",
        location: "10.0.12.5 (ATC Tower Console)",
        result: "ALLOWED",
        reason: "Tier 1 authenticated via hardware token."
      },
      {
        timestamp: "03:14:05 UTC",
        user: "UNKNOWN_PROBE",
        role: "Unauthenticated Guest",
        table: "flight_dispatch_master",
        action: "CONNECT / LOGIN PROBE",
        location: "192.168.42.88 (Gate C-12 Kiosk)",
        result: "DENIED",
        reason: "Blocked after 15 failed password attempts."
      },
      {
        timestamp: "03:10:14 UTC",
        user: "sarah.almansoor (AV-5190)",
        role: "TSA Liaison Officer",
        table: "passenger_manifest_pnr",
        action: "SELECT (Flight AF-892 Manifest)",
        location: "10.0.22.4 (Security Operations Center)",
        result: "ALLOWED",
        reason: "Official TSA inspection session with logging."
      },
      {
        timestamp: "02:59:01 UTC",
        user: "liam.oconnor (AV-7014)",
        role: "Ground Gate Controller",
        table: "flight_dispatch_master",
        action: "UPDATE (Gate C-18 Reassignment)",
        location: "192.168.42.15 (Terminal 2 Desk)",
        result: "ALLOWED",
        reason: "Gate assignment policy matched."
      },
      {
        timestamp: "02:45:20 UTC",
        user: "marcus.vance (AV-3819)",
        role: "Baggage Supervisor",
        table: "baggage_weight_balance",
        action: "SELECT (Bulk 5,000 Rows)",
        location: "192.168.42.102 (Baggage Office)",
        result: "ALLOWED",
        reason: "Permitted role, flagged for anomalous volume review."
      },
      {
        timestamp: "02:30:11 UTC",
        user: "EXTERNAL_HOST_77.88.9.1",
        role: "Public Internet Ingress",
        table: "Direct Port 5432 Listener",
        action: "SYN FLOOD / PORT SCAN",
        location: "77.88.9.1 (External Host)",
        result: "DENIED",
        reason: "Air-Shield WAF dropped connection at airport boundary."
      },
      {
        timestamp: "02:15:44 UTC",
        user: "maya.patel (AV-6288)",
        role: "Air Traffic Controller",
        table: "atc_radar_telemetry",
        action: "INSERT (Flight Track Vector KORD-09L)",
        location: "10.0.12.5 (ATC Tower Console)",
        result: "ALLOWED",
        reason: "ATC stream write permitted."
      },
      {
        timestamp: "01:50:00 UTC",
        user: "viktor.novikov (AV-8831)",
        role: "Airport IT Admin",
        table: "airside_security_clearance",
        action: "SELECT (Audit Validation)",
        location: "10.0.30.2 (IT Operations Vault)",
        result: "ALLOWED",
        reason: "Scheduled automated compliance check."
      }
    ],

    // Chart mock data for 24 hours
    chartData: {
      today: [
        { hour: "00h", count: 42, type: "normal" },
        { hour: "02h", count: 28, type: "normal" },
        { hour: "04h", count: 35, type: "normal" },
        { hour: "06h", count: 85, type: "normal" },
        { hour: "08h", count: 142, type: "normal" },
        { hour: "10h", count: 188, type: "normal" },
        { hour: "12h", count: 165, type: "normal" },
        { hour: "14h", count: 210, type: "highlight" }, // Highlighted bar like Slide 1
        { hour: "16h", count: 195, type: "normal" },
        { hour: "18h", count: 172, type: "normal" },
        { hour: "20h", count: 110, type: "normal" },
        { hour: "22h", count: 64, type: "normal" },
        { hour: "03h (Now)", count: 96, type: "spike" }
      ],
      peak: [
        { hour: "08h", count: 140, type: "normal" },
        { hour: "09h", count: 180, type: "normal" },
        { hour: "10h", count: 230, type: "normal" },
        { hour: "11h", count: 250, type: "highlight" },
        { hour: "12h", count: 210, type: "normal" },
        { hour: "13h", count: 195, type: "normal" },
        { hour: "14h", count: 240, type: "normal" },
        { hour: "15h", count: 220, type: "normal" }
      ],
      night: [
        { hour: "22h", count: 50, type: "normal" },
        { hour: "23h", count: 42, type: "normal" },
        { hour: "00h", count: 30, type: "normal" },
        { hour: "01h", count: 25, type: "normal" },
        { hour: "02h", count: 20, type: "normal" },
        { hour: "03h", count: 98, type: "spike" },
        { hour: "04h", count: 32, type: "normal" },
        { hour: "05h", count: 45, type: "normal" }
      ]
    },

    isLockdownActive: false
  };

  // Working state cloned from initial
  let state = JSON.parse(JSON.stringify(INITIAL_STATE));

  // ==========================================================================
  // DOM ELEMENT SELECTORS
  // ==========================================================================
  const elements = {
    // Nav & Layout
    navItems: document.querySelectorAll('.nav-item'),
    sections: document.querySelectorAll('.dashboard-section'),
    pageTitle: document.getElementById('pageTitle'),
    breadcrumbSection: document.getElementById('breadcrumbSection'),
    liveUtcClock: document.getElementById('liveUtcClock'),
    globalSearchInput: document.getElementById('globalSearchInput'),
    quickHelpBtn: document.getElementById('quickHelpBtn'),

    // Top Banners & Actions
    scenarioBtn: document.getElementById('scenarioBtn'),
    lockdownToggleBtn: document.getElementById('lockdownToggleBtn'),
    lockdownBtnText: document.getElementById('lockdownBtnText'),
    resetDemoBtn: document.getElementById('resetDemoBtn'),
    lockdownAlertBanner: document.getElementById('lockdownAlertBanner'),
    deactivateLockdownBtn: document.getElementById('deactivateLockdownBtn'),
    violationAlertBox: document.getElementById('violationAlertBox'),
    mitigateViolationBtn: document.getElementById('mitigateViolationBtn'),
    viewViolationLogBtn: document.getElementById('viewViolationLogBtn'),
    dismissViolationBtn: document.getElementById('dismissViolationBtn'),

    // Badges & Counters
    badgeOverviewAlerts: document.getElementById('badgeOverviewAlerts'),
    badgeRiskyUsers: document.getElementById('badgeRiskyUsers'),
    badgeOpenThreats: document.getElementById('badgeOpenThreats'),
    badgeLogCount: document.getElementById('badgeLogCount'),
    statUsers: document.getElementById('statUsers'),
    statAlerts: document.getElementById('statAlerts'),
    statBlocked: document.getElementById('statBlocked'),
    statIntegrity: document.getElementById('statIntegrity'),

    // Overview section
    accessChartContainer: document.getElementById('accessChartContainer'),
    overviewLiveTableBody: document.getElementById('overviewLiveTableBody'),
    highPriorityWidget: document.getElementById('highPriorityWidget'),
    btnQuickBlockHighPriority: document.getElementById('btnQuickBlockHighPriority'),
    btnQuickInvestigate: document.getElementById('btnQuickInvestigate'),

    // IAM Section
    iamTableBody: document.getElementById('iamTableBody'),
    iamRoleFilter: document.getElementById('iamRoleFilter'),
    iamStatusFilter: document.getElementById('iamStatusFilter'),
    iamCountBadge: document.getElementById('iamCountBadge'),
    addStaffModalBtn: document.getElementById('addStaffModalBtn'),

    // Network Section
    deviceTableBody: document.getElementById('deviceTableBody'),
    firewallRulesBody: document.getElementById('firewallRulesBody'),
    addDeviceBtn: document.getElementById('addDeviceBtn'),
    addRuleBtn: document.getElementById('addRuleBtn'),

    // Threats Section
    threatCardsContainer: document.getElementById('threatCardsContainer'),
    threatSeverityFilter: document.getElementById('threatSeverityFilter'),
    threatStatusFilter: document.getElementById('threatStatusFilter'),
    triggerThreatSimBtn: document.getElementById('triggerThreatSimBtn'),

    // Audit Section
    auditTableBody: document.getElementById('auditTableBody'),
    auditResultFilter: document.getElementById('auditResultFilter'),
    auditTableFilter: document.getElementById('auditTableFilter'),
    auditSearchInput: document.getElementById('auditSearchInput'),
    auditShowingBadge: document.getElementById('auditShowingBadge'),
    exportCsvBtn: document.getElementById('exportCsvBtn'),

    // Original Feature 1: Least-Privilege
    privilegeDetectorBody: document.getElementById('privilegeDetectorBody'),
    runLeastPrivilegeScanBtn: document.getElementById('runLeastPrivilegeScanBtn'),
    excessivePrivCount: document.getElementById('excessivePrivCount'),

    // Original Feature 2: Airport Map
    mapSelectedNode: document.getElementById('mapSelectedNode'),
    mapQuarantineBtn: document.getElementById('mapQuarantineBtn'),
    mapPingBtn: document.getElementById('mapPingBtn'),
    gateC18Pulse: document.getElementById('gateC18Pulse'),
    gateC18Node: document.getElementById('gateC18Node'),
    zone2StatusText: document.getElementById('zone2StatusText'),

    // Modal & Toast
    actionModal: document.getElementById('actionModal'),
    modalTitle: document.getElementById('modalTitle'),
    modalBody: document.getElementById('modalBody'),
    modalFooter: document.getElementById('modalFooter'),
    modalCloseBtn: document.getElementById('modalCloseBtn'),
    modalCancelBtn: document.getElementById('modalCancelBtn'),
    modalConfirmBtn: document.getElementById('modalConfirmBtn'),
    toastContainer: document.getElementById('toastContainer')
  };

  // ==========================================================================
  // INITIALIZATION
  // ==========================================================================
  function init() {
    startUtcClock();
    setupNavigation();
    setupChart('today');
    renderOverview();
    renderIAM();
    renderNetwork();
    renderThreats();
    renderAuditLogs();
    renderPrivilegeScanner();
    setupEventHandlers();
  }

  // ==========================================================================
  // LIVE CLOCK
  // ==========================================================================
  function startUtcClock() {
    function update() {
      const now = new Date();
      const h = String(now.getUTCHours()).padStart(2, '0');
      const m = String(now.getUTCMinutes()).padStart(2, '0');
      const s = String(now.getUTCSeconds()).padStart(2, '0');
      if (elements.liveUtcClock) {
        elements.liveUtcClock.textContent = `${h}:${m}:${s} UTC`;
      }
    }
    update();
    setInterval(update, 1000);
  }

  // ==========================================================================
  // NAVIGATION & TAB SWITCHING
  // ==========================================================================
  function switchSection(targetSectionId) {
    elements.sections.forEach(sec => {
      sec.classList.remove('active');
      if (sec.id === `section-${targetSectionId}`) {
        sec.classList.add('active');
      }
    });

    elements.navItems.forEach(item => {
      item.classList.remove('active');
      if (item.dataset.section === targetSectionId) {
        item.classList.add('active');
      }
    });

    const titleMap = {
      overview: "1. Security Overview • Airport DB Health",
      identity: "2. Identity & Access Management (IAM)",
      network: "3. Network Protection & Zone Firewalls",
      threats: "4. Threat Monitoring & Active Responses",
      audit: "5. Immutable Aviation Database Audit Trail",
      privileges: "Original Feature #1 • Least-Privilege & RBAC Scanner",
      "airport-map": "Original Feature #2 • Interactive Airport Network-Zone Matrix"
    };

    if (elements.pageTitle) {
      elements.pageTitle.textContent = titleMap[targetSectionId] || "AeroShield Dashboard";
    }
    if (elements.breadcrumbSection) {
      elements.breadcrumbSection.textContent = targetSectionId.toUpperCase().replace('-', ' ');
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function setupNavigation() {
    elements.navItems.forEach(item => {
      item.addEventListener('click', () => {
        const section = item.dataset.section;
        switchSection(section);
      });
    });

    // In-page navigation helper links
    document.addEventListener('click', (e) => {
      const targetLink = e.target.closest('[data-nav-target]');
      if (targetLink) {
        e.preventDefault();
        switchSection(targetLink.dataset.navTarget);
      }
      const inlineLink = e.target.closest('.nav-link-inline');
      if (inlineLink) {
        e.preventDefault();
        switchSection(inlineLink.dataset.section);
      }
    });
  }

  // ==========================================================================
  // ACCESS ACTIVITY CHART (Slide 1 Recreation)
  // ==========================================================================
  function setupChart(period) {
    const data = state.chartData[period] || state.chartData.today;
    elements.accessChartContainer.innerHTML = '';

    const maxCount = Math.max(...data.map(d => d.count), 250);

    data.forEach(item => {
      const col = document.createElement('div');
      col.className = 'chart-bar-col';

      const heightPct = Math.round((item.count / maxCount) * 100);

      const fill = document.createElement('div');
      fill.className = `chart-bar-fill ${item.type}`;
      fill.style.height = `${Math.max(heightPct, 12)}%`;

      const tooltip = document.createElement('div');
      tooltip.className = 'chart-bar-tooltip';
      tooltip.innerHTML = `<strong>${item.hour}</strong><br>${item.count} queries/hr`;

      col.appendChild(tooltip);
      col.appendChild(fill);

      col.addEventListener('click', () => {
        showToast(`Selected time window ${item.hour}: ${item.count} queries analyzed.`, 'info');
      });

      elements.accessChartContainer.appendChild(col);
    });

    // Update pill buttons
    document.querySelectorAll('[data-chart-period]').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.chartPeriod === period);
      btn.onclick = () => setupChart(btn.dataset.chartPeriod);
    });
  }

  // ==========================================================================
  // SECTION 1: SECURITY OVERVIEW
  // ==========================================================================
  function renderOverview() {
    const openThreatCount = state.threats.filter(t => t.status === 'OPEN').length;
    const blockedCount = state.auditLogs.filter(l => l.result === 'DENIED').length;

    elements.badgeOverviewAlerts.textContent = openThreatCount;
    elements.badgeOpenThreats.textContent = openThreatCount;
    elements.statAlerts.textContent = openThreatCount < 10 ? `0${openThreatCount}` : openThreatCount;
    elements.statBlocked.textContent = blockedCount;
    elements.statUsers.textContent = state.users.length * 16; // Simulated 128 airport DB users
    elements.badgeRiskyUsers.textContent = state.users.filter(u => u.hasExcessivePrivileges).length;
    elements.badgeLogCount.textContent = state.auditLogs.length;

    // Overview Table (Top 5 recent events)
    elements.overviewLiveTableBody.innerHTML = '';
    state.auditLogs.slice(0, 5).forEach(log => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${log.timestamp}</td>
        <td><strong>${escapeHtml(log.user)}</strong></td>
        <td><code class="code-hl">${escapeHtml(log.table)}</code></td>
        <td>${escapeHtml(log.action)}</td>
        <td>
          <span class="severity-pill ${log.result === 'DENIED' ? 'critical' : 'medium'}">
            ${log.result === 'DENIED' ? 'SUSPICIOUS' : 'AUTHORIZED'}
          </span>
        </td>
        <td>
          <span class="result-badge ${log.result === 'DENIED' ? 'denied' : 'allowed'}">
            ${log.result}
          </span>
        </td>
      `;
      elements.overviewLiveTableBody.appendChild(tr);
    });
  }

  // ==========================================================================
  // SECTION 2: IDENTITY & ACCESS MANAGEMENT (IAM)
  // ==========================================================================
  function renderIAM() {
    const roleFilter = elements.iamRoleFilter.value;
    const statusFilter = elements.iamStatusFilter.value;

    const filtered = state.users.filter(user => {
      const matchRole = roleFilter === 'ALL' || user.role === roleFilter;
      const matchStatus = statusFilter === 'ALL' || user.status === statusFilter;
      return matchRole && matchStatus;
    });

    elements.iamCountBadge.textContent = `Showing ${filtered.length} of ${state.users.length} Airport Staff`;
    elements.iamTableBody.innerHTML = '';

    filtered.forEach(user => {
      const tr = document.createElement('tr');
      if (user.status === 'Flagged') tr.classList.add('row-flagged');

      const initials = user.name.split(' ').map(n => n[0]).join('').substring(0, 2);

      const permsHtml = user.permissions.map(p => {
        const isExcessive = p.includes('UNAPPROVED');
        return `<span class="perm-chip ${isExcessive ? 'excessive' : ''}">${escapeHtml(p)}</span>`;
      }).join(' ');

      const riskClass = user.riskScore > 70 ? 'high' : user.riskScore > 30 ? 'medium' : 'low';

      tr.innerHTML = `
        <td>
          <div class="user-cell">
            <div class="user-mini-avatar">${initials}</div>
            <div>
              <div class="user-meta-name">${escapeHtml(user.name)}</div>
              <div class="user-meta-id">${escapeHtml(user.id)}</div>
            </div>
          </div>
        </td>
        <td>
          <div style="font-weight: 600; color: #fff;">${escapeHtml(user.role)}</div>
          <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(user.department)}</div>
        </td>
        <td><span class="badge-tier ${getClearanceClass(user.clearance)}">${escapeHtml(user.clearance)}</span></td>
        <td><div class="perm-chips">${permsHtml}</div></td>
        <td>
          <span class="status-pill ${user.status.toLowerCase()}">
            <span class="dot-online" style="${user.status === 'Suspended' ? 'background: var(--accent-danger)' : ''}"></span>
            ${escapeHtml(user.status)}
          </span>
        </td>
        <td>
          <div class="risk-meter">
            <div class="risk-bar-bg"><div class="risk-bar-fill ${riskClass}"></div></div>
            <span style="font-family: var(--font-mono); font-size: 0.75rem; font-weight: 700;">${user.riskScore}%</span>
          </div>
        </td>
        <td>
          <div style="display: flex; gap: 0.35rem;">
            ${user.status === 'Active' || user.status === 'Flagged' ? 
              `<button class="btn btn-ghost btn-sm btn-suspend-user" data-user-id="${user.id}" title="Suspend account">Suspend</button>` :
              `<button class="btn btn-primary btn-sm btn-activate-user" data-user-id="${user.id}" title="Reactivate account">Activate</button>`
            }
            <button class="btn btn-ghost btn-sm btn-view-grants" data-user-id="${user.id}">Grants</button>
          </div>
        </td>
      `;
      elements.iamTableBody.appendChild(tr);
    });

    attachIamActionListeners();
  }

  function getClearanceClass(clearance) {
    if (clearance.includes('AIRSIDE')) return 'tier-airside';
    if (clearance.includes('PNR')) return 'tier-pnr';
    return 'tier-ops';
  }

  function attachIamActionListeners() {
    document.querySelectorAll('.btn-suspend-user').forEach(btn => {
      btn.onclick = () => {
        const u = state.users.find(x => x.id === btn.dataset.userId);
        if (u) {
          u.status = 'Suspended';
          logAuditAction('ADMIN_CONSOLE', 'SYSTEM_ADMIN', `Suspended user account ${u.name} (${u.id})`, 'ALLOWED', 'Security officer administrative suspension');
          renderIAM();
          renderOverview();
          showToast(`Account suspended: ${u.name}`, 'warning');
        }
      };
    });

    document.querySelectorAll('.btn-activate-user').forEach(btn => {
      btn.onclick = () => {
        const u = state.users.find(x => x.id === btn.dataset.userId);
        if (u) {
          u.status = u.hasExcessivePrivileges ? 'Flagged' : 'Active';
          logAuditAction('ADMIN_CONSOLE', 'SYSTEM_ADMIN', `Reactivated user account ${u.name} (${u.id})`, 'ALLOWED', 'Administrative reactivation');
          renderIAM();
          renderOverview();
          showToast(`Account reactivated: ${u.name}`, 'success');
        }
      };
    });

    document.querySelectorAll('.btn-view-grants').forEach(btn => {
      btn.onclick = () => {
        const u = state.users.find(x => x.id === btn.dataset.userId);
        if (u) {
          openModal(
            `Database Grants • ${u.name} (${u.id})`,
            `
              <p><strong>Department:</strong> ${escapeHtml(u.department)}</p>
              <p><strong>Clearance:</strong> ${escapeHtml(u.clearance)}</p>
              <p style="margin-top: 1rem;"><strong>Active PostgreSQL / Oracle Grants:</strong></p>
              <ul style="margin: 0.5rem 0 0 1.25rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan);">
                ${u.permissions.map(p => `<li>${escapeHtml(p)}</li>`).join('')}
              </ul>
              ${u.hasExcessivePrivileges ? `
                <div style="margin-top: 1rem; padding: 0.75rem; background: rgba(255, 69, 96, 0.1); border: 1px solid var(--accent-danger); border-radius: 6px;">
                  <strong style="color: var(--accent-danger);">Security Alert:</strong>
                  <p style="font-size: 0.8rem; margin-top: 0.25rem;">${escapeHtml(u.excessiveDetails)}</p>
                </div>
              ` : ''}
            `,
            'Close Window',
            null
          );
        }
      };
    });
  }

  // ==========================================================================
  // SECTION 3: NETWORK PROTECTION & ZONE FIREWALL
  // ==========================================================================
  function renderNetwork() {
    // Devices Table
    elements.deviceTableBody.innerHTML = '';
    state.devices.forEach(dev => {
      const tr = document.createElement('tr');
      const isQuarantine = dev.status.includes('Quarantine');

      tr.innerHTML = `
        <td><strong style="color: #fff;">${escapeHtml(dev.id)}</strong><br><span style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(dev.name)}</span></td>
        <td>${escapeHtml(dev.type)}</td>
        <td>${escapeHtml(dev.location)}</td>
        <td><span class="badge-tier tier-pnr">${escapeHtml(dev.zone)}</span></td>
        <td>
          <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--accent-cyan);">${escapeHtml(dev.ip)}</div>
          <div style="font-family: var(--font-mono); font-size: 0.68rem; color: var(--text-muted);">${escapeHtml(dev.mac)}</div>
        </td>
        <td><span style="font-size: 0.72rem; color: var(--accent-teal);">${escapeHtml(dev.mtls)}</span></td>
        <td>
          <span class="status-pill ${isQuarantine ? 'suspended' : 'active'}">
            ${escapeHtml(dev.status)}
          </span>
        </td>
        <td>
          ${isQuarantine ? 
            `<button class="btn btn-danger btn-sm btn-quarantine-dev" data-dev-id="${dev.id}">Quarantine Device</button>` :
            `<button class="btn btn-ghost btn-sm btn-ping-dev" data-dev-id="${dev.id}">Ping mTLS</button>`
          }
        </td>
      `;
      elements.deviceTableBody.appendChild(tr);
    });

    // Firewall Rules
    elements.firewallRulesBody.innerHTML = '';
    state.firewallRules.forEach(rule => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code class="code-hl">${escapeHtml(rule.id)}</code></td>
        <td>${escapeHtml(rule.origin)}</td>
        <td><strong style="color: #fff;">${escapeHtml(rule.target)}</strong></td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(rule.portProtocol)}</td>
        <td>${escapeHtml(rule.payload)}</td>
        <td><span class="badge-safe">${escapeHtml(rule.state)}</span></td>
        <td><span class="result-badge ${rule.action.includes('ALLOW') ? 'allowed' : 'denied'}">${escapeHtml(rule.action)}</span></td>
      `;
      elements.firewallRulesBody.appendChild(tr);
    });

    // Device actions
    document.querySelectorAll('.btn-quarantine-dev').forEach(btn => {
      btn.onclick = () => {
        const d = state.devices.find(x => x.id === btn.dataset.devId);
        if (d) {
          d.status = "QUARANTINED (VLAN 999)";
          logAuditAction('AIR-SHIELD WAF', 'DEVICE_GUARD', `Hardware token quarantine applied to ${d.name} (${d.ip})`, 'ALLOWED', 'Manual security isolation');
          renderNetwork();
          renderOverview();
          updateAirportZoneMapQuarantineState(true);
          showToast(`Quarantined endpoint: ${d.name} on VLAN 999`, 'danger');
        }
      };
    });

    document.querySelectorAll('.btn-ping-dev').forEach(btn => {
      btn.onclick = () => {
        showToast(`mTLS Health Check OK: ${btn.dataset.devId} latency 0.3ms`, 'success');
      };
    });
  }

  // ==========================================================================
  // SECTION 4: THREAT MONITORING
  // ==========================================================================
  function renderThreats() {
    const sevFilter = elements.threatSeverityFilter.value;
    const statFilter = elements.threatStatusFilter.value;

    const filtered = state.threats.filter(t => {
      const matchSev = sevFilter === 'ALL' || t.severity === sevFilter;
      const matchStat = statFilter === 'ALL' || t.status === statFilter;
      return matchSev && matchStat;
    });

    elements.threatCardsContainer.innerHTML = '';

    if (filtered.length === 0) {
      elements.threatCardsContainer.innerHTML = `
        <div style="grid-column: 1/-1; text-align: center; padding: 3rem; color: var(--text-muted);">
          No active threats match current filter criteria.
        </div>
      `;
      return;
    }

    filtered.forEach(threat => {
      const card = document.createElement('div');
      card.className = `threat-card ${threat.severity.toLowerCase()}`;

      card.innerHTML = `
        <div class="threat-top">
          <span class="severity-pill ${threat.severity.toLowerCase()}">${threat.severity}</span>
          <span class="threat-time">${threat.timestamp}</span>
        </div>
        <h4 class="threat-title">${escapeHtml(threat.title)}</h4>
        <div class="threat-meta-box">
          <div class="meta-row">
            <span class="meta-key">Source Entity:</span>
            <span class="meta-val">${escapeHtml(threat.sourceUser)}</span>
          </div>
          <div class="meta-row">
            <span class="meta-key">Endpoint / IP:</span>
            <span class="meta-val">${escapeHtml(threat.sourceIp)}</span>
          </div>
          <div class="meta-row">
            <span class="meta-key">Target Table:</span>
            <span class="meta-val" style="color: var(--accent-cyan);">${escapeHtml(threat.targetTable)}</span>
          </div>
          <div class="meta-row">
            <span class="meta-key">Status:</span>
            <span class="meta-val" style="color: ${threat.status === 'OPEN' ? 'var(--accent-danger)' : 'var(--accent-teal)'};">${threat.status}</span>
          </div>
        </div>
        <div style="font-size: 0.75rem; color: var(--text-secondary); background: #081126; padding: 0.5rem; border-radius: 4px; font-family: var(--font-mono); overflow-x: auto;">
          ${escapeHtml(threat.sqlQuery)}
        </div>
        <div class="threat-actions-bar">
          ${threat.status === 'OPEN' ? `
            <button class="btn btn-danger btn-sm btn-mitigate-threat" data-threat-id="${threat.id}">Mitigate / Block</button>
            <button class="btn btn-ghost btn-sm btn-ack-threat" data-threat-id="${threat.id}">Acknowledge</button>
          ` : `
            <button class="btn btn-ghost btn-sm" disabled style="opacity: 0.6;">Threat Mitigated</button>
          `}
          <button class="btn btn-ghost btn-sm btn-inspect-threat" data-threat-id="${threat.id}">Deep Inspect</button>
        </div>
      `;

      elements.threatCardsContainer.appendChild(card);
    });

    attachThreatListeners();
  }

  function attachThreatListeners() {
    document.querySelectorAll('.btn-mitigate-threat').forEach(btn => {
      btn.onclick = () => {
        const t = state.threats.find(x => x.id === btn.dataset.threatId);
        if (t) {
          executeThreatMitigation(t);
        }
      };
    });

    document.querySelectorAll('.btn-ack-threat').forEach(btn => {
      btn.onclick = () => {
        const t = state.threats.find(x => x.id === btn.dataset.threatId);
        if (t) {
          t.status = 'ACKNOWLEDGED';
          renderThreats();
          renderOverview();
          showToast(`Alert acknowledged: ${t.id}`, 'info');
        }
      };
    });

    document.querySelectorAll('.btn-inspect-threat').forEach(btn => {
      btn.onclick = () => {
        const t = state.threats.find(x => x.id === btn.dataset.threatId);
        if (t) {
          openModal(
            `Threat Packet Investigation: ${t.id}`,
            `
              <p><strong>Incident Title:</strong> ${escapeHtml(t.title)}</p>
              <p><strong>Timestamp:</strong> ${escapeHtml(t.timestamp)}</p>
              <p><strong>Source Host:</strong> ${escapeHtml(t.sourceIp)}</p>
              <p><strong>Attempted SQL Query Payload:</strong></p>
              <pre style="background: #040815; padding: 0.75rem; border-radius: 6px; font-family: var(--font-mono); color: var(--accent-cyan); font-size: 0.8rem; margin: 0.5rem 0;">${escapeHtml(t.sqlQuery)}</pre>
              <p><strong>Violation Analysis:</strong></p>
              <p style="color: var(--accent-danger); font-size: 0.85rem;">${escapeHtml(t.violationType)}</p>
            `,
            'Close',
            null
          );
        }
      };
    });
  }

  function executeThreatMitigation(threat) {
    threat.status = 'MITIGATED';
    threat.mitigated = true;

    // Quarantine device if matched
    const dev = state.devices.find(d => threat.sourceIp.includes(d.ip));
    if (dev) dev.status = "QUARANTINED (VLAN 999)";

    // Suspend user if internal
    if (threat.sourceUser.includes('david.kim')) {
      const u = state.users.find(x => x.id === 'AV-4402');
      if (u) {
        u.status = 'Suspended';
        u.permissions = u.permissions.filter(p => !p.includes('UNAPPROVED'));
        u.hasExcessivePrivileges = false;
      }
    }

    // Log the remediation
    logAuditAction('WAF_AIRSHIELD', 'AUTO_DEFENSE', `Mitigated threat ${threat.id} on ${threat.targetTable} - Source IP Isolated`, 'ALLOWED', 'Automated Defense Execution');

    // Update Airport Zone Map
    updateAirportZoneMapQuarantineState(true);

    // Hide violation box if visible
    elements.violationAlertBox.classList.add('hidden');

    renderThreats();
    renderOverview();
    renderIAM();
    renderNetwork();
    renderAuditLogs();
    renderPrivilegeScanner();

    showToast(`Mitigation Successful: Threat ${threat.id} neutralized and endpoint isolated.`, 'success');
  }

  // ==========================================================================
  // SECTION 5: AUDIT LOGS
  // ==========================================================================
  function renderAuditLogs() {
    const resFilter = elements.auditResultFilter.value;
    const tblFilter = elements.auditTableFilter.value;
    const query = (elements.auditSearchInput.value || '').toLowerCase().trim();

    const filtered = state.auditLogs.filter(log => {
      const matchRes = resFilter === 'ALL' || log.result === resFilter;
      const matchTbl = tblFilter === 'ALL' || log.table === tblFilter;
      const matchQuery = !query || 
        log.user.toLowerCase().includes(query) ||
        log.table.toLowerCase().includes(query) ||
        log.action.toLowerCase().includes(query) ||
        log.location.toLowerCase().includes(query);

      return matchRes && matchTbl && matchQuery;
    });

    elements.auditShowingBadge.textContent = `Showing ${filtered.length} entries`;
    elements.auditTableBody.innerHTML = '';

    filtered.forEach(log => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${log.timestamp}</td>
        <td><strong style="color: #fff;">${escapeHtml(log.user)}</strong></td>
        <td><span style="font-size: 0.75rem;">${escapeHtml(log.role)}</span></td>
        <td><code class="code-hl">${escapeHtml(log.table)}</code></td>
        <td style="font-size: 0.78rem;">${escapeHtml(log.action)}</td>
        <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--accent-cyan);">${escapeHtml(log.location)}</td>
        <td><span class="result-badge ${log.result === 'ALLOWED' ? 'allowed' : 'denied'}">${log.result}</span></td>
        <td>
          <button class="btn btn-ghost btn-sm btn-inspect-log" style="padding: 0.15rem 0.45rem; font-size: 0.7rem;">Details</button>
        </td>
      `;

      tr.querySelector('.btn-inspect-log').onclick = () => {
        openModal(
          `Audit Entry Inspection: ${log.timestamp}`,
          `
            <p><strong>Actor:</strong> ${escapeHtml(log.user)}</p>
            <p><strong>Role:</strong> ${escapeHtml(log.role)}</p>
            <p><strong>Target Database Table:</strong> <code class="code-hl">${escapeHtml(log.table)}</code></p>
            <p><strong>Action Payload:</strong> ${escapeHtml(log.action)}</p>
            <p><strong>Origin IP & Terminal:</strong> ${escapeHtml(log.location)}</p>
            <p><strong>Result:</strong> <span class="result-badge ${log.result === 'ALLOWED' ? 'allowed' : 'denied'}">${log.result}</span></p>
            <p style="margin-top: 0.75rem;"><strong>Security Rationale:</strong></p>
            <p style="color: var(--text-secondary); background: #070e20; padding: 0.5rem; border-radius: 4px; font-size: 0.82rem;">${escapeHtml(log.reason)}</p>
          `,
          'Done',
          null
        );
      };

      elements.auditTableBody.appendChild(tr);
    });
  }

  function logAuditAction(user, role, action, result, reason) {
    const now = new Date();
    const timeStr = `${String(now.getUTCHours()).padStart(2, '0')}:${String(now.getUTCMinutes()).padStart(2, '0')}:${String(now.getUTCSeconds()).padStart(2, '0')} UTC`;
    state.auditLogs.unshift({
      timestamp: timeStr,
      user: user,
      role: role,
      table: "security_audit_vault",
      action: action,
      location: "127.0.0.1 (Local SecOps)",
      result: result,
      reason: reason
    });
  }

  // ==========================================================================
  // ORIGINAL FEATURE 1: LEAST-PRIVILEGE SCANNER
  // ==========================================================================
  function renderPrivilegeScanner() {
    const riskyUsers = state.users.filter(u => u.hasExcessivePrivileges);

    elements.excessivePrivCount.textContent = riskyUsers.length > 0 ? 
      `${riskyUsers.length} High Risk` : "0 (Fully Compliant)";

    elements.privilegeDetectorBody.innerHTML = '';

    if (riskyUsers.length === 0) {
      elements.privilegeDetectorBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 2.5rem; color: var(--accent-teal);">
            <strong>Zero-Trust Least-Privilege Verified:</strong> All active airport staff accounts strictly conform to minimum operational requirements.
          </td>
        </tr>
      `;
      return;
    }

    riskyUsers.forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong style="color: #fff;">${escapeHtml(u.name)}</strong> (${escapeHtml(u.id)})</td>
        <td>${escapeHtml(u.role)}</td>
        <td><span class="badge-tier tier-ops">Ramp & Fuel Operations</span></td>
        <td><span class="perm-chip excessive">passenger_manifest_pnr (READ)</span></td>
        <td><span class="badge-tier tier-pnr" style="color: var(--accent-danger);">PII Data Leakage Risk</span></td>
        <td>
          <button class="btn btn-primary btn-sm btn-remediate-privilege" data-user-id="${u.id}">
            Revoke Excessive Grant
          </button>
        </td>
      `;

      tr.querySelector('.btn-remediate-privilege').onclick = () => {
        remediatePrivileges(u);
      };

      elements.privilegeDetectorBody.appendChild(tr);
    });
  }

  function remediatePrivileges(user) {
    user.permissions = user.permissions.filter(p => !p.includes('UNAPPROVED'));
    user.hasExcessivePrivileges = false;
    user.status = 'Active';
    user.riskScore = 15;

    logAuditAction('LEAST_PRIVILEGE_ENGINE', 'IAM_AUTOMATION', `Revoked unapproved grant on passenger_manifest_pnr for ${user.name}`, 'ALLOWED', 'Enforced Principle of Least Privilege');

    renderPrivilegeScanner();
    renderIAM();
    renderOverview();
    renderAuditLogs();

    showToast(`Remediation Applied: Excessive grants revoked for ${user.name}. Compliance restored.`, 'success');
  }

  // ==========================================================================
  // ORIGINAL FEATURE 2: INTERACTIVE AIRPORT ZONE MATRIX
  // ==========================================================================
  function updateAirportZoneMapQuarantineState(isQuarantined) {
    if (elements.gateC18Pulse) {
      elements.gateC18Pulse.style.display = isQuarantined ? 'none' : 'block';
    }
    if (elements.gateC18Node) {
      elements.gateC18Node.setAttribute('fill', isQuarantined ? '#64748B' : '#FF4560');
    }
    if (elements.zone2StatusText) {
      elements.zone2StatusText.textContent = isQuarantined ? 
        'Status: Threat Quarantined' : 'Status: 1 Threat Under Review';
      elements.zone2StatusText.setAttribute('fill', isQuarantined ? '#10B981' : '#FFA726');
    }
    if (elements.mapSelectedNode) {
      elements.mapSelectedNode.textContent = isQuarantined ? 
        'Gate C-18 Kiosk [QUARANTINED & ISOLATED]' : 'Gate C-18 Self-Service Terminal [CRITICAL THREAT SOURCE]';
    }
    if (elements.mapQuarantineBtn) {
      elements.mapQuarantineBtn.textContent = isQuarantined ? 
        'Release Quarantine' : 'Quarantine Gate C-18 Terminal';
      elements.mapQuarantineBtn.className = isQuarantined ? 
        'btn btn-ghost btn-sm' : 'btn btn-danger btn-sm';
    }
  }

  // ==========================================================================
  // SCENARIO WALKTHROUGH & INCIDENT SIMULATION (Slide 5 Requirement)
  // ==========================================================================
  function triggerViolationScenario() {
    // Show top violation walkthrough banner
    elements.violationAlertBox.classList.remove('hidden');

    // Add critical event to Audit Log if not already present
    const hasLog = state.auditLogs.some(l => l.user.includes('david.kim') && l.result === 'DENIED');
    if (!hasLog) {
      state.auditLogs.unshift({
        timestamp: "03:19:12 UTC",
        user: "david.kim (AV-4402)",
        role: "Ramp Operations Lead",
        table: "passenger_manifest_pnr",
        action: "SELECT * FROM passenger_manifest_pnr",
        location: "192.168.42.88 (Gate C-18 Kiosk)",
        result: "DENIED",
        reason: "Access policy #204 violated: Ramp role prohibited from querying Passenger PII."
      });
    }

    // Reset Gate C-18 map state to threat active
    updateAirportZoneMapQuarantineState(false);

    // Make sure threat is OPEN
    const threat = state.threats.find(t => t.id === 'THREAT-9941');
    if (threat) threat.status = 'OPEN';

    renderOverview();
    renderThreats();
    renderAuditLogs();

    showToast("Incident Injected: Unauthorized off-hours query detected from Gate C-18 Kiosk!", "danger");
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // ==========================================================================
  // EMERGENCY CYBER LOCKDOWN SIMULATION (Original Feature #3)
  // ==========================================================================
  function toggleEmergencyLockdown() {
    state.isLockdownActive = !state.isLockdownActive;

    if (state.isLockdownActive) {
      elements.lockdownAlertBanner.classList.remove('hidden');
      elements.lockdownBtnText.textContent = "Disengage Lockdown";
      elements.lockdownToggleBtn.className = "btn btn-danger btn-sm";

      // Log lockdown in Audit
      logAuditAction('DEFCON_CONTROLLER', 'AIRPORT_DIRECTOR', 'ENGAGED AIRPORT-WIDE DATABASE DEFCON-1 CYBER LOCKDOWN', 'ALLOWED', 'Landside DB quarantine engaged. Read-only failover activated.');

      showToast("DEFCON-1 CYBER LOCKDOWN ACTIVATED: All landside DB access suspended.", "danger");
    } else {
      elements.lockdownAlertBanner.classList.add('hidden');
      elements.lockdownBtnText.textContent = "Emergency Lockdown";
      elements.lockdownToggleBtn.className = "btn btn-danger-soft btn-sm";

      logAuditAction('DEFCON_CONTROLLER', 'AIRPORT_DIRECTOR', 'LIFTED AIRPORT DATABASE CYBER LOCKDOWN', 'ALLOWED', 'Standard airport operations resumed.');

      showToast("Cyber Lockdown Lifted: Standard database operations resumed.", "success");
    }

    renderOverview();
    renderAuditLogs();
  }

  // ==========================================================================
  // RESET DEMO TO INITIAL STATE
  // ==========================================================================
  function resetDemo() {
    state = JSON.parse(JSON.stringify(INITIAL_STATE));
    elements.lockdownAlertBanner.classList.add('hidden');
    elements.violationAlertBox.classList.add('hidden');
    elements.lockdownBtnText.textContent = "Emergency Lockdown";
    elements.lockdownToggleBtn.className = "btn btn-danger-soft btn-sm";
    updateAirportZoneMapQuarantineState(false);

    renderOverview();
    renderIAM();
    renderNetwork();
    renderThreats();
    renderAuditLogs();
    renderPrivilegeScanner();

    showToast("AeroShield prototype reset to initial laboratory state.", "info");
  }

  // ==========================================================================
  // CSV EXPORT UTILITY
  // ==========================================================================
  function exportAuditCsv() {
    const headers = ["Timestamp", "User", "Role", "Database Table", "SQL Action", "IP Endpoint", "Result", "Security Rationale"];
    const rows = state.auditLogs.map(l => [
      `"${l.timestamp}"`,
      `"${l.user}"`,
      `"${l.role}"`,
      `"${l.table}"`,
      `"${l.action}"`,
      `"${l.location}"`,
      `"${l.result}"`,
      `"${l.reason.replace(/"/g, '""')}"`
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `aeroshield_audit_trail_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    showToast("Audit Trail exported to CSV successfully.", "success");
  }

  // ==========================================================================
  // EVENT LISTENERS BINDING
  // ==========================================================================
  function setupEventHandlers() {
    // Top scenario & lockdown buttons
    elements.scenarioBtn.addEventListener('click', triggerViolationScenario);
    elements.lockdownToggleBtn.addEventListener('click', toggleEmergencyLockdown);
    elements.deactivateLockdownBtn.addEventListener('click', toggleEmergencyLockdown);
    elements.resetDemoBtn.addEventListener('click', resetDemo);

    // Violation banner actions
    elements.mitigateViolationBtn.addEventListener('click', () => {
      const threat = state.threats.find(t => t.id === 'THREAT-9941');
      if (threat) executeThreatMitigation(threat);
    });

    elements.viewViolationLogBtn.addEventListener('click', () => {
      switchSection('audit');
      elements.auditSearchInput.value = 'david.kim';
      renderAuditLogs();
    });

    elements.dismissViolationBtn.addEventListener('click', () => {
      elements.violationAlertBox.classList.add('hidden');
    });

    // High Priority Callout (Slide 1)
    elements.btnQuickBlockHighPriority.addEventListener('click', () => {
      const threat = state.threats.find(t => t.id === 'THREAT-9938');
      if (threat) executeThreatMitigation(threat);
    });

    elements.btnQuickInvestigate.addEventListener('click', () => {
      switchSection('threats');
    });

    // Filters
    elements.iamRoleFilter.addEventListener('change', renderIAM);
    elements.iamStatusFilter.addEventListener('change', renderIAM);
    elements.threatSeverityFilter.addEventListener('change', renderThreats);
    elements.threatStatusFilter.addEventListener('change', renderThreats);
    elements.auditResultFilter.addEventListener('change', renderAuditLogs);
    elements.auditTableFilter.addEventListener('change', renderAuditLogs);
    elements.auditSearchInput.addEventListener('input', renderAuditLogs);

    // Global search
    elements.globalSearchInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      if (q) {
        switchSection('audit');
        elements.auditSearchInput.value = q;
        renderAuditLogs();
      }
    });

    // CSV Export
    elements.exportCsvBtn.addEventListener('click', exportAuditCsv);

    // Inject New Threat Simulation button
    elements.triggerThreatSimBtn.addEventListener('click', () => {
      const newThreatId = `THREAT-${Math.floor(1000 + Math.random() * 9000)}`;
      const now = new Date();
      const timeStr = `${String(now.getUTCHours()).padStart(2, '0')}:${String(now.getUTCMinutes()).padStart(2, '0')}:${String(now.getUTCSeconds()).padStart(2, '0')} UTC`;

      state.threats.unshift({
        id: newThreatId,
        severity: "HIGH",
        status: "OPEN",
        timestamp: timeStr,
        title: "SQL Injection Probe on Passenger Check-in Gateway",
        sourceUser: "ANONYMOUS_WEB_CLIENT",
        sourceIp: "172.16.50.119 (Public Landside DMZ)",
        targetTable: "passenger_manifest_pnr",
        sqlQuery: "SELECT * FROM passenger_manifest_pnr WHERE 1=1 --",
        violationType: "SQL Injection (SQLi) WAF Pattern Match",
        mitigated: false
      });

      renderThreats();
      renderOverview();
      showToast(`Injected Threat: ${newThreatId} detected by WAF engine.`, 'warning');
    });

    // Run Least Privilege Scan
    elements.runLeastPrivilegeScanBtn.addEventListener('click', () => {
      renderPrivilegeScanner();
      showToast("Zero-Trust RBAC Privilege scan completed. 1 overprivileged account found.", "info");
    });

    // Map Quarantine Toggle
    elements.mapQuarantineBtn.addEventListener('click', () => {
      const isCurrentlyQuarantined = elements.mapQuarantineBtn.textContent.includes('Release');
      updateAirportZoneMapQuarantineState(!isCurrentlyQuarantined);
      showToast(
        !isCurrentlyQuarantined ? "Gate C-18 Kiosk isolated from network." : "Gate C-18 Kiosk quarantine released.",
        !isCurrentlyQuarantined ? "danger" : "info"
      );
    });

    elements.mapPingBtn.addEventListener('click', () => {
      showToast("ATC Core DB & Telemetry Conduit: Active (0.2ms latency, TLS 1.3 Strict)", "success");
    });

    // Add Staff Modal
    elements.addStaffModalBtn.addEventListener('click', () => {
      openModal(
        "Provision Aviation Database Staff Account",
        `
          <div style="display: flex; flex-direction: column; gap: 0.85rem;">
            <div>
              <label style="font-size: 0.75rem; font-weight: 700; color: var(--text-muted); display: block; margin-bottom: 0.25rem;">Full Name:</label>
              <input type="text" id="newStaffName" class="select-control" style="width: 100%;" placeholder="e.g. Robert Torres">
            </div>
            <div>
              <label style="font-size: 0.75rem; font-weight: 700; color: var(--text-muted); display: block; margin-bottom: 0.25rem;">Aviation Role:</label>
              <select id="newStaffRole" class="select-control" style="width: 100%;">
                <option value="Flight Dispatcher">Flight Dispatcher</option>
                <option value="Air Traffic Controller">Air Traffic Controller</option>
                <option value="Ramp Operations Lead">Ramp Operations Lead</option>
                <option value="Baggage Handling Supervisor">Baggage Handling Supervisor</option>
                <option value="Avionics Database Architect">Avionics Database Architect</option>
                <option value="TSA Liaison Officer">TSA Liaison Officer</option>
              </select>
            </div>
            <div>
              <label style="font-size: 0.75rem; font-weight: 700; color: var(--text-muted); display: block; margin-bottom: 0.25rem;">Security Clearance Tier:</label>
              <select id="newStaffClearance" class="select-control" style="width: 100%;">
                <option value="TIER 1 • AIRSIDE SECRET">TIER 1 • AIRSIDE SECRET</option>
                <option value="TIER 2 • PASSENGER PII CONFIDENTIAL">TIER 2 • PASSENGER PII CONFIDENTIAL</option>
                <option value="TIER 3 • OPERATIONS STANDARD">TIER 3 • OPERATIONS STANDARD</option>
              </select>
            </div>
          </div>
        `,
        "Cancel",
        () => {
          const nameInput = document.getElementById('newStaffName');
          const roleInput = document.getElementById('newStaffRole');
          const clearanceInput = document.getElementById('newStaffClearance');

          if (nameInput && nameInput.value.trim()) {
            const newId = `AV-${Math.floor(1000 + Math.random() * 9000)}`;
            state.users.push({
              id: newId,
              name: nameInput.value.trim(),
              department: "Airport Operations",
              role: roleInput.value,
              clearance: clearanceInput.value,
              permissions: ["flight_schedules (READ)"],
              status: "Active",
              riskScore: 10,
              hasExcessivePrivileges: false
            });

            logAuditAction('IAM_ADMIN', 'SECURITY_OFFICER', `Provisioned new account for ${nameInput.value.trim()} (${newId})`, 'ALLOWED', 'Standard onboarding workflow');

            renderIAM();
            renderOverview();
            closeModal();
            showToast(`Provisioned account for ${nameInput.value.trim()}`, 'success');
          }
        }
      );
    });

    // Help Modal
    elements.quickHelpBtn.addEventListener('click', () => {
      openModal(
        "AeroShield • IT 414 Laboratory Guide & Architecture",
        `
          <h4 style="color: #fff; margin-bottom: 0.5rem;">Laboratory Activity Mission</h4>
          <p style="font-size: 0.85rem; margin-bottom: 1rem;">
            Design an original, easy-to-use aviation database security dashboard that makes airport database security visible and actionable across <strong>Access</strong>, <strong>Network Controls</strong>, <strong>Threat Alerts</strong>, and <strong>Audit History</strong>.
          </p>
          <h4 style="color: #fff; margin-bottom: 0.5rem;">5 Required Sections Implemented:</h4>
          <ol style="margin-left: 1.25rem; font-size: 0.8rem; line-height: 1.6; color: var(--text-secondary);">
            <li><strong>Security Overview:</strong> Active users (128), sessions, blocked queries (17), open alerts (04), interactive hourly access activity chart.</li>
            <li><strong>Identity & Access (IAM):</strong> Fictional aviation employees, roles, RBAC matrix, clearance tiers (Tier 1 Airside, Tier 2 PNR, Tier 3 Ops).</li>
            <li><strong>Network Protection:</strong> Firewalls, authorized airport endpoints (Gate kiosks, ATC towers), VLAN database zones.</li>
            <li><strong>Threat Monitoring:</strong> Real-time suspicious queries, severity filters, automated mitigation buttons.</li>
            <li><strong>Audit Logs:</strong> Who did what, when, where, and allowed/denied result with CSV export.</li>
          </ol>
          <h4 style="color: #fff; margin: 1rem 0 0.5rem;">Original Features (Slide 4 Exceeded):</h4>
          <ul style="margin-left: 1.25rem; font-size: 0.8rem; line-height: 1.6; color: var(--accent-cyan);">
            <li><strong>Zero-Trust Least-Privilege & Excessive Permission Detector:</strong> Identifies unneeded PII access for ground ramp agents and remediates with one click.</li>
            <li><strong>Interactive Airport Restricted Network-Zone Map:</strong> Visual SVG airport layout depicting Airside, Concourse, and Landside DMZ.</li>
            <li><strong>Simulated DEFCON-1 Emergency Cyber Lockdown:</strong> Immediate landside quarantine while preserving vital ATC and flight telemetry.</li>
          </ul>
        `,
        "Close Guide",
        null
      );
    });

    // Modal Close handlers
    elements.modalCloseBtn.onclick = closeModal;
    elements.modalCancelBtn.onclick = closeModal;
    elements.actionModal.onclick = (e) => {
      if (e.target === elements.actionModal) closeModal();
    };
  }

  // ==========================================================================
  // MODAL UTILITY
  // ==========================================================================
  function openModal(title, bodyHtml, cancelText = 'Cancel', confirmCallback = null) {
    elements.modalTitle.textContent = title;
    elements.modalBody.innerHTML = bodyHtml;
    elements.modalCancelBtn.textContent = cancelText;

    if (confirmCallback) {
      elements.modalConfirmBtn.style.display = 'inline-flex';
      elements.modalConfirmBtn.onclick = confirmCallback;
    } else {
      elements.modalConfirmBtn.style.display = 'none';
    }

    elements.actionModal.classList.remove('hidden');
  }

  function closeModal() {
    elements.actionModal.classList.add('hidden');
  }

  // ==========================================================================
  // TOAST NOTIFICATION UTILITY
  // ==========================================================================
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = `<svg class="icon text-teal" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>`;
    } else if (type === 'danger') {
      iconSvg = `<svg class="icon text-danger" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    } else {
      iconSvg = `<svg class="icon text-cyan" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
    }

    toast.innerHTML = `
      ${iconSvg}
      <span>${escapeHtml(message)}</span>
    `;

    elements.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(20px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Start the application
  window.addEventListener('DOMContentLoaded', init);

})();
