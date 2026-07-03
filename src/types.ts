/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

// ============================================================================
// Core Network & Packet Types
// ============================================================================

export type NetworkProtocol =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'HTTP'
  | 'HTTPS'
  | 'DNS'
  | 'TLS'
  | 'FTP'
  | 'SMTP'
  | 'SSH'
  | 'UNKNOWN';

export interface NetworkPacket {
  id: string;
  timestamp: string; // ISO String
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: NetworkProtocol;
  length: number;
  payloadHex: string;
  payloadAscii: string;
  flags: {
    syn?: boolean;
    ack?: boolean;
    fin?: boolean;
    rst?: boolean;
    psh?: boolean;
    urg?: boolean;
  };
  sessionId: string;
}

// ============================================================================
// Deep Packet Inspection (DPI) & Session Flow Tracking Types
// ============================================================================

export interface HttpMetadata {
  method: string;
  uri: string;
  hostname: string;
  userAgent: string;
  contentType?: string;
  responseCode?: number;
  contentLength?: number;
}

export interface DnsMetadata {
  query: string;
  queryType: 'A' | 'AAAA' | 'MX' | 'TXT' | 'CNAME' | 'NS' | 'PTR';
  responseAddresses?: string[];
  responseCode?: string;
  txId: number;
}

export interface TlsMetadata {
  sni: string;
  version: string; // TLS 1.2, TLS 1.3
  cipherSuite: string;
  ja3Fingerprint?: string;
}

export interface FtpMetadata {
  command: string;
  argument?: string;
  responseCode?: number;
  responseMessage?: string;
}

export interface SmtpMetadata {
  sender?: string;
  recipient?: string;
  subject?: string;
  command?: string;
}

export interface FlowStatistics {
  packetsPerSecond: number;
  bytesPerSecond: number;
  payloadEntropy: number; // 0.0 - 8.0 randomness
  durationMs: number;
}

export interface DpiSessionFlow {
  sessionId: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: NetworkProtocol;
  flowState: 'NEW' | 'ESTABLISHED' | 'FIN_WAIT' | 'CLOSED' | 'RESET';
  startTime: string;
  lastActiveTime: string;
  totalPackets: number;
  totalBytes: number;
  statistics: FlowStatistics;
  
  // Protocol-Specific Parsed Metadata
  http?: HttpMetadata;
  dns?: DnsMetadata;
  tls?: TlsMetadata;
  ftp?: FtpMetadata;
  smtp?: SmtpMetadata;
}

// ============================================================================
// Behavioral AI Profiles & Anomaly Scoring Types
// ============================================================================

export type EntityType = 'USER' | 'DEVICE' | 'SERVER' | 'DEPARTMENT' | 'APPLICATION' | 'SUBNET';

export interface BehavioralBaseline {
  avgPacketRate: number;
  stdDevPacketRate: number;
  commonProtocols: NetworkProtocol[];
  commonDestinations: string[];
  peakActivityHours: number[]; // 0-23
  averageDataEntropy: number;
  uniqueDestinationPortCount: number;
}

export interface EntityBehaviorProfile {
  entityId: string; // e.g. "192.168.1.50" or "admin_user"
  entityName: string;
  entityType: EntityType;
  department?: string; // e.g., "Engineering", "Finance", "HR"
  baseline: BehavioralBaseline;
  
  // Current 5-minute sliding window metrics
  currentActivity: {
    packetRate: number;
    bytesRate: number;
    activeProtocols: NetworkProtocol[];
    destinationsVisited: string[];
    destinationPortsVisited: number[];
    dataEntropy: number;
    hourOfActivity: number;
  };

  // ML Scoring Models Outputs
  anomalyScores: {
    isolationForest: number; // 0.0 - 1.0
    autoencoder: number;      // 0.0 - 1.0 (reconstruction error score)
    lof: number;              // 0.0 - 1.0 (Local Outlier Factor score)
    ensembleScore: number;    // 0.0 - 1.0
  };
  
  riskScore: number;       // 0 - 100
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  explainability: string[]; // Human-readable features triggering the risk (e.g., "Novel protocol SMTP detected", "Data entropy spike")
}

// ============================================================================
// Correlation Engine, Telemetry Logs & Incident Alerts
// ============================================================================

export type LogSource =
  | 'WINDOWS_EVENT_LOG'
  | 'LINUX_SYS_LOG'
  | 'FIREWALL'
  | 'NETWORK_FLOW'
  | 'DNS_QUERY'
  | 'AUTH_SERVER'
  | 'PROCESS_EXECUTION'
  | 'ENDPOINT_TELEMETRY';

export interface UnifiedTelemetryLog {
  id: string;
  timestamp: string;
  source: LogSource;
  host: string;
  userId?: string;
  severity: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  message: string;
  
  // Context-specific details
  details: {
    processName?: string;
    processPath?: string;
    parentProcessName?: string;
    commandLine?: string;
    srcIp?: string;
    dstIp?: string;
    srcPort?: number;
    dstPort?: number;
    domainQueried?: string;
    dnsRecordType?: string;
    authStatus?: 'SUCCESS' | 'FAILURE' | 'LOCKOUT';
    fileChanged?: string;
    registryKey?: string;
  };
}

export interface AttackPrediction {
  current_stage: string;
  predicted_next_stage: string;
  confidence: number;
  reasoning: string[];
}

export interface SecurityIncident {
  id: string;
  title: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  summary: string;
  sourceIp?: string;
  targetIp?: string;
  compromisedUser?: string;
  riskScore: number;
  prediction?: AttackPrediction;
  businessImpact?: string;
  businessImpactLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  
  // Associated data
  alerts: string[]; // References to anomaly alerts
  telemetryLogIds: string[]; // References to correlated raw logs
  mitreMapping: {
    tactic: string;
    techniqueId: string;
    techniqueName: string;
  }[];
  
  timeline: {
    timestamp: string;
    type: 'ALERT' | 'LOG' | 'PLAYBOOK' | 'SOC_COMMENT';
    source: string;
    description: string;
  }[];
}

// ============================================================================
// MITRE ATT&CK Matrix Mapping Types
// ============================================================================

export type MitreTactic =
  | 'INITIAL_ACCESS'
  | 'EXECUTION'
  | 'PERSISTENCE'
  | 'PRIVILEGE_ESCALATION'
  | 'CREDENTIAL_ACCESS'
  | 'DISCOVERY'
  | 'LATERAL_MOVEMENT'
  | 'COLLECTION'
  | 'EXFILTRATION'
  | 'IMPACT';

export interface MitreTechnique {
  id: string; // e.g., "T1190"
  name: string; // e.g., "Exploit Public-Facing Application"
  tactic: MitreTactic;
  description: string;
  detectionSignal: string; // Rule description
}

// ============================================================================
// RAG & Threat Intelligence Types
// ============================================================================

export interface ThreatIntelligenceDoc {
  id: string;
  sourceType: 'MITRE_ATTACK' | 'CERT_IN_ADVISORY' | 'CVE' | 'SECURITY_PLAYBOOK' | 'INTERNAL_DOC';
  externalId: string; // e.g., "CVE-2024-3094", "CERT-In-2026-0043"
  title: string;
  content: string;
  url?: string;
  publishedDate: string;
  vectorId?: string;
}

// ============================================================================
// Response Playbooks & Orchestrator Types
// ============================================================================

export type PlaybookActionType =
  | 'BLOCK_IP'
  | 'DISABLE_USER'
  | 'KILL_PROCESS'
  | 'ISOLATE_ENDPOINT'
  | 'SNAPSHOT_VM'
  | 'CREATE_TICKET'
  | 'NOTIFY_SOC';

export interface PlaybookStep {
  id: string;
  name: string;
  actionType: PlaybookActionType;
  target: string; // IP, username, hostname, processName, etc.
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  outputLog?: string;
}

export interface IncidentPlaybookRun {
  id: string;
  playbookId: string;
  name: string;
  incidentId: string;
  triggeredBy: string; // "AUTO" or "user_id"
  startTime: string;
  endTime?: string;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED';
  steps: PlaybookStep[];
  logs: string[]; // Step terminal-like log entries
}

// ============================================================================
// Authentication & RBAC Types
// ============================================================================

export type UserRole = 'SOC_OPERATOR' | 'SECURITY_ANALYST' | 'INCIDENT_RESPONDER' | 'ADMIN';

export interface SocUser {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  fullName: string;
  department: string;
  lastLogin: string;
}

// ============================================================================
// AI SOC Copilot Chat Types
// ============================================================================

export interface CopilotMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  contextIncidentId?: string;
  ragSources?: ThreatIntelligenceDoc[];
}

// ============================================================================
// Response Recommendation Engine Types
// ============================================================================

export interface ResponseRecommendation {
  id: string;
  incidentId: string;
  incidentTitle: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  action: string;
  reason: string;
  estimatedImpact: string;
  timestamp: string;
  status: 'PENDING' | 'DISPATCHED' | 'DISMISSED';
}

