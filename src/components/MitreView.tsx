/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  Grid, 
  ShieldAlert, 
  Terminal, 
  User, 
  ExternalLink,
  Cpu,
  Info
} from 'lucide-react';
import { SecurityIncident, MitreTactic } from '../types.js';

interface MitreViewProps {
  incidents: SecurityIncident[];
}

interface TechniqueCell {
  id: string;
  name: string;
  tactic: MitreTactic;
  description: string;
  mitreUrl: string;
}

export default function MitreView({ incidents }: MitreViewProps) {
  const [selectedTech, setSelectedTech] = useState<TechniqueCell | null>(null);

  // Static definition of standard enterprise MITRE techniques
  const mitreMatrix: Record<MitreTactic, TechniqueCell[]> = {
    INITIAL_ACCESS: [
      { id: 'T1190', name: 'Exploit Public App', tactic: 'INITIAL_ACCESS', description: 'Adversaries may exploit a vulnerability in an Internet-facing computer or system to gain unauthorized access.', mitreUrl: 'https://attack.mitre.org/techniques/T1190/' },
      { id: 'T1566', name: 'Phishing Campaigns', tactic: 'INITIAL_ACCESS', description: 'Adversaries may send malicious attachments or links to compromise user credentials or execute payloads.', mitreUrl: 'https://attack.mitre.org/techniques/T1566/' }
    ],
    EXECUTION: [
      { id: 'T1059.001', name: 'PowerShell Interpreter', tactic: 'EXECUTION', description: 'Adversaries may use PowerShell commands to execute malicious scripts, bypass restrictions, and run files.', mitreUrl: 'https://attack.mitre.org/techniques/T1059/001/' },
      { id: 'T1021.004', name: 'SSH Remote Command', tactic: 'EXECUTION', description: 'Adversaries may establish SSH sessions to execute commands and scripts remotely on victim machines.', mitreUrl: 'https://attack.mitre.org/techniques/T1021/004/' }
    ],
    PERSISTENCE: [
      { id: 'T1543', name: 'Create System Service', tactic: 'PERSISTENCE', description: 'Adversaries may create or modify system services to execute malicious binaries on boot.', mitreUrl: 'https://attack.mitre.org/techniques/T1543/' },
      { id: 'T1071.004', name: 'DNS C2 Beaconinging', tactic: 'PERSISTENCE', description: 'Adversaries may establish persistence using DNS protocol queries carrying base64 commands.', mitreUrl: 'https://attack.mitre.org/techniques/T1071/004/' }
    ],
    PRIVILEGE_ESCALATION: [
      { id: 'T1548', name: 'Bypass UAC Protections', tactic: 'PRIVILEGE_ESCALATION', description: 'Adversaries may bypass User Account Control permissions to execute high-privilege binaries.', mitreUrl: 'https://attack.mitre.org/techniques/T1548/' },
      { id: 'T1055', name: 'Process Injection', tactic: 'PRIVILEGE_ESCALATION', description: 'Adversaries may inject malicious payloads into active legitimate processes to escalate privilege states.', mitreUrl: 'https://attack.mitre.org/techniques/T1055/' }
    ],
    CREDENTIAL_ACCESS: [
      { id: 'T1003.001', name: 'LSASS Memory Dumping', tactic: 'CREDENTIAL_ACCESS', description: 'Adversaries may dump the memory of lsass.exe to extract clear-text Kerberos or NTLM tokens.', mitreUrl: 'https://attack.mitre.org/techniques/T1003/001/' },
      { id: 'T1110', name: 'LDAP Brute Force', tactic: 'CREDENTIAL_ACCESS', description: 'Adversaries may execute dictionary attacks on authentication directories to crack admin accounts.', mitreUrl: 'https://attack.mitre.org/techniques/T1110/' }
    ],
    DISCOVERY: [
      { id: 'T1046', name: 'Network Port Scanning', tactic: 'DISCOVERY', description: 'Adversaries may scan network ports to map active services, vulnerable versions, and subnets.', mitreUrl: 'https://attack.mitre.org/techniques/T1046/' },
      { id: 'T1087', name: 'Account Discovery', tactic: 'DISCOVERY', description: 'Adversaries may query Active Directory groups or local systems to map administrative accounts.', mitreUrl: 'https://attack.mitre.org/techniques/T1087/' }
    ],
    LATERAL_MOVEMENT: [
      { id: 'T1021.002', name: 'SMB / Admin Shares', tactic: 'LATERAL_MOVEMENT', description: 'Adversaries may copy files and remotely execute commands using administrative disk shares.', mitreUrl: 'https://attack.mitre.org/techniques/T1021/002/' },
      { id: 'T1072', name: 'Software Deployment', tactic: 'LATERAL_MOVEMENT', description: 'Adversaries may leverage third-party update tooling or admin shells to distribute files laterally.', mitreUrl: 'https://attack.mitre.org/techniques/T1072/' }
    ],
    COLLECTION: [
      { id: 'T1114', name: 'Email Store Access', tactic: 'COLLECTION', description: 'Adversaries may target user mailboxes or Exchange caches to collect sensitive company files.', mitreUrl: 'https://attack.mitre.org/techniques/T1114/' },
      { id: 'T1560', name: 'Archive DB Backups', tactic: 'COLLECTION', description: 'Adversaries may compress collected database back-ups to facilitate high-volume exfiltration.', mitreUrl: 'https://attack.mitre.org/techniques/T1560/' }
    ],
    EXFILTRATION: [
      { id: 'T1048', name: 'Exfiltration Over TLS', tactic: 'EXFILTRATION', description: 'Adversaries may leverage alternative high-entropy TLS tunnels to bypass standard proxy filters.', mitreUrl: 'https://attack.mitre.org/techniques/T1048/' },
      { id: 'T1567', name: 'Cloud Storage Leak', tactic: 'EXFILTRATION', description: 'Adversaries may leak corporate data over legitimate APIs of cloud providers (Mega, Drive).', mitreUrl: 'https://attack.mitre.org/techniques/T1567/' }
    ],
    IMPACT: [
      { id: 'T1485', name: 'Data Destruction', tactic: 'IMPACT', description: 'Adversaries may delete system files, databases, or AD catalogs to disrupt corporate capabilities.', mitreUrl: 'https://attack.mitre.org/techniques/T1485/' },
      { id: 'T1489', name: 'Service Stop command', tactic: 'IMPACT', description: 'Adversaries may stop anti-virus daemons or logging services to obfuscate active attacks.', mitreUrl: 'https://attack.mitre.org/techniques/T1489/' }
    ]
  };

  // Helper to identify if a technique is actively tagged inside open/investigating cases
  const getActiveIncidentForTechnique = (techId: string) => {
    return incidents.find(inc => 
      inc.status !== 'RESOLVED' && 
      inc.mitreMapping.some(m => m.techniqueId === techId)
    );
  };

  const getTacticHeaderLabel = (tactic: MitreTactic) => {
    return tactic.replace('_', ' ');
  };

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col h-full p-8 text-gray-200">
      
      {/* Header */}
      <div className="border-b border-[#111930] pb-6 mb-8">
        <h2 className="text-xl font-bold text-white font-sans flex items-center gap-2">
          <Grid className="h-5.5 w-5.5 text-red-500" />
          MITRE ATT&CK MATRIX MAPPER
        </h2>
        <p className="text-xs text-gray-400 mt-1">Unified matrix mapping active network packet inspections, processes, and firewall anomalies directly to specific adversarial techniques.</p>
      </div>

      {/* Grid Canvas */}
      <div className="flex-1 overflow-x-auto overflow-y-auto mb-6 bg-[#090f20]/60 border border-[#172343] rounded-xl p-6 shadow-xl flex gap-4 min-w-[1200px]">
        
        {Object.entries(mitreMatrix).map(([tactic, techniques]) => {
          return (
            <div key={tactic} className="flex-1 flex flex-col space-y-4">
              
              {/* Column Header */}
              <div className="bg-[#0c1223] border border-[#1b274c] px-3 py-2.5 rounded-lg text-center font-bold text-[9px] font-sans tracking-wider uppercase text-indigo-400 min-h-[50px] flex items-center justify-center">
                {getTacticHeaderLabel(tactic as MitreTactic)}
              </div>

              {/* Technique cells list */}
              <div className="flex flex-col space-y-2">
                {techniques.map((tech) => {
                  const linkedInc = getActiveIncidentForTechnique(tech.id);
                  const isCritical = linkedInc?.severity === 'CRITICAL';
                  const isHigh = linkedInc?.severity === 'HIGH';

                  let bgClass = 'bg-[#050813] border-[#16213d] hover:bg-[#0c1328] text-gray-400';
                  if (linkedInc) {
                    bgClass = isCritical 
                      ? 'bg-red-950/40 border-red-800 text-red-400 font-bold animate-pulse' 
                      : 'bg-amber-950/40 border-amber-800 text-amber-400 font-bold animate-pulse';
                  }

                  return (
                    <div
                      key={tech.id}
                      onClick={() => setSelectedTech(tech)}
                      className={`p-3.5 border rounded-lg cursor-pointer transition-all flex flex-col justify-between text-left h-[90px] select-none ${bgClass}`}
                    >
                      <div>
                        <span className="font-mono text-[8px] opacity-70 block mb-1">{tech.id}</span>
                        <h4 className="text-[10px] leading-snug font-sans truncate">{tech.name}</h4>
                      </div>
                      
                      {linkedInc && (
                        <div className="flex items-center space-x-1.5 mt-2">
                          <span className="flex h-1.5 w-1.5 relative">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-red-500"></span>
                          </span>
                          <span className="text-[8px] font-mono font-bold uppercase text-red-500">ACTIVE SIGNAL</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

            </div>
          );
        })}

      </div>

      {/* Bottom Inspector Drawer */}
      {selectedTech && (
        <div className="bg-[#050914] border border-[#1c2a4f] rounded-xl p-6 shadow-2xl relative font-sans text-xs">
          <button 
            onClick={() => setSelectedTech(null)}
            className="absolute right-4 top-4 text-gray-500 hover:text-white"
          >
            ✕
          </button>

          <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-[#131d38] pb-4 mb-4 gap-2">
            <div>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-bold bg-[#131f3f] text-indigo-400 border border-indigo-800 font-mono uppercase mb-2">
                MITRE ATT&CK TECHNIQUE: {selectedTech.id}
              </span>
              <h3 className="text-base font-bold text-white font-sans flex items-center gap-2">
                {selectedTech.name}
                <a 
                  href={selectedTech.mitreUrl} 
                  target="_blank" 
                  rel="noreferrer" 
                  className="text-gray-500 hover:text-white"
                  title="View Official MITRE ATT&CK Wiki"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                </a>
              </h3>
            </div>
            
            {/* Show status if flagged */}
            {getActiveIncidentForTechnique(selectedTech.id) ? (
              <span className="px-2.5 py-1 text-[10px] font-bold bg-red-950 border border-red-800 text-red-400 font-mono rounded animate-pulse">
                🔴 SIGNAL THREAT IN PROGRESS
              </span>
            ) : (
              <span className="px-2.5 py-1 text-[10px] font-bold bg-gray-900 border border-gray-700 text-gray-500 font-mono rounded">
                🟢 SIGNAL INACTIVE
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-gray-400 font-sans leading-relaxed">
            <div className="md:col-span-2">
              <h4 className="text-white font-bold mb-1">Technique Description</h4>
              <p className="font-medium">{selectedTech.description}</p>
            </div>

            {/* Check active threat mapping */}
            <div className="bg-[#0a0f1e] border border-[#131d38] p-4 rounded-lg">
              <h4 className="text-white font-bold mb-2 flex items-center gap-1">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                Threat Diagnostics
              </h4>
              {getActiveIncidentForTechnique(selectedTech.id) ? (
                <div className="space-y-2">
                  <p className="text-gray-400 text-[10px]">CORRELATED INCIDENT:</p>
                  <p className="text-white font-bold text-xs">{getActiveIncidentForTechnique(selectedTech.id)?.title}</p>
                  <p className="text-[10px] font-mono text-gray-500 mt-2">COMPROMISED HOST: <span className="text-red-400 font-bold">{getActiveIncidentForTechnique(selectedTech.id)?.sourceIp}</span></p>
                </div>
              ) : (
                <p className="text-gray-500 italic">No packet anomalous footprints currently correlated to this MITRE technique.</p>
              )}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
