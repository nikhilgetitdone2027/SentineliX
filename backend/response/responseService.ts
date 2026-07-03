/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { IResponseService } from './responseService.interface';
import { IncidentPlaybookRun, PlaybookActionType, ResponseRecommendation } from '../../src/types';
import { SecurityDatabase } from '../services/db';

export class ResponseService implements IResponseService {
  private db: SecurityDatabase;

  constructor() {
    this.db = SecurityDatabase.getInstance();
  }

  public async getPlaybookRuns(): Promise<IncidentPlaybookRun[]> {
    return this.db.playbookRuns;
  }

  public async getPlaybookRunById(id: string): Promise<IncidentPlaybookRun | null> {
    const run = this.db.playbookRuns.find(r => r.id === id);
    return run || null;
  }

  public async triggerPlaybook(actionType: PlaybookActionType, target: string, incidentId?: string): Promise<IncidentPlaybookRun> {
    const activeIncidentId = incidentId || 'inc-2026-001';
    const runId = `run-${Math.floor(Math.random() * 1000000)}`;
    const now = new Date();
    
    const stepsList = [
      { 
        id: 'step-1', 
        name: `Initializing playbook for ${actionType} targeting ${target}`, 
        actionType, 
        target, 
        status: 'RUNNING' as const, 
        outputLog: 'CONNECTING TO SENTINELX-AGENT-DAEMON...\nCONNECTION SECURED.' 
      },
    ];

    const newRun: IncidentPlaybookRun = {
      id: runId,
      playbookId: `pb-${actionType.toLowerCase()}`,
      name: `Orchestrator: Response ${actionType} on ${target}`,
      incidentId: activeIncidentId,
      triggeredBy: this.db.currentSocUser?.fullName || 'SYSTEM',
      startTime: now.toISOString(),
      status: 'RUNNING',
      steps: stepsList,
      logs: [
        `[${now.toLocaleTimeString()}] Triggered playbook: Response ${actionType} on ${target}`,
        `[${now.toLocaleTimeString()}] Authenticating with Security Token as CISO_ADMIN... [OK]`,
        `[${now.toLocaleTimeString()}] Dispatching Agent payload to subnet gateway...`,
      ]
    };

    this.db.playbookRuns.unshift(newRun);

    // Simulate step processing asynchronously
    setTimeout(() => {
      const activeRun = this.db.playbookRuns.find(r => r.id === runId);
      if (activeRun) {
        activeRun.steps[0].status = 'COMPLETED';
        activeRun.steps[0].outputLog += '\nExecuting local commands...\nSUCCESS.';
        
        const step2 = {
          id: 'step-2',
          name: `Executing ${actionType} operations`,
          actionType,
          target,
          status: 'RUNNING' as const,
          outputLog: `[SHELL CMD] executing defense-orchestrator --action ${actionType} --target ${target}\n`,
        };
        
        activeRun.steps.push(step2);
        activeRun.logs.push(`[${new Date().toLocaleTimeString()}] Execution Payload delivered.`);
        
        // Execute playbooks logic on databases
        if (actionType === 'ISOLATE_ENDPOINT') {
          step2.outputLog += `iptables -A INPUT -s ${target} -j DROP\niptables -A OUTPUT -d ${target} -j DROP\nENDPOINT ISOLATED SUCCESSFULLY.`;
          
          const incident = this.db.incidentsDb.find(i => i.id === activeIncidentId);
          if (incident) {
            incident.status = 'CONTAINED';
            incident.summary += ` [CONTAINED: Host ${target} isolated from network via firewall blocks.]`;
            incident.timeline.push({
              timestamp: new Date().toISOString(),
              type: 'PLAYBOOK',
              source: 'PLAYBOOK_ENGINE',
              description: `Playbook completed. Workstation ${target} completely isolated via network drop.`,
            });
          }
        } else if (actionType === 'BLOCK_IP') {
          step2.outputLog += `route add -host ${target} reject\nIP Address blocked on main subnet gateway.`;
          
          const incident = this.db.incidentsDb.find(i => i.id === activeIncidentId);
          if (incident) {
            incident.status = 'RESOLVED';
            incident.summary += ` [RESOLVED: Malicious external IP ${target} blacklisted on Edge router.]`;
            incident.timeline.push({
              timestamp: new Date().toISOString(),
              type: 'PLAYBOOK',
              source: 'PLAYBOOK_ENGINE',
              description: `Playbook completed. Outbound IP ${target} added to blackhole lists. Threat neutralized.`,
            });
          }
        } else if (actionType === 'DISABLE_USER') {
          step2.outputLog += `ldapmodify -x -D "cn=admin" -w "secret" <<EOF\ndn: uid=${target},ou=users,dc=sentinelx,dc=gov\nchangetype: modify\nreplace: nsAccountLock\nnsAccountLock: true\nEOF\nLDAP USER LOCKED OUT.`;
          
          const incident = this.db.incidentsDb.find(i => i.id === activeIncidentId);
          if (incident) {
            incident.compromisedUser = `${target} (LOCKED)`;
            incident.timeline.push({
              timestamp: new Date().toISOString(),
              type: 'PLAYBOOK',
              source: 'PLAYBOOK_ENGINE',
              description: `Playbook completed. LDAP credentials for user "${target}" locked in Active Directory.`,
            });
          }
        }

        setTimeout(() => {
          const finalRun = this.db.playbookRuns.find(r => r.id === runId);
          if (finalRun) {
            finalRun.steps[1].status = 'COMPLETED';
            finalRun.status = 'COMPLETED';
            finalRun.endTime = new Date().toISOString();
            finalRun.logs.push(`[${new Date().toLocaleTimeString()}] Orchestrator: All tasks completed. Execution SUCCESS.`);
          }
        }, 2000);
      }
    }, 1500);

    return newRun;
  }

  public async getRecommendationHistory(): Promise<ResponseRecommendation[]> {
    return this.db.recommendationsHistory;
  }

  public async dismissRecommendation(id: string): Promise<boolean> {
    const rec = this.db.recommendationsHistory.find(r => r.id === id);
    if (rec) {
      rec.status = 'DISMISSED';
      return true;
    }
    return false;
  }

  public async dispatchRecommendation(id: string): Promise<boolean> {
    const rec = this.db.recommendationsHistory.find(r => r.id === id);
    if (rec) {
      rec.status = 'DISPATCHED';
      
      // Determine playbook action type mapping
      let playbookAction: PlaybookActionType = 'BLOCK_IP';
      let target = '10.0.60.100'; // default target
      
      if (rec.action === 'Isolate endpoint') {
        playbookAction = 'ISOLATE_ENDPOINT';
      } else if (rec.action === 'Block source IP' || rec.action === 'Block outbound traffic') {
        playbookAction = 'BLOCK_IP';
      } else if (rec.action === 'Reset password' || rec.action === 'Disable AD Account') {
        playbookAction = 'DISABLE_USER';
        target = 'svc_sync_finance';
      }

      // If there's an associated incident, retrieve target details
      if (rec.incidentId) {
        const incident = this.db.incidentsDb.find(i => i.id === rec.incidentId);
        if (incident) {
          target = incident.sourceIp || '10.0.60.100';
          if (playbookAction === 'DISABLE_USER' && incident.compromisedUser) {
            target = incident.compromisedUser.split(' ')[0];
          }
        }
      }

      // Execute/trigger actual playbook!
      await this.triggerPlaybook(playbookAction, target, rec.incidentId);
      return true;
    }
    return false;
  }

  public async generateRecommendations(
    incidentId?: string, 
    severity?: string, 
    mitreMapping?: any[]
  ): Promise<ResponseRecommendation[]> {
    let finalSeverity = severity || 'HIGH';
    let finalMappings = mitreMapping || [];
    let incidentTitle = 'Dynamic Asset Correlation alert';
    let targetIncidentId = incidentId || 'inc-2026-001';

    if (incidentId) {
      const incident = this.db.incidentsDb.find(i => i.id === incidentId);
      if (incident) {
        finalSeverity = incident.severity;
        finalMappings = incident.mitreMapping || [];
        incidentTitle = incident.title;
      }
    }

    const recommendations: ResponseRecommendation[] = [];
    const textToAnalyze = (incidentTitle + " " + finalMappings.map(m => m.tactic + " " + m.techniqueName).join(" ")).toLowerCase();

    // Check 1: Large Upload / Exfiltration
    if (textToAnalyze.includes('upload') || textToAnalyze.includes('exfiltration') || textToAnalyze.includes('t1048')) {
      recommendations.push({
        id: `rec-${Math.floor(Math.random() * 1000000)}`,
        incidentId: targetIncidentId,
        incidentTitle,
        priority: finalSeverity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        action: 'Block outbound traffic',
        reason: 'Abnormally large upload rates and exfiltration signatures detected over alternate network channel.',
        estimatedImpact: 'Terminates unauthorized outbound flows from the node, while maintaining core intranet access.',
        timestamp: new Date().toISOString(),
        status: 'PENDING'
      });
    }

    // Check 2: Credential Attack
    if (textToAnalyze.includes('credential') || textToAnalyze.includes('brute') || textToAnalyze.includes('ldap') || textToAnalyze.includes('password') || textToAnalyze.includes('t1003') || textToAnalyze.includes('t1110')) {
      recommendations.push({
        id: `rec-${Math.floor(Math.random() * 1000000)}`,
        incidentId: targetIncidentId,
        incidentTitle,
        priority: finalSeverity === 'CRITICAL' || finalSeverity === 'HIGH' ? 'HIGH' : 'MEDIUM',
        action: 'Reset password',
        reason: 'Compromised Active Directory credentials being used for remote exploitation or lateral credential stuffing.',
        estimatedImpact: 'Locks the corresponding account in LDAP/Active Directory. High impact to user but immediate credential protection.',
        timestamp: new Date().toISOString(),
        status: 'PENDING'
      });
    }

    // Check 3: Port Scan / Network Recon
    if (textToAnalyze.includes('scan') || textToAnalyze.includes('discovery') || textToAnalyze.includes('recon') || textToAnalyze.includes('t1046')) {
      recommendations.push({
        id: `rec-${Math.floor(Math.random() * 1000000)}`,
        incidentId: targetIncidentId,
        incidentTitle,
        priority: 'MEDIUM',
        action: 'Block source IP',
        reason: 'Target host scanning active subnets and listing local open ports (MITRE Discovery T1046).',
        estimatedImpact: 'Blocks source IP on local firewall routers. Low risk of service disruption with high security ROI.',
        timestamp: new Date().toISOString(),
        status: 'PENDING'
      });
    }

    // Check 4: Malware / Malicious Script Execution
    if (textToAnalyze.includes('malware') || textToAnalyze.includes('execution') || textToAnalyze.includes('powershell') || textToAnalyze.includes('t1059') || textToAnalyze.includes('lsass')) {
      recommendations.push({
        id: `rec-${Math.floor(Math.random() * 1000000)}`,
        incidentId: targetIncidentId,
        incidentTitle,
        priority: finalSeverity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        action: 'Isolate endpoint',
        reason: 'Malware infection and unauthorized script interpreters spammed on local device terminals.',
        estimatedImpact: 'Triggers immediate port shutdown or host firewall quarantine. Highly disruptive to work tasks but isolates threat.',
        timestamp: new Date().toISOString(),
        status: 'PENDING'
      });
    }

    // Fallback if none matched
    if (recommendations.length === 0) {
      const fallbackAction = finalSeverity === 'CRITICAL' ? 'Isolate endpoint' : 
                             (finalSeverity === 'HIGH' ? 'Reset password' : 
                             (finalSeverity === 'MEDIUM' ? 'Block source IP' : 'Block source IP'));
      const fallbackPriority = finalSeverity;
      const fallbackReason = `Automated threat mitigation recommended due to ${finalSeverity} severity alert correlation.`;
      const fallbackImpact = `Resolves high risk threat nodes. Impact varies depending on target asset type.`;

      recommendations.push({
        id: `rec-${Math.floor(Math.random() * 1000000)}`,
        incidentId: targetIncidentId,
        incidentTitle,
        priority: fallbackPriority as any,
        action: fallbackAction,
        reason: fallbackReason,
        estimatedImpact: fallbackImpact,
        timestamp: new Date().toISOString(),
        status: 'PENDING'
      });
    }

    // Add generated recommendations into persistent database history
    for (const rec of recommendations) {
      const exists = this.db.recommendationsHistory.some(r => r.incidentId === rec.incidentId && r.action === rec.action && r.status === 'PENDING');
      if (!exists) {
        this.db.recommendationsHistory.unshift(rec);
      }
    }

    return recommendations;
  }
}

