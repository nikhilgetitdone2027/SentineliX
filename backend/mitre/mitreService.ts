/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { IMitreService } from './mitreService.interface';
import { MitreTechnique, MitreTactic } from '../../src/types';

export class MitreService implements IMitreService {
  private techniques: MitreTechnique[] = [
    {
      id: 'T1059.001',
      name: 'Command and Scripting Interpreter: PowerShell',
      tactic: 'EXECUTION',
      description: 'Adversaries may use PowerShell commands to perform execution, system info collection, and lateral movement.',
      detectionSignal: 'Process execution parent/child analysis (powershell.exe spawned by explorer.exe or Web servers).'
    },
    {
      id: 'T1003.001',
      name: 'OS Credential Dumping: LSASS Memory',
      tactic: 'CREDENTIAL_ACCESS',
      description: 'Adversaries may attempt to access LSASS process memory to harvest credentials (e.g., using Mimikatz or raw minidump tools).',
      detectionSignal: 'Unauthorized read handles or LSASS dump requests flagged by Endpoints (e.g. rdump.exe).'
    },
    {
      id: 'T1021.002',
      name: 'Remote Services: SMB/Windows Admin Shares',
      tactic: 'LATERAL_MOVEMENT',
      description: 'Adversaries may move laterally by accessing network shares over SMB (ports 139, 445) using valid administrative credentials.',
      detectionSignal: 'AD Kerberos anomalies paired with high-frequency SMB directory reads targeting non-standard system drives.'
    },
    {
      id: 'T1048',
      name: 'Exfiltration Over Alternative Protocol',
      tactic: 'EXFILTRATION',
      description: 'Adversaries may steal sensitive records or database backups using alternative protocols instead of HTTP/HTTPS, such as raw TLS tunnels.',
      detectionSignal: 'Abnormally high entropy and data ratios pointing to external onion routing nodes.'
    },
    {
      id: 'T1071.004',
      name: 'Application Layer Protocol: DNS',
      tactic: 'PERSISTENCE',
      description: 'Adversaries may communicate using DNS queries containing encoded subdomains to command external implants (DNS Tunneling).',
      detectionSignal: 'Extremely high volume of TXT/A queries pointing to newly registered top-level domains.'
    },
    {
      id: 'T1566',
      name: 'Phishing',
      tactic: 'INITIAL_ACCESS',
      description: 'Adversaries may send malicious attachments or links in emails to compromise internal end-user workstations.',
      detectionSignal: 'Browser launching from uncommon attachment extensions or unrecognized mail filters.'
    }
  ];

  public async getAllTechniques(): Promise<MitreTechnique[]> {
    return this.techniques;
  }

  public async getTechniquesByTactic(tactic: MitreTactic): Promise<MitreTechnique[]> {
    return this.techniques.filter(t => t.tactic === tactic);
  }

  public async getTechniqueById(id: string): Promise<MitreTechnique | null> {
    const tech = this.techniques.find(t => t.id === id);
    return tech || null;
  }
}
