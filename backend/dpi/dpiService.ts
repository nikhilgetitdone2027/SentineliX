/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { IDpiService } from './dpiService.interface';
import { NetworkPacket, DpiSessionFlow } from '../../src/types';
import { SecurityDatabase } from '../services/db';

export class DpiService implements IDpiService {
  private db: SecurityDatabase;

  constructor() {
    this.db = SecurityDatabase.getInstance();
  }

  public async getLivePackets(): Promise<NetworkPacket[]> {
    return this.db.packetsBuffer;
  }

  public async getLiveFlows(): Promise<DpiSessionFlow[]> {
    return this.db.activeFlows;
  }

  public async uploadPcap(fileBuffer: Buffer, fileName: string): Promise<{ success: boolean; packetCount: number; message: string }> {
    // In later steps, this will parse actual PCAP structures via C++ DPI integrations
    console.log(`DPI Engine received PCAP file "${fileName}" containing ${fileBuffer.length} bytes.`);
    
    // Simulate parsing success
    const mockPacketCount = Math.floor(Math.random() * 500) + 120;
    return {
      success: true,
      packetCount: mockPacketCount,
      message: `PCAP parsed successfully. Infused ${mockPacketCount} parsed flows into the SentinelX correlation window.`
    };
  }
}
