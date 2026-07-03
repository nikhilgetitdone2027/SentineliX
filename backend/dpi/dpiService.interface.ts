/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { NetworkPacket, DpiSessionFlow } from '../../src/types';

export interface IDpiService {
  getLivePackets(): Promise<NetworkPacket[]>;
  getLiveFlows(): Promise<DpiSessionFlow[]>;
  uploadPcap(fileBuffer: Buffer, fileName: string): Promise<{ success: boolean; packetCount: number; message: string }>;
}
