/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ThreatIntelligenceDoc } from '../../src/types';

export interface IRagService {
  queryThreatIntelligence(query: string): Promise<ThreatIntelligenceDoc[]>;
  getAllIntelligenceDocs(): Promise<ThreatIntelligenceDoc[]>;
  ingestIntelligenceDoc(doc: Omit<ThreatIntelligenceDoc, 'id' | 'publishedDate'>): Promise<ThreatIntelligenceDoc>;
}
