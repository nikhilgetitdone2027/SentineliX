/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { IAiService } from './aiService.interface';
import { EntityBehaviorProfile } from '../../src/types';
import { SecurityDatabase } from '../services/db';

export class AiService implements IAiService {
  private db: SecurityDatabase;

  constructor() {
    this.db = SecurityDatabase.getInstance();
  }

  public async getBehavioralProfiles(): Promise<EntityBehaviorProfile[]> {
    return this.db.entityProfiles;
  }

  public async getProfileById(entityId: string): Promise<EntityBehaviorProfile | null> {
    const profile = this.db.entityProfiles.find(p => p.entityId === entityId);
    return profile || null;
  }

  public async recalculateAnomalies(): Promise<void> {
    console.log('AI Behavioral Engine recalculating anomaly isolation scores...');
    // This will host actual neural networks or outlier model inference in later steps
  }
}
