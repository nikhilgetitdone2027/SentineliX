/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { EntityBehaviorProfile } from '../../src/types';

export interface IAiService {
  getBehavioralProfiles(): Promise<EntityBehaviorProfile[]>;
  getProfileById(entityId: string): Promise<EntityBehaviorProfile | null>;
  recalculateAnomalies(): Promise<void>;
}
