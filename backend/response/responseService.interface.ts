/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { IncidentPlaybookRun, PlaybookActionType, ResponseRecommendation } from '../../src/types';

export interface IResponseService {
  getPlaybookRuns(): Promise<IncidentPlaybookRun[]>;
  triggerPlaybook(actionType: PlaybookActionType, target: string, incidentId?: string): Promise<IncidentPlaybookRun>;
  getPlaybookRunById(id: string): Promise<IncidentPlaybookRun | null>;
  getRecommendationHistory(): Promise<ResponseRecommendation[]>;
  generateRecommendations(incidentId?: string, severity?: string, mitreMapping?: any[]): Promise<ResponseRecommendation[]>;
  dismissRecommendation(id: string): Promise<boolean>;
  dispatchRecommendation(id: string): Promise<boolean>;
}
