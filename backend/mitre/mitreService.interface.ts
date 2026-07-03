/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { MitreTechnique, MitreTactic } from '../../src/types';

export interface IMitreService {
  getAllTechniques(): Promise<MitreTechnique[]>;
  getTechniquesByTactic(tactic: MitreTactic): Promise<MitreTechnique[]>;
  getTechniqueById(id: string): Promise<MitreTechnique | null>;
}
