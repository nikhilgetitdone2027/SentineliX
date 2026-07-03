/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { IRagService } from './ragService.interface';
import { ThreatIntelligenceDoc } from '../../src/types';
import { SecurityDatabase } from '../services/db';

export class RagService implements IRagService {
  private db: SecurityDatabase;

  constructor() {
    this.db = SecurityDatabase.getInstance();
  }

  public async queryThreatIntelligence(query: string): Promise<ThreatIntelligenceDoc[]> {
    if (!query) {
      return this.db.threatIntelDb.slice(0, 4);
    }

    try {
      // Direct call to FastAPI RAG microservice
      const response = await fetch('http://127.0.0.1:8090/rag/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, k: 4 })
      });

      if (response.ok) {
        const data = await response.json();
        const results = data.results || [];
        // Map any python structures back to our frontend interface structure
        return results.map((doc: any) => ({
          id: doc.id || doc.externalId,
          title: doc.title,
          content: doc.content,
          externalId: doc.externalId,
          sourceType: doc.sourceType,
          publishedDate: doc.publishedDate || new Date().toISOString(),
          url: doc.url || ''
        }));
      }
    } catch (err) {
      console.warn('RagService: FastAPI microservice query failed, utilizing Node.js local DB fallback.', err);
    }

    // Fallback search mechanism
    const tokens = query.toLowerCase().split(/\s+/);
    const hits = this.db.threatIntelDb.filter(doc => {
      return tokens.some((token: string) => 
        doc.title.toLowerCase().includes(token) || 
        doc.content.toLowerCase().includes(token) ||
        doc.externalId.toLowerCase().includes(token)
      );
    });

    return hits.length > 0 ? hits : this.db.threatIntelDb.slice(0, 4);
  }

  public async getAllIntelligenceDocs(): Promise<ThreatIntelligenceDoc[]> {
    return this.db.threatIntelDb;
  }

  public async ingestIntelligenceDoc(doc: Omit<ThreatIntelligenceDoc, 'id' | 'publishedDate'>): Promise<ThreatIntelligenceDoc> {
    const localDoc: ThreatIntelligenceDoc = {
      ...doc,
      id: `intel-${Math.floor(Math.random() * 1000000)}`,
      publishedDate: new Date().toISOString(),
      url: ''
    };
    
    // Core: Ingest into our persistent Express memory structure
    this.db.threatIntelDb.push(localDoc);

    try {
      // Ingest into python FAISS vector database
      const response = await fetch('http://127.0.0.1:8090/rag/index', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: doc.title,
          content: doc.content,
          externalId: doc.externalId,
          sourceType: doc.sourceType
        })
      });

      if (response.ok) {
        const data = await response.json();
        if (data.document) {
          return {
            ...localDoc,
            id: data.document.id
          };
        }
      }
    } catch (err) {
      console.warn('RagService: Failed to upload custom document to Python FAISS index.', err);
    }

    return localDoc;
  }
}
