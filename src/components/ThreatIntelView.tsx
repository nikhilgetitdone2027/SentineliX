/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Search, 
  BookOpen, 
  ExternalLink, 
  ShieldCheck, 
  Clock, 
  FileText,
  AlertOctagon,
  HelpCircle,
  Plus,
  X,
  Cpu,
  CheckCircle,
  Loader2
} from 'lucide-react';
import { ThreatIntelligenceDoc } from '../types.js';

export default function ThreatIntelView() {
  const [query, setQuery] = useState('');
  const [docs, setDocs] = useState<ThreatIntelligenceDoc[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedDocId, setSelectedDocId] = useState<string | null>(null);
  
  // Ingestion form state
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newExternalId, setNewExternalId] = useState('');
  const [newSourceType, setNewSourceType] = useState<'MITRE_ATTACK' | 'CERT_IN_ADVISORY' | 'CVE' | 'SECURITY_PLAYBOOK'>('CVE');
  const [newContent, setNewContent] = useState('');
  const [indexing, setIndexing] = useState(false);
  const [indexSuccess, setIndexSuccess] = useState(false);
  
  // Engine status state
  const [engineStatus, setEngineStatus] = useState<any>(null);

  // Initial load
  useEffect(() => {
    handleSearch('');
    fetchEngineStatus();
  }, []);

  const fetchEngineStatus = async () => {
    try {
      const response = await fetch('/api/rag/status');
      if (response.ok) {
        const data = await response.json();
        setEngineStatus(data);
      }
    } catch (err) {
      console.error('Failed to fetch RAG engine status:', err);
    }
  };

  const handleSearch = async (searchStr: string) => {
    setLoading(true);
    try {
      const response = await fetch('/api/threat-intel/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: searchStr }),
      });
      const data = await response.json();
      setDocs(data.results || []);
      if (data.results && data.results.length > 0) {
        setSelectedDocId(data.results[0].id);
      } else {
        setSelectedDocId(null);
      }
    } catch (err) {
      console.error('Failed to query threat intelligence RAG databases:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle || !newExternalId || !newContent) {
      alert('Please fill in all required fields.');
      return;
    }

    setIndexing(true);
    setIndexSuccess(false);
    try {
      const response = await fetch('/api/threat-intel/index', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newTitle,
          content: newContent,
          externalId: newExternalId,
          sourceType: newSourceType
        })
      });

      if (response.ok) {
        setIndexSuccess(true);
        setNewTitle('');
        setNewExternalId('');
        setNewContent('');
        // Refresh RAG Status and query lists
        setTimeout(() => {
          setIsAddOpen(false);
          setIndexSuccess(false);
          handleSearch('');
          fetchEngineStatus();
        }, 1500);
      } else {
        const errText = await response.text();
        alert(`Failed to index document: ${errText}`);
      }
    } catch (err: any) {
      alert(`Error during document ingestion: ${err?.message || err}`);
    } finally {
      setIndexing(false);
    }
  };

  const getSourceBadgeColor = (source: string) => {
    switch (source) {
      case 'CVE': return 'bg-red-950 text-red-400 border-red-900/40';
      case 'CERT_IN_ADVISORY': return 'bg-amber-950/80 text-amber-400 border-amber-900/40';
      case 'MITRE_ATTACK': return 'bg-indigo-950 text-indigo-400 border-indigo-900/40';
      case 'SECURITY_PLAYBOOK': return 'bg-emerald-950 text-emerald-400 border-emerald-900/40';
      default: return 'bg-gray-900 text-gray-400 border-gray-800';
    }
  };

  const selectedDoc = docs.find(d => d.id === selectedDocId);

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col md:flex-row h-full">
      
      {/* Left List Pane */}
      <div className="w-full md:w-2/5 border-r border-[#131d38] flex flex-col h-full bg-[#030712]">
        
        {/* Header and Input Search */}
        <div className="p-6 border-b border-[#131d38] bg-[#070c1b]/60 flex-shrink-0">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans flex items-center gap-2">
              <BookOpen className="h-4.5 w-4.5 text-red-500" />
              Threat Intelligence (RAG)
            </h3>
            <button
              onClick={() => setIsAddOpen(!isAddOpen)}
              className="flex items-center gap-1 px-2.5 py-1 bg-[#101b36] hover:bg-[#18284e] border border-[#1b2f5c] text-[10px] text-red-400 font-mono font-bold rounded transition-colors"
            >
              {isAddOpen ? <X className="h-3 w-3" /> : <Plus className="h-3 w-3" />}
              <span>{isAddOpen ? 'CANCEL' : 'INDEX DOC'}</span>
            </button>
          </div>
          
          {!isAddOpen ? (
            <form 
              onSubmit={(e) => {
                e.preventDefault();
                handleSearch(query);
              }}
              className="relative"
            >
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search CVEs, CERT advisories, playbooks semantically..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1b274c] rounded-lg pl-9 pr-20 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-red-500 transition-colors"
              />
              <button 
                type="submit"
                className="absolute right-1.5 top-1.5 px-3 py-1 bg-red-600 hover:bg-red-700 text-white font-mono text-[9px] font-bold rounded transition-all"
              >
                QUERY RAG
              </button>
            </form>
          ) : (
            <div className="text-[10px] font-mono text-gray-400">
              Ingest verified security knowledge into the FAISS vector database.
            </div>
          )}
        </div>

        {/* Ingestion Panel / Slide-down Form */}
        {isAddOpen && (
          <form onSubmit={handleIngest} className="p-6 border-b border-[#1b2d5a] bg-[#091124] flex-shrink-0 space-y-4 max-h-[350px] overflow-y-auto">
            <div className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="h-4 w-4 text-red-400" />
              <span>Ingest Document to FAISS Store</span>
            </div>

            {indexSuccess ? (
              <div className="p-4 bg-emerald-950/40 border border-emerald-900 rounded-lg text-center space-y-2">
                <CheckCircle className="h-6 w-6 text-emerald-400 mx-auto" />
                <p className="text-xs font-mono text-emerald-300">Document successfully indexed!</p>
                <p className="text-[9px] text-gray-400">Generating sentence embeddings and populating FAISS index...</p>
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="block text-[9px] font-mono text-gray-400 uppercase mb-1">Document Title *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. CVE-2024-4210: Critical RCE in Cisco Webex"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    className="w-full bg-[#050913] border border-[#1b274c] rounded p-2 text-xs text-white focus:outline-none focus:border-red-500"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[9px] font-mono text-gray-400 uppercase mb-1">External ID *</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. CVE-2024-4210 / T1059.001"
                      value={newExternalId}
                      onChange={(e) => setNewExternalId(e.target.value)}
                      className="w-full bg-[#050913] border border-[#1b274c] rounded p-2 text-xs text-white focus:outline-none focus:border-red-500"
                    />
                  </div>
                  <div>
                    <label className="block text-[9px] font-mono text-gray-400 uppercase mb-1">Source Type</label>
                    <select
                      value={newSourceType}
                      onChange={(e) => setNewSourceType(e.target.value as any)}
                      className="w-full bg-[#050913] border border-[#1b274c] rounded p-2 text-xs text-white focus:outline-none focus:border-red-500 font-sans"
                    >
                      <option value="CVE">CVE Database</option>
                      <option value="MITRE_ATTACK">MITRE ATT&CK</option>
                      <option value="CERT_IN_ADVISORY">CERT Advisory</option>
                      <option value="SECURITY_PLAYBOOK">Security Playbook</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-[9px] font-mono text-gray-400 uppercase mb-1">Detailed Content (Knowledge base item) *</label>
                  <textarea
                    required
                    rows={3}
                    placeholder="Provide full technical description, payload details, mitigation procedures, and registry/system signals..."
                    value={newContent}
                    onChange={(e) => setNewContent(e.target.value)}
                    className="w-full bg-[#050913] border border-[#1b274c] rounded p-2 text-xs text-white focus:outline-none focus:border-red-500 font-sans"
                  />
                </div>

                <button
                  type="submit"
                  disabled={indexing}
                  className="w-full bg-red-600 hover:bg-red-700 text-white font-mono text-xs font-bold py-2 px-4 rounded transition-colors flex items-center justify-center gap-2"
                >
                  {indexing ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span>EMBEDDING & INDEXING...</span>
                    </>
                  ) : (
                    <span>INDEX INTO VECTOR STORE</span>
                  )}
                </button>
              </div>
            )}
          </form>
        )}

        {/* Documents Scroll list */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#101931]">
          {docs.map((doc) => {
            const isSelected = selectedDocId === doc.id;
            return (
              <div 
                key={doc.id}
                onClick={() => setSelectedDocId(doc.id)}
                className={`p-5 cursor-pointer transition-all ${
                  isSelected ? 'bg-[#0f1936] border-l-4 border-red-500' : 'hover:bg-[#070b16]'
                }`}
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="font-mono text-[10px] font-bold text-gray-500">{doc.externalId}</span>
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-bold border uppercase font-mono ${getSourceBadgeColor(doc.sourceType)}`}>
                    {doc.sourceType.replace('_', ' ')}
                  </span>
                </div>
                <h4 className="text-xs font-bold text-white font-sans leading-snug">{doc.title}</h4>
              </div>
            );
          })}

          {loading && (
            <div className="p-8 text-center text-xs font-mono text-gray-500 flex flex-col items-center gap-2">
              <Loader2 className="h-5 w-5 text-red-500 animate-spin" />
              <span>Querying distributed vector store models...</span>
            </div>
          )}

          {!loading && docs.length === 0 && (
            <div className="p-8 text-center text-xs text-gray-500 font-sans">
              No matching intelligence files found. Try searching for "LDAP", "AD", "xz", or "Mitre".
            </div>
          )}
        </div>

        {/* Engine Status Bar */}
        {engineStatus && (
          <div className="p-4 border-t border-[#131d38] bg-[#060c19] text-[9px] font-mono text-gray-500 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className={`h-1.5 w-1.5 rounded-full ${engineStatus.is_ready ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500 animate-bounce'}`} />
              <span>MODEL: {engineStatus.model_name || 'N/A'}</span>
            </div>
            <div>
              <span>INDEXED: <strong className="text-gray-300">{engineStatus.total_documents_indexed}</strong> DOCS</span>
            </div>
          </div>
        )}
      </div>

      {/* Right Content Pane */}
      <div className="w-full md:w-3/5 flex flex-col h-full bg-[#040918] overflow-y-auto">
        {selectedDoc ? (
          <div className="p-8">
            <div className="border-b border-[#131d38] pb-6 mb-6">
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[8px] font-bold bg-[#131f3f] text-red-400 border border-red-800 font-mono uppercase mb-2">
                VERIFIED SECURITY KNOWLEDGE SOURCE
              </span>
              <h3 className="text-base font-bold text-white font-sans">{selectedDoc.title}</h3>
              <p className="text-xs text-gray-400 font-mono mt-1">SOURCE ID: {selectedDoc.externalId} | Published: {new Date(selectedDoc.publishedDate).toLocaleDateString()}</p>
            </div>

            {/* Document body content */}
            <div className="bg-[#050813] border border-[#141f3d] rounded-xl p-6 mb-6 leading-relaxed text-xs text-gray-300 font-sans font-medium">
              <div className="flex items-center space-x-2.5 text-[10px] uppercase font-mono font-bold text-red-400 border-b border-[#141f3d] pb-3 mb-4">
                <FileText className="h-4.5 w-4.5" />
                <span>Forensic Advisory content</span>
              </div>
              <p className="whitespace-pre-line leading-relaxed">{selectedDoc.content}</p>
            </div>

            {/* External Links */}
            {selectedDoc.url && (
              <div className="bg-[#080d1e] border border-blue-900/30 p-4 rounded-lg flex items-center justify-between text-xs font-sans">
                <div className="flex items-center space-x-3 text-blue-400">
                  <ShieldCheck className="h-5 w-5" />
                  <span>Verified external reference database available.</span>
                </div>
                <a 
                  href={selectedDoc.url} 
                  target="_blank" 
                  rel="noreferrer" 
                  className="flex items-center space-x-1.5 text-red-400 font-bold font-mono hover:text-red-300"
                >
                  <span>BROWSE REFERENCE</span>
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>
            )}

          </div>
        ) : (
          <div className="m-auto text-gray-500 font-sans p-8 text-center flex flex-col items-center justify-center gap-3">
            <HelpCircle className="h-8 w-8 text-indigo-500 opacity-60 animate-bounce" />
            <p className="text-xs max-w-xs leading-relaxed">Search and select an active Threat Advisory document to view mitigation playbooks and CISO guidelines.</p>
          </div>
        )}
      </div>

    </div>
  );
}
