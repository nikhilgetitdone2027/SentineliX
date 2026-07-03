/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import { 
  Sparkles, 
  Send, 
  Bot, 
  User, 
  AlertTriangle, 
  ShieldCheck, 
  Search, 
  Clock,
  Terminal,
  Info,
  FileText,
  HelpCircle,
  Loader2
} from 'lucide-react';
import Markdown from 'react-markdown';
import { CopilotMessage, SecurityIncident } from '../types.js';

interface CopilotViewProps {
  incidents: SecurityIncident[];
  initialIncidentId: string | null;
}

export default function CopilotView({ incidents, initialIncidentId }: CopilotViewProps) {
  const [messages, setMessages] = useState<CopilotMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: 'Greetings, Operator. I am the SentinelX AI Principal Threat Architect.\n\nI can analyze deep packet inspection layers, verify behavioral anomalies against MITRE ATT&CK vectors, cross-correlate endpoint logs, and draft response playbooks. How can I assist with your SOC operations today?',
      timestamp: new Date().toISOString()
    }
  ]);
  const [input, setInput] = useState('');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(initialIncidentId || 'NONE');
  const [sending, setSending] = useState(false);
  
  // Right Drawer Tabbed States
  const [sidebarTab, setSidebarTab] = useState<'context' | 'explain' | 'report'>('context');
  const [explanation, setExplanation] = useState<string>('');
  const [report, setReport] = useState<string>('');
  const [explaining, setExplaining] = useState<boolean>(false);
  const [reporting, setReporting] = useState<boolean>(false);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Sync with incident state updates
  useEffect(() => {
    if (initialIncidentId) {
      setSelectedIncidentId(initialIncidentId);
    }
  }, [initialIncidentId]);

  // Clear states when active incident changes
  useEffect(() => {
    setExplanation('');
    setReport('');
    setExplainError(null);
    setReportError(null);
  }, [selectedIncidentId]);

  const activeIncident = incidents.find(i => i.id === selectedIncidentId);

  const handleSend = async (textToSend?: string) => {
    const promptText = textToSend || input;
    if (!promptText.trim() || sending) return;

    if (!textToSend) setInput('');

    const userMsg: CopilotMessage = {
      id: `msg-${Date.now()}-user`,
      role: 'user',
      content: promptText,
      timestamp: new Date().toISOString()
    };

    setMessages(prev => [...prev, userMsg]);
    setSending(true);

    try {
      const response = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...messages, userMsg],
          incidentId: selectedIncidentId !== 'NONE' ? selectedIncidentId : undefined
        }),
      });

      const data = await response.json();

      const botMsg: CopilotMessage = {
        id: `msg-${Date.now()}-bot`,
        role: 'assistant',
        content: data.message || 'Apologies. I experienced a connection fault and could not compile the threat response.',
        timestamp: new Date().toISOString(),
        contextIncidentId: selectedIncidentId !== 'NONE' ? selectedIncidentId : undefined,
        ragSources: data.sources || []
      };

      setMessages(prev => [...prev, botMsg]);
    } catch (err) {
      console.error('Failed to communicate with Gemini SOC Copilot:', err);
      const errorMsg: CopilotMessage = {
        id: `msg-${Date.now()}-err`,
        role: 'assistant',
        content: 'System Error: Network communications to Gemini 3.5 cognitive pipelines failed. Please verify that your API key is correctly loaded in Settings > Secrets.',
        timestamp: new Date().toISOString()
      };
      setMessages(prev => [...prev, errorMsg]);
    } finally {
      setSending(false);
    }
  };

  const generateExplanation = async () => {
    if (selectedIncidentId === 'NONE' || !activeIncident) {
      setExplainError('Please select a valid target incident from the dropdown context first.');
      return;
    }

    setExplaining(true);
    setExplainError(null);
    try {
      const response = await fetch('/api/copilot/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentId: selectedIncidentId,
          incident: activeIncident,
          mitreMapping: activeIncident.mitreMapping || [],
          riskScore: activeIncident.riskScore,
          ragContext: 'Correlated security documentation from indexed RAG threat-intelligence repositories.'
        })
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const data = await response.json();
      setExplanation(data.explanation || 'No explanation received.');
    } catch (err: any) {
      console.error('Failed to generate threat explanation:', err);
      setExplainError(err?.message || 'Cognitive pipeline fault while compiling threat explanation.');
    } finally {
      setExplaining(false);
    }
  };

  const generateReport = async () => {
    if (selectedIncidentId === 'NONE' || !activeIncident) {
      setReportError('Please select a valid target incident from the dropdown context first.');
      return;
    }

    setReporting(true);
    setReportError(null);
    try {
      const response = await fetch(`/api/copilot/report/${selectedIncidentId}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const data = await response.json();
      setReport(data.report || 'No report received.');
    } catch (err: any) {
      console.error('Failed to generate incident report:', err);
      setReportError(err?.message || 'Cognitive pipeline fault while compiling forensic markdown report.');
    } finally {
      setReporting(false);
    }
  };

  const handleQuickPrompt = (type: string) => {
    const inc = incidents.find(i => i.id === selectedIncidentId);
    if (!inc) {
      handleSend("Briefly explain how SentinelX uses Isolation Forest and Autoencoders to baseline network user behavior.");
      return;
    }

    if (type === 'SUMMARY') {
      handleSend(`Provide a formal technical summary for active Incident ${inc.id}. Suggest immediate remediation steps.`);
    } else if (type === 'MITRE') {
      handleSend(`Analyze active Incident ${inc.id} and maps its raw telemetry indicators to the MITRE ATT&CK Matrix.`);
    } else if (type === 'PLAYBOOK') {
      handleSend(`Draft a custom defensive security response playbook to isolate the compromised workstation and safeguard internal databases.`);
    }
  };

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col h-full p-8 text-gray-200">
      
      {/* Header & Context Bind selector */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-[#111930] pb-6 mb-6 gap-4">
        <div>
          <h2 className="text-xl font-bold text-white font-sans flex items-center gap-2">
            <Sparkles className="h-5.5 w-5.5 text-red-500 animate-pulse" />
            SENTINELX AI SOC COPILOT
          </h2>
          <p className="text-xs text-gray-400 mt-1">Cognitive cyber-defense partner powered by Gemini 3.5, contextually integrated with RAG repositories.</p>
        </div>

        {/* Bind Incident Dropdown */}
        <div className="flex items-center space-x-3 text-xs">
          <label className="text-gray-400 font-mono text-[10px] font-bold uppercase whitespace-nowrap">Incident Target Context:</label>
          <select
            value={selectedIncidentId}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="bg-[#0c1223] border border-[#1b274c] rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-red-500 font-sans max-w-[280px]"
          >
            <option value="NONE">General Threat Hunting (No Context)</option>
            {incidents.map(inc => (
              <option key={inc.id} value={inc.id}>[{inc.id}] {inc.title.substring(0, 32)}...</option>
            ))}
          </select>
        </div>
      </div>

      {/* Main split: Chats thread left, Context helper right */}
      <div className="flex-1 overflow-hidden flex flex-col lg:flex-row gap-6">
        
        {/* Chat Pane */}
        <div className="flex-1 bg-[#090f20]/60 border border-[#172343] rounded-xl overflow-hidden shadow-2xl flex flex-col h-full">
          {/* Thread messages area */}
          <div className="flex-1 overflow-y-auto p-6 space-y-5 bg-[#050915]/60">
            {messages.map((msg) => {
              const isBot = msg.role === 'assistant';
              return (
                <div key={msg.id} className={`flex items-start space-x-4 max-w-[85%] ${!isBot ? 'ml-auto flex-row-reverse space-x-reverse' : ''}`}>
                  {/* Avatar */}
                  <div className={`p-2 rounded-lg flex-shrink-0 border ${
                    isBot 
                      ? 'bg-red-950/30 text-red-400 border-red-800/60' 
                      : 'bg-indigo-950/40 text-indigo-400 border-indigo-800/60'
                  }`}>
                    {isBot ? <Bot className="h-4.5 w-4.5" /> : <User className="h-4.5 w-4.5" />}
                  </div>

                  {/* Body text bubble */}
                  <div className={`rounded-xl p-4.5 text-xs text-gray-200 leading-relaxed font-sans font-medium ${
                    isBot ? 'bg-[#091024]/80 border border-[#142045]' : 'bg-[#152042] border border-[#213264]'
                  }`}>
                    <div className="prose prose-invert max-w-none text-xs leading-relaxed space-y-2 markdown-body">
                      <Markdown>{msg.content}</Markdown>
                    </div>

                    {/* Citations/RAG results block */}
                    {isBot && msg.ragSources && msg.ragSources.length > 0 && (
                      <div className="mt-4 pt-3 border-t border-[#131f45] text-[10px] font-mono text-gray-400 space-y-1.5">
                        <p className="font-bold text-indigo-400 uppercase tracking-wider block text-[9px]">RAG Threat Intelligence Footnotes:</p>
                        {msg.ragSources.map((src, sIdx) => (
                          <div key={src.id} className="flex items-center space-x-1.5">
                            <span className="text-red-500 font-bold">•</span>
                            <span className="text-white font-semibold">[{src.externalId}]</span>
                            <span>{src.title}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {sending && (
              <div className="flex items-start space-x-4">
                <div className="p-2 bg-red-950/30 text-red-400 border border-red-800/60 rounded-lg">
                  <Bot className="h-4.5 w-4.5 animate-spin" />
                </div>
                <div className="bg-[#091024]/80 border border-[#142045] rounded-xl p-4 text-xs font-mono text-red-400 animate-pulse">
                  Gemini Threat Architect modeling behavioral packets...
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Shortcuts */}
          <div className="px-6 py-3 bg-[#070b16] border-t border-[#141f3d] flex flex-wrap gap-2 text-[10px] font-sans font-bold">
            <span className="text-gray-500 mr-2 uppercase tracking-wider flex items-center font-mono">Operations:</span>
            <button 
              onClick={() => handleQuickPrompt('SUMMARY')} 
              className="px-2.5 py-1.5 bg-[#0d162d] border border-[#1c2a4f] hover:border-red-500 text-gray-300 rounded hover:text-white transition-all uppercase"
            >
              Incident Summary
            </button>
            <button 
              onClick={() => handleQuickPrompt('MITRE')} 
              className="px-2.5 py-1.5 bg-[#0d162d] border border-[#1c2a4f] hover:border-red-500 text-gray-300 rounded hover:text-white transition-all uppercase"
            >
              Map MITRE Tactics
            </button>
            <button 
              onClick={() => handleQuickPrompt('PLAYBOOK')} 
              className="px-2.5 py-1.5 bg-[#0d162d] border border-[#1c2a4f] hover:border-red-500 text-gray-300 rounded hover:text-white transition-all uppercase"
            >
              Draft Playbook
            </button>
          </div>

          {/* Chat input box */}
          <div className="p-4 border-t border-[#141f3d] bg-[#050813]">
            <div className="relative">
              <input
                type="text"
                placeholder="Ask Threat Architect regarding live sockets, TLS entropy alerts, or compliance rules..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                disabled={sending}
                className="w-full bg-[#03050b] border border-[#1b274c] rounded-xl pl-4 pr-12 py-3 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-red-500 transition-colors"
              />
              <button 
                onClick={() => handleSend()}
                disabled={!input.trim() || sending}
                className="absolute right-3 top-2.5 p-1.5 bg-red-600 hover:bg-red-700 disabled:bg-gray-800 disabled:text-gray-500 text-white rounded-lg transition-all"
              >
                <Send className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Right Info Context & Forensic Report Drawer */}
        <div className="w-full lg:w-96 bg-[#090f20]/30 border border-[#142045] rounded-xl p-5 text-xs flex flex-col h-full">
          
          {/* Tabs header */}
          <div className="flex border-b border-[#18274d] mb-4 text-[10px] font-mono font-bold uppercase tracking-wider shrink-0">
            <button 
              onClick={() => setSidebarTab('context')}
              className={`flex-1 pb-2.5 text-center transition-colors border-b-2 flex items-center justify-center gap-1.5 ${
                sidebarTab === 'context' 
                  ? 'border-red-500 text-white' 
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              <Info className="h-3.5 w-3.5 text-indigo-400" />
              Context
            </button>
            <button 
              onClick={() => setSidebarTab('explain')}
              className={`flex-1 pb-2.5 text-center transition-colors border-b-2 flex items-center justify-center gap-1.5 ${
                sidebarTab === 'explain' 
                  ? 'border-red-500 text-white' 
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              <HelpCircle className="h-3.5 w-3.5 text-red-400" />
              Explain
            </button>
            <button 
              onClick={() => setSidebarTab('report')}
              className={`flex-1 pb-2.5 text-center transition-colors border-b-2 flex items-center justify-center gap-1.5 ${
                sidebarTab === 'report' 
                  ? 'border-red-500 text-white' 
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              <FileText className="h-3.5 w-3.5 text-amber-400" />
              Report
            </button>
          </div>

          {/* Tab Content */}
          <div className="flex-1 overflow-y-auto pr-1">
            {sidebarTab === 'context' && (
              <div className="space-y-4">
                <h4 className="text-white font-bold uppercase tracking-wider flex items-center gap-1.5 font-sans">
                  Active Context Info
                </h4>

                {selectedIncidentId !== 'NONE' && activeIncident ? (
                  <div className="space-y-4 leading-relaxed text-gray-400 font-sans font-medium">
                    <div className="bg-[#050813] border border-[#131d38] p-3.5 rounded-lg">
                      <span className="text-[9px] font-mono text-red-500 font-bold block uppercase tracking-wider">INCIDENT DETAILS</span>
                      <span className="text-white font-bold block mt-1 leading-tight">{activeIncident.title}</span>
                      <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-[#131d38] text-[10px] font-mono">
                        <div>
                          <span className="text-gray-500 block">ID:</span>
                          <span className="text-gray-300">{activeIncident.id}</span>
                        </div>
                        <div>
                          <span className="text-gray-500 block">Severity:</span>
                          <span className={`font-bold ${
                            activeIncident.severity === 'CRITICAL' ? 'text-red-500' : 'text-amber-500'
                          }`}>{activeIncident.severity}</span>
                        </div>
                        <div>
                          <span className="text-gray-500 block">Risk Score:</span>
                          <span className="text-red-400 font-bold">{activeIncident.riskScore}%</span>
                        </div>
                        <div>
                          <span className="text-gray-500 block">Status:</span>
                          <span className="text-gray-300">{activeIncident.status}</span>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-[#050813] border border-[#131d38] p-3.5 rounded-lg space-y-1 text-[11px]">
                      <span className="text-[9px] font-mono text-indigo-400 font-bold block uppercase tracking-wider">AFFECTED SYSTEM</span>
                      <div><span className="text-gray-500">Source:</span> <span className="text-gray-300 font-mono">{activeIncident.sourceIp}</span></div>
                      <div><span className="text-gray-500">Target:</span> <span className="text-gray-300 font-mono">{activeIncident.targetIp || 'N/A'}</span></div>
                      <div><span className="text-gray-500">Compromised User:</span> <span className="text-gray-300 font-semibold">{activeIncident.compromisedUser || 'N/A'}</span></div>
                    </div>

                    <p className="text-[11px] leading-relaxed text-gray-400 font-sans">
                      Toggle between the tabs above to request an AI-generated technical explainer or a detailed audit-ready incident compliance report using live backend cognitive pipelines.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3 leading-relaxed text-gray-500 text-center py-8">
                    <p>Currently running in standard Threat Hunt mode.</p>
                    <p className="italic text-[10px]">Please select a specific active security incident from the header context dropdown to enable context-aware investigations.</p>
                  </div>
                )}
              </div>
            )}

            {sidebarTab === 'explain' && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h4 className="text-white font-bold uppercase tracking-wider font-sans">AI Threat Explainer</h4>
                  {selectedIncidentId !== 'NONE' && (
                    <button 
                      onClick={generateExplanation}
                      disabled={explaining}
                      className="px-2.5 py-1 bg-red-600 hover:bg-red-700 disabled:bg-gray-800 text-white font-mono text-[9px] font-bold rounded uppercase transition-all shrink-0"
                    >
                      {explaining ? 'Analyzing...' : 'Generate Explainer'}
                    </button>
                  )}
                </div>

                {explainError && (
                  <div className="bg-red-950/40 border border-red-900 text-red-200 p-3 rounded-lg text-[11px] leading-relaxed">
                    {explainError}
                  </div>
                )}

                {explaining ? (
                  <div className="flex flex-col items-center justify-center py-12 space-y-3 text-gray-400">
                    <Loader2 className="h-6 w-6 text-red-500 animate-spin" />
                    <span className="text-[10px] font-mono uppercase tracking-widest animate-pulse">Modeling behavioral layers...</span>
                  </div>
                ) : explanation ? (
                  <div className="bg-[#050813] border border-[#131d38] p-4 rounded-xl text-gray-300 text-[11px] leading-relaxed prose prose-invert max-w-none space-y-3 markdown-body">
                    <Markdown>{explanation}</Markdown>
                  </div>
                ) : (
                  <div className="text-center py-10 text-gray-500 space-y-3">
                    <HelpCircle className="h-8 w-8 mx-auto text-gray-600" />
                    <p className="text-[11px]">Click the button above to synthesize a concise, high-intensity technical analysis mapping this threat's root cause, suspicious factors, and recommended actions.</p>
                  </div>
                )}
              </div>
            )}

            {sidebarTab === 'report' && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h4 className="text-white font-bold uppercase tracking-wider font-sans">AI Forensic Report</h4>
                  {selectedIncidentId !== 'NONE' && (
                    <button 
                      onClick={generateReport}
                      disabled={reporting}
                      className="px-2.5 py-1 bg-amber-600 hover:bg-amber-700 disabled:bg-gray-800 text-white font-mono text-[9px] font-bold rounded uppercase transition-all shrink-0"
                    >
                      {reporting ? 'Compiling...' : 'Generate Report'}
                    </button>
                  )}
                </div>

                {reportError && (
                  <div className="bg-red-950/40 border border-red-900 text-red-200 p-3 rounded-lg text-[11px] leading-relaxed">
                    {reportError}
                  </div>
                )}

                {reporting ? (
                  <div className="flex flex-col items-center justify-center py-12 space-y-3 text-gray-400">
                    <Loader2 className="h-6 w-6 text-amber-500 animate-spin" />
                    <span className="text-[10px] font-mono uppercase tracking-widest animate-pulse">Drafting compliance report...</span>
                  </div>
                ) : report ? (
                  <div className="bg-[#050813] border border-[#131d38] p-4 rounded-xl text-gray-300 text-[11px] leading-relaxed prose prose-invert max-w-none space-y-3 markdown-body">
                    <Markdown>{report}</Markdown>
                  </div>
                ) : (
                  <div className="text-center py-10 text-gray-500 space-y-3">
                    <FileText className="h-8 w-8 mx-auto text-gray-600" />
                    <p className="text-[11px]">Compile an audit-ready, full forensic compliance report detailing deep packet dissection telemetry, MITRE ATT&CK Matrix mapping, and remediation actions.</p>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="bg-[#070c1b] border border-[#1a2544] p-3 rounded-lg text-[10px] font-mono text-gray-500 leading-normal mt-4 shrink-0">
            <span className="text-amber-400 font-bold uppercase block mb-1">COGNITIVE NOTE</span>
            SentinelX utilizes Gemini 3.5 live reasoning. Ensure your API keys are registered under settings to experience real-time federal compliance reports.
          </div>
        </div>

      </div>

    </div>
  );
}
