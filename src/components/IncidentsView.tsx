/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  AlertOctagon, 
  Clock, 
  Terminal, 
  User, 
  ShieldAlert, 
  FileText, 
  Sparkles, 
  Layers, 
  ArrowRight,
  UserCheck,
  CheckCircle,
  HelpCircle,
  X,
  Play
} from 'lucide-react';
import { SecurityIncident } from '../types.js';

interface IncidentsViewProps {
  incidents: SecurityIncident[];
  onTriggerPlaybook: (actionType: string, target: string) => void;
  selectedIncidentId: string | null;
  setSelectedIncidentId: (id: string | null) => void;
}

export default function IncidentsView({ 
  incidents, 
  onTriggerPlaybook,
  selectedIncidentId,
  setSelectedIncidentId 
}: IncidentsViewProps) {
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [generatingReport, setGeneratingReport] = useState(false);

  const selectedIncident = incidents.find(i => i.id === selectedIncidentId);

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'bg-red-950 text-red-400 border-red-800';
      case 'HIGH': return 'bg-amber-950 text-amber-400 border-amber-800';
      default: return 'bg-blue-950 text-blue-400 border-blue-800';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'RESOLVED': return 'bg-emerald-950 text-emerald-400 border-emerald-800';
      case 'CONTAINED': return 'bg-blue-950 text-blue-400 border-blue-800';
      case 'INVESTIGATING': return 'bg-amber-950 text-amber-400 border-amber-800';
      default: return 'bg-red-950 text-red-400 border-red-800';
    }
  };

  const handleGenerateReport = async (incidentId: string) => {
    setGeneratingReport(true);
    setReportMarkdown(null);
    try {
      const response = await fetch('/api/copilot/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incidentId }),
      });
      const data = await response.json();
      if (data.report) {
        setReportMarkdown(data.report);
      } else if (data.error) {
        setReportMarkdown(`### Error Compiling Report\n\n${data.error}`);
      }
    } catch (err: any) {
      setReportMarkdown(`### Connection Failure\n\nFailed to establish communications with Gemini 3.5 Compiler: ${err?.message || 'Unknown fault'}`);
    } finally {
      setGeneratingReport(false);
    }
  };

  const handlePrint = () => {
    const printContent = document.getElementById('forensic-report-content');
    if (!printContent) return;

    const iframe = document.createElement('iframe');
    iframe.style.position = 'fixed';
    iframe.style.right = '0';
    iframe.style.bottom = '0';
    iframe.style.width = '0';
    iframe.style.height = '0';
    iframe.style.border = '0';
    document.body.appendChild(iframe);

    const doc = iframe.contentWindow?.document;
    if (doc) {
      doc.open();
      doc.write(`
        <html>
          <head>
            <title>SentinelX Forensic Report - ${selectedIncident?.id}</title>
            <style>
              body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                color: #111827;
                background-color: #ffffff;
                padding: 40px;
                line-height: 1.6;
                font-size: 13px;
              }
              h1 {
                font-size: 18px;
                border-bottom: 2px solid #dc2626;
                padding-bottom: 8px;
                margin-top: 24px;
                text-transform: uppercase;
                font-family: monospace;
              }
              h2 {
                font-size: 14px;
                color: #b91c1c;
                margin-top: 20px;
                text-transform: uppercase;
                font-family: monospace;
              }
              h3 {
                font-size: 11px;
                color: #d97706;
                margin-top: 16px;
                text-transform: uppercase;
                font-family: monospace;
              }
              p {
                margin: 10px 0;
              }
              code {
                font-family: monospace;
                background-color: #f3f4f6;
                padding: 2px 4px;
                border: 1px solid #e5e7eb;
                border-radius: 4px;
                font-size: 11px;
                color: #dc2626;
              }
              hr {
                border: 0;
                border-top: 1px solid #e5e7eb;
                margin: 24px 0;
              }
              .flex {
                display: flex;
              }
              .gap-2 {
                gap: 8px;
              }
              .pl-2 {
                padding-left: 8px;
              }
              @media print {
                body { padding: 0; }
              }
            </style>
          </head>
          <body>
            ${printContent.innerHTML}
          </body>
        </html>
      `);
      doc.close();

      setTimeout(() => {
        iframe.contentWindow?.focus();
        iframe.contentWindow?.print();
        document.body.removeChild(iframe);
      }, 500);
    }
  };

  const renderReport = (markdown: string) => {
    const lines = markdown.split('\n');
    return (
      <div id="forensic-report-content" className="text-gray-300 font-sans leading-relaxed text-xs">
        {lines.map((line, idx) => {
          if (line.startsWith('# ')) {
            return (
              <h1 key={idx} className="text-sm font-bold text-white border-b border-red-800/40 pb-2 mt-5 mb-3 tracking-tight font-mono uppercase">
                {line.replace('# ', '')}
              </h1>
            );
          }
          if (line.startsWith('## ')) {
            return (
              <h2 key={idx} className="text-xs font-bold text-red-400 mt-4 mb-2 tracking-tight uppercase font-mono">
                {line.replace('## ', '')}
              </h2>
            );
          }
          if (line.startsWith('### ')) {
            return (
              <h3 key={idx} className="text-[11px] font-bold text-amber-500 mt-3 mb-1 uppercase font-mono">
                {line.replace('### ', '')}
              </h3>
            );
          }
          if (line.startsWith('- ')) {
            return (
              <div key={idx} className="flex items-start gap-2 my-1 pl-2 font-mono text-[11px]">
                <span className="text-red-500">•</span>
                <span className="text-gray-300">{line.replace('- ', '')}</span>
              </div>
            );
          }
          if (line.trim() === '---') {
            return <hr key={idx} className="border-red-900/30 my-4" />;
          }
          if (line.trim() === '') {
            return <div key={idx} className="h-2" />;
          }

          return (
            <p key={idx} className="my-1.5 leading-relaxed font-sans text-gray-300">
              {line.split('`').map((part, i) => {
                if (i % 2 === 1) {
                  return (
                    <code key={i} className="bg-red-950/40 text-red-400 border border-red-900/40 px-1 py-0.5 rounded text-[10px] font-mono font-bold">
                      {part}
                    </code>
                  );
                }
                return part;
              })}
            </p>
          );
        })}
      </div>
    );
  };

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col md:flex-row h-full">
      
      {/* Left List Pane */}
      <div className="w-full md:w-2/5 border-r border-[#131d38] flex flex-col h-full bg-[#030712]">
        <div className="p-6 border-b border-[#131d38] bg-[#070c1b]/60">
          <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans mb-1 flex items-center gap-2">
            <AlertOctagon className="h-5 w-5 text-red-500 animate-pulse" />
            SOC Incident Command Room
          </h3>
          <p className="text-[10px] text-gray-400">Consolidated dossiers mapping threat actors, log telemetry, and network flows.</p>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-[#101931]">
          {incidents.map((inc) => {
            const isSelected = selectedIncidentId === inc.id;
            return (
              <div 
                key={inc.id}
                onClick={() => {
                  setSelectedIncidentId(inc.id);
                  setReportMarkdown(null);
                }}
                className={`p-5 cursor-pointer transition-all ${
                  isSelected ? 'bg-[#0f1936] border-l-4 border-red-500' : 'hover:bg-[#070b16]'
                }`}
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="font-mono text-[10px] font-bold text-red-500">{inc.id}</span>
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-bold border uppercase font-mono ${getSeverityColor(inc.severity)}`}>
                    {inc.severity}
                  </span>
                </div>
                <h4 className="text-xs font-bold text-white font-sans">{inc.title}</h4>
                <div className="flex justify-between items-center mt-3 text-[10px] font-mono text-gray-500">
                  <span>Host: <span className="text-gray-300">{inc.sourceIp || 'Gateway'}</span></span>
                  <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-bold border uppercase ${getStatusColor(inc.status)}`}>
                    {inc.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Details Pane */}
      <div className="w-full md:w-3/5 flex flex-col h-full bg-[#040918] overflow-y-auto">
        {selectedIncident ? (
          <div className="p-8">
            {/* Header Block */}
            <div className="border-b border-[#131d38] pb-6 mb-6">
              <div className="flex justify-between items-start">
                <div>
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold bg-[#131f3f] text-red-400 border border-red-800 font-mono uppercase mb-2">
                    INCIDENT ACTIVE DOSSIER
                  </span>
                  <h3 className="text-lg font-bold text-white font-sans">{selectedIncident.title}</h3>
                  <p className="text-xs text-gray-400 font-mono mt-1">First Detected: {new Date(selectedIncident.timestamp).toLocaleString()}</p>
                </div>
                <div className="text-right">
                  <span className={`inline-flex items-center px-3 py-1 rounded text-xs font-bold border uppercase font-mono ${getStatusColor(selectedIncident.status)}`}>
                    {selectedIncident.status}
                  </span>
                </div>
              </div>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-3 gap-4 mb-8 text-xs font-mono">
              <div className="bg-[#090f20] border border-[#172343] p-3 rounded-lg">
                <span className="text-gray-500 uppercase block text-[9px]">Compromised Host</span>
                <span className="text-white font-bold block mt-1">{selectedIncident.sourceIp || 'N/A'}</span>
              </div>
              <div className="bg-[#090f20] border border-[#172343] p-3 rounded-lg">
                <span className="text-gray-500 uppercase block text-[9px]">Target IP / Node</span>
                <span className="text-white font-bold block mt-1">{selectedIncident.targetIp || 'Internal AD'}</span>
              </div>
              <div className="bg-[#090f20] border border-[#172343] p-3 rounded-lg">
                <span className="text-gray-500 uppercase block text-[9px]">Ensemble Threat Index</span>
                <span className="text-red-400 font-extrabold block mt-1">{selectedIncident.riskScore}%</span>
              </div>
            </div>

            {/* Incident Summary */}
            <div className="bg-[#060b19] border border-[#131d38] rounded-xl p-5 mb-6 text-xs">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider font-sans mb-2">Threat Assessment Summary</h4>
              <p className="text-gray-300 leading-relaxed font-sans font-medium">{selectedIncident.summary}</p>
            </div>

            {/* Business Impact & AI Attack Prediction Agent */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
              {/* Business Impact Evaluation */}
              <div className="bg-[#060b19] border border-[#131d38] rounded-xl p-5 text-xs flex flex-col justify-between">
                <div>
                  <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider font-sans mb-3 flex items-center gap-1.5">
                    <Layers className="h-4 w-4 text-amber-500" />
                    Business Impact Engine
                  </h4>
                  <div className="flex items-center gap-2 mb-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border uppercase font-mono ${
                      selectedIncident.businessImpactLevel === 'CRITICAL' ? 'bg-red-950 text-red-400 border-red-800' :
                      selectedIncident.businessImpactLevel === 'HIGH' ? 'bg-amber-950 text-amber-400 border-amber-800' :
                      selectedIncident.businessImpactLevel === 'MEDIUM' ? 'bg-blue-950 text-blue-400 border-blue-800' :
                      'bg-slate-950 text-slate-400 border-slate-800'
                    }`}>
                      {selectedIncident.businessImpactLevel || 'HIGH'} IMPACT
                    </span>
                    <span className="text-gray-400 text-[10px] font-mono">FINANCIAL & LEGAL RISK</span>
                  </div>
                  <p className="text-gray-300 leading-relaxed font-sans font-medium">
                    {selectedIncident.businessImpact || 'Possible corporate liability, potential regulatory fines, and external customer service interruptions due to network asset quarantine.'}
                  </p>
                </div>
              </div>

              {/* AI Attack Prediction */}
              <div className="bg-[#050c20] border border-indigo-900/40 rounded-xl p-5 text-xs">
                <h4 className="text-xs font-bold text-indigo-400 uppercase tracking-wider font-sans mb-3 flex items-center gap-1.5">
                  <Sparkles className="h-4 w-4 text-indigo-400 animate-pulse" />
                  AI Attack Prediction Agent
                </h4>
                {selectedIncident.prediction ? (
                  <div>
                    <div className="flex items-center justify-between mb-3 bg-[#0a122e] border border-indigo-950 p-2.5 rounded-lg">
                      <div>
                        <span className="text-[9px] text-gray-500 uppercase block font-mono">Current Stage</span>
                        <span className="text-white font-bold font-mono">{selectedIncident.prediction.current_stage}</span>
                      </div>
                      <ArrowRight className="h-4 w-4 text-indigo-400" />
                      <div className="text-right">
                        <span className="text-[9px] text-gray-500 uppercase block font-mono">Predicted Next</span>
                        <span className="text-indigo-400 font-bold font-mono">{selectedIncident.prediction.predicted_next_stage}</span>
                      </div>
                    </div>

                    <div className="mb-3">
                      <div className="flex justify-between items-center mb-1 text-[10px] font-mono text-gray-400">
                        <span>Prediction Confidence</span>
                        <span className="text-indigo-400 font-bold">{selectedIncident.prediction.confidence}%</span>
                      </div>
                      <div className="w-full bg-[#0c1533] rounded-full h-1.5 overflow-hidden">
                        <div 
                          className="bg-indigo-500 h-1.5 rounded-full transition-all duration-1000" 
                          style={{ width: `${selectedIncident.prediction.confidence}%` }}
                        />
                      </div>
                    </div>

                    <div className="bg-[#030614] border border-indigo-950/60 p-2.5 rounded-lg font-mono text-[10px] text-gray-400">
                      <span className="text-indigo-400 font-bold block mb-1 uppercase text-[9px]">AI Reasoning Framework:</span>
                      <ul className="space-y-1 list-disc list-inside">
                        {selectedIncident.prediction.reasoning.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ) : (
                  <div className="text-gray-500 font-mono text-[11px] py-4 text-center">
                    No active target predictions available for this low-severity dossier.
                  </div>
                )}
              </div>
            </div>

            {/* MITRE Mapping Cards */}
            <div className="mb-8">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-sans mb-3 flex items-center gap-1.5">
                <ShieldAlert className="h-4.5 w-4.5 text-red-500" />
                MITRE ATT&CK Matrix Techniques Tagged
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-xs font-mono">
                {selectedIncident.mitreMapping.map((mit, idx) => (
                  <div key={idx} className="bg-[#070c1b] border border-[#1c2a4f] rounded-lg p-3">
                    <div className="flex justify-between items-center text-[10px] text-red-400 font-bold mb-1">
                      <span>{mit.tactic}</span>
                      <span>{mit.techniqueId}</span>
                    </div>
                    <span className="text-white font-semibold block leading-tight">{mit.techniqueName}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Automated PDF Incident Forensics Report */}
            <div className="border-t border-[#131d38] pt-6 mb-8">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-sans">Automated Incident Forensics Reporting</h4>
                  <p className="text-[10px] text-gray-400">Compile audit-ready compliance dossiers via server-side Gemini 3.5.</p>
                </div>
                <button 
                  onClick={() => handleGenerateReport(selectedIncident.id)}
                  disabled={generatingReport}
                  className="flex items-center space-x-2 bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-700 hover:to-amber-700 disabled:opacity-55 text-white rounded-lg px-4 py-2 text-xs font-mono font-bold transition-all shadow-lg shadow-red-950/20"
                >
                  <Sparkles className="h-4 w-4" />
                  <span>{generatingReport ? 'COMPILING REPORT...' : 'COMPILE FORENSICS REPORT'}</span>
                </button>
              </div>

              {/* PDF report mockup container */}
              {reportMarkdown && (
                <div className="bg-[#03050c] border border-red-900/30 rounded-xl p-6 text-xs text-gray-300 relative max-h-[500px] overflow-y-auto">
                  <div className="flex items-center justify-between border-b border-red-950/60 pb-3 mb-4">
                    <span className="text-[10px] font-bold text-red-400 font-mono tracking-wider uppercase">
                      AUDIT-READY SECURITY BRIEFING
                    </span>
                    <div className="flex items-center gap-2">
                      <button 
                        onClick={handlePrint}
                        className="px-2.5 py-1 text-[10px] bg-red-950/40 text-red-400 hover:bg-red-900/20 hover:text-white rounded border border-red-800/40 font-mono font-bold transition-all flex items-center gap-1 cursor-pointer"
                        title="Download or Print PDF report"
                      >
                        <Sparkles className="h-3 w-3" /> PRINT / SAVE PDF
                      </button>
                      <button 
                        onClick={() => setReportMarkdown(null)}
                        className="p-1 bg-red-950/40 text-red-400 hover:text-white rounded border border-red-800/40 cursor-pointer"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                  <div className="mt-2 font-sans">
                    {renderReport(reportMarkdown)}
                  </div>
                </div>
              )}
            </div>

            {/* Incident Event Timeline Feed */}
            <div className="border-t border-[#131d38] pt-6">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider font-sans mb-4 flex items-center gap-1.5">
                <Clock className="h-4.5 w-4.5 text-indigo-400" />
                Forensic Incident Activity Timeline
              </h4>
              <div className="space-y-5 border-l border-[#131d38] pl-5 ml-2.5 text-xs">
                {selectedIncident.timeline.map((time, idx) => (
                  <div key={idx} className="relative">
                    <span className={`absolute -left-7.5 top-0.5 rounded-full w-4 h-4 border flex items-center justify-center text-[8px] font-mono font-bold ${
                      time.type === 'ALERT' 
                        ? 'bg-red-950 text-red-400 border-red-800' 
                        : time.type === 'PLAYBOOK'
                          ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                          : 'bg-blue-950 text-blue-400 border-blue-800'
                    }`}>
                      {time.type[0]}
                    </span>
                    <div className="font-mono text-[10px] text-gray-500">{new Date(time.timestamp).toLocaleTimeString()}</div>
                    <div className="text-white font-semibold font-sans mt-0.5">{time.source}</div>
                    <p className="text-gray-400 mt-1 font-sans">{time.description}</p>
                  </div>
                ))}
              </div>
            </div>

          </div>
        ) : (
          <div className="m-auto text-gray-500 font-sans">
            Select an active incident dossier from the queue to open the Command Room.
          </div>
        )}
      </div>

    </div>
  );
}
