/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  CheckCircle, 
  XCircle, 
  Play, 
  History, 
  Sparkles, 
  AlertTriangle, 
  Clock, 
  ShieldCheck, 
  Layers,
  ArrowRight
} from 'lucide-react';
import { ResponseRecommendation, SecurityIncident } from '../types';

interface ResponseRecommendationsViewProps {
  incidents: SecurityIncident[];
  onTriggerPlaybook?: (actionType: string, target: string) => void;
}

export default function ResponseRecommendationsView({ incidents, onTriggerPlaybook }: ResponseRecommendationsViewProps) {
  const [recommendations, setRecommendations] = useState<ResponseRecommendation[]>([]);
  const [history, setHistory] = useState<ResponseRecommendation[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'active' | 'history'>('active');
  const [notification, setNotification] = useState<{ type: 'success' | 'error', message: string } | null>(null);

  // Load recommendations history
  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/response/history');
      if (res.ok) {
        const data = await res.json();
        const items: ResponseRecommendation[] = data.history || [];
        setHistory(items);
        // Set active recommendations (PENDING status)
        setRecommendations(items.filter(item => item.status === 'PENDING'));
      }
    } catch (err) {
      console.error('Failed to fetch recommendation history:', err);
    }
  };

  useEffect(() => {
    fetchHistory();
    // Poll history every 5 seconds to stay updated
    const interval = setInterval(fetchHistory, 5000);
    return () => clearInterval(interval);
  }, []);

  // Set default selected incident once loaded
  useEffect(() => {
    if (incidents.length > 0 && !selectedIncidentId) {
      setSelectedIncidentId(incidents[0].id);
    }
  }, [incidents, selectedIncidentId]);

  // Request fresh recommendations
  const handleGenerateRecommendations = async () => {
    if (!selectedIncidentId) return;
    setLoading(true);
    setNotification(null);

    try {
      const incident = incidents.find(i => i.id === selectedIncidentId);
      const res = await fetch('/api/response/recommend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentId: selectedIncidentId,
          severity: incident?.severity,
          mitreMapping: incident?.mitreMapping
        })
      });

      if (res.ok) {
        const data = await res.json();
        const generated: ResponseRecommendation[] = data.recommendations || [];
        setNotification({
          type: 'success',
          message: `Generated ${generated.length} AI containment recommendation(s) based on MITRE mapping.`
        });
        fetchHistory();
      } else {
        setNotification({
          type: 'error',
          message: 'Failed to generate recommendations from engine.'
        });
      }
    } catch (err) {
      console.error(err);
      setNotification({ type: 'error', message: 'Network error generating recommendations.' });
    } finally {
      setLoading(false);
    }
  };

  // Dispatch a recommendation
  const handleDispatch = async (recId: string) => {
    setNotification(null);
    try {
      const res = await fetch('/api/response/dispatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: recId })
      });

      if (res.ok) {
        setNotification({
          type: 'success',
          message: 'Containment recommendation successfully dispatched to SentinelX Orchestrator.'
        });
        fetchHistory();
      } else {
        setNotification({
          type: 'error',
          message: 'Failed to dispatch playbook containment command.'
        });
      }
    } catch (err) {
      console.error(err);
      setNotification({ type: 'error', message: 'Failed to communicate with orchestrator.' });
    }
  };

  // Dismiss a recommendation
  const handleDismiss = async (recId: string) => {
    setNotification(null);
    try {
      const res = await fetch('/api/response/dismiss', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: recId })
      });

      if (res.ok) {
        setNotification({
          type: 'success',
          message: 'Recommendation dismissed from active stack.'
        });
        fetchHistory();
      } else {
        setNotification({
          type: 'error',
          message: 'Failed to dismiss recommendation.'
        });
      }
    } catch (err) {
      console.error(err);
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'CRITICAL':
        return 'bg-red-950/70 text-red-400 border-red-800/80';
      case 'HIGH':
        return 'bg-amber-950/70 text-amber-400 border-amber-800/80';
      case 'MEDIUM':
        return 'bg-blue-950/70 text-blue-400 border-blue-800/80';
      default:
        return 'bg-slate-900/70 text-slate-400 border-slate-700/80';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'DISPATCHED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-950/70 text-emerald-400 border border-emerald-800/80 font-mono">DISPATCHED</span>;
      case 'DISMISSED':
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold bg-slate-950/70 text-slate-400 border border-slate-800/80 font-mono">DISMISSED</span>;
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold bg-blue-950/70 text-blue-400 border border-blue-800/80 font-mono animate-pulse">PENDING</span>;
    }
  };

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col h-full font-sans text-gray-200">
      
      {/* Top Banner Header */}
      <div className="p-6 border-b border-[#131d38] bg-[#070c1b]/60 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center space-x-2.5 mb-1.5">
            <span className="p-1 bg-red-950/50 border border-red-800/40 rounded">
              <ShieldAlert className="h-4.5 w-4.5 text-red-500 animate-pulse" />
            </span>
            <h2 className="text-base font-bold text-white uppercase tracking-wider">
              AI Containment Recommendation Engine
            </h2>
          </div>
          <p className="text-xs text-gray-400 font-sans max-w-2xl leading-relaxed">
            Generate and analyze non-automated response recommendations mapped directly against MITRE ATT&CK tactics and security incident indicators. Select and dispatch tactics on-demand.
          </p>
        </div>

        {/* Tab Selection */}
        <div className="flex bg-[#0a0f1d] border border-[#1b274c] rounded-lg p-1 text-xs">
          <button
            onClick={() => setActiveTab('active')}
            className={`px-4 py-1.5 rounded-md font-medium transition-all ${
              activeTab === 'active' 
                ? 'bg-[#18254c] text-white shadow' 
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Active Stack ({recommendations.length})
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`px-4 py-1.5 rounded-md font-medium transition-all ${
              activeTab === 'history' 
                ? 'bg-[#18254c] text-white shadow' 
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Recommendation History ({history.length})
          </button>
        </div>
      </div>

      {/* Main Grid Workspace */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">

        {/* Global Notifications */}
        {notification && (
          <div className={`p-4 rounded-xl border text-xs flex items-start space-x-3 transition-all ${
            notification.type === 'success' 
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300' 
              : 'bg-red-950/40 border-red-800/60 text-red-300'
          }`}>
            {notification.type === 'success' ? (
              <ShieldCheck className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
            )}
            <div className="flex-1">
              <span className="font-bold uppercase tracking-wider block mb-0.5">
                {notification.type === 'success' ? 'Task Executed Successfully' : 'System Operational Warning'}
              </span>
              <span>{notification.message}</span>
            </div>
          </div>
        )}

        {/* Dynamic Threat Containment Trigger */}
        <div className="bg-[#070c1b] border border-[#142247] rounded-xl p-5 shadow-lg">
          <div className="flex items-center space-x-2 mb-4">
            <Sparkles className="h-5 w-5 text-amber-500 animate-pulse" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">
              Dynamic Threat Containment Analyst Recommendation Tool
            </h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
            
            <div className="md:col-span-8">
              <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest block mb-2 font-mono">
                Select Active Security Case
              </label>
              <select
                value={selectedIncidentId}
                onChange={(e) => setSelectedIncidentId(e.target.value)}
                className="w-full bg-[#030712] border border-[#1b274c] rounded-lg px-3 py-2.5 text-xs text-white focus:outline-none focus:border-red-500 font-sans"
              >
                <option value="" disabled>-- Choose open security incident --</option>
                {incidents.map((incident) => (
                  <option key={incident.id} value={incident.id}>
                    [{incident.id}] {incident.title} (Severity: {incident.severity})
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-4">
              <button
                disabled={loading || !selectedIncidentId}
                onClick={handleGenerateRecommendations}
                className="w-full flex items-center justify-center space-x-2 bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-700 hover:to-amber-700 disabled:from-gray-800 disabled:to-gray-900 disabled:text-gray-500 disabled:cursor-not-allowed text-white rounded-lg py-2.5 font-mono font-bold text-xs transition-all shadow-lg shadow-red-950/20"
              >
                {loading ? (
                  <>
                    <span className="h-3.5 w-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                    <span>GENERATING RECOMMENDER PATHS...</span>
                  </>
                ) : (
                  <>
                    <Terminal className="h-4 w-4" />
                    <span>GENERATE RECOMMENDATIONS</span>
                  </>
                )}
              </button>
            </div>

          </div>
        </div>

        {/* Main Tabs Workspace Rendering */}
        {activeTab === 'active' ? (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest font-mono flex items-center gap-1.5">
                <Layers className="h-4 w-4 text-red-400" />
                Active Containment Recommendations Stack ({recommendations.length})
              </h3>
              <p className="text-[11px] text-gray-500 font-mono">Only recommend actions • No Automated SOAR</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {recommendations.map((rec) => (
                <div 
                  key={rec.id} 
                  className="bg-[#091024]/80 border border-[#1c2e5a] hover:border-red-500/40 rounded-xl p-5 shadow-xl transition-all duration-300 flex flex-col justify-between group"
                >
                  <div>
                    {/* Header: Action Name & Priority */}
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[9px] font-bold border font-mono ${getPriorityColor(rec.priority)}`}>
                          {rec.priority} PRIORITY
                        </span>
                        <h4 className="text-sm font-bold text-white uppercase tracking-wider font-sans mt-2.5 group-hover:text-red-400 transition-colors">
                          {rec.action}
                        </h4>
                      </div>
                      <span className="text-[9px] font-mono font-semibold text-gray-500">{rec.id}</span>
                    </div>

                    {/* Meta linked Case */}
                    <div className="bg-[#030612]/80 border border-[#131d3a]/60 px-3 py-2 rounded-lg text-[11px] mb-4 flex items-center gap-2">
                      <span className="font-bold text-red-500 font-mono shrink-0 uppercase tracking-widest">{rec.incidentId}</span>
                      <span className="text-gray-400 truncate">{rec.incidentTitle}</span>
                    </div>

                    {/* Detailed info block */}
                    <div className="space-y-3.5 text-xs">
                      {/* Reason */}
                      <div className="bg-[#020308]/40 border-l-2 border-red-500/50 p-3 rounded-r-lg">
                        <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block mb-1 font-mono">
                          Security Justification
                        </span>
                        <p className="text-gray-300 leading-relaxed font-sans">{rec.reason}</p>
                      </div>

                      {/* Estimated Impact */}
                      <div className="bg-[#020308]/40 border-l-2 border-amber-500/50 p-3 rounded-r-lg">
                        <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block mb-1 font-mono">
                          Estimated Operational Impact
                        </span>
                        <p className="text-gray-300 leading-relaxed font-sans">{rec.estimatedImpact}</p>
                      </div>
                    </div>
                  </div>

                  {/* Operational Controls Dispatcher */}
                  <div className="mt-6 pt-4 border-t border-[#1a2b53] flex items-center justify-between gap-3 text-xs">
                    <button
                      onClick={() => handleDismiss(rec.id)}
                      className="px-4 py-2 bg-slate-900/60 hover:bg-slate-950 hover:text-red-400 border border-slate-800 rounded-lg font-mono font-bold transition-all"
                    >
                      DISMISS RECOMMENDATION
                    </button>
                    
                    <button
                      onClick={() => handleDispatch(rec.id)}
                      className="flex-1 flex items-center justify-center space-x-1.5 bg-gradient-to-r from-red-600/80 to-amber-600/80 hover:from-red-600 hover:to-amber-600 text-white border border-red-500/30 rounded-lg py-2 font-mono font-bold transition-all"
                    >
                      <Play className="h-3.5 w-3.5" />
                      <span>DISPATCH CONTAINMENT</span>
                    </button>
                  </div>
                </div>
              ))}

              {recommendations.length === 0 && (
                <div className="md:col-span-2 bg-[#060a15] border border-dashed border-[#14234c] rounded-xl p-12 text-center text-xs text-gray-500 flex flex-col items-center justify-center gap-3">
                  <ShieldCheck className="h-8 w-8 text-emerald-500 animate-pulse" />
                  <div>
                    <p className="font-bold text-gray-300 mb-1 uppercase tracking-wider">No Pending Containment Actions</p>
                    <p className="max-w-md mx-auto leading-relaxed text-gray-500">
                      Select an incident from the drop-down tool above and dispatch the Recommendation Engine to generate proactive incident isolation mappings.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest font-mono flex items-center gap-1.5">
                <History className="h-4 w-4 text-amber-400" />
                Response Recommendation Execution Audit Logs (`/response/history`)
              </h3>
            </div>

            <div className="bg-[#060a16] border border-[#121c3b] rounded-xl overflow-hidden shadow-2xl">
              <div className="p-4 bg-[#0a1125] border-b border-[#121c3b] flex items-center justify-between text-xs font-mono font-bold text-gray-400">
                <span className="w-16">ID</span>
                <span className="w-24">INCIDENT</span>
                <span className="w-48 truncate">RECOMMENDED ACTION</span>
                <span className="w-32">EST. PRIORITY</span>
                <span className="w-24">STATUS</span>
                <span className="w-36 text-right">TIMESTAMP</span>
              </div>

              <div className="divide-y divide-[#101831] max-h-[500px] overflow-y-auto">
                {history.map((rec) => (
                  <div key={rec.id} className="p-4 flex items-center justify-between text-xs font-mono hover:bg-[#0c142b]/40 transition-colors">
                    <span className="w-16 font-bold text-gray-500">{rec.id}</span>
                    <span className="w-24 font-bold text-red-500">{rec.incidentId}</span>
                    <span className="w-48 truncate text-gray-200 font-sans font-semibold">{rec.action}</span>
                    <span className="w-32">
                      <span className={`px-2 py-0.5 rounded text-[8px] font-bold border ${getPriorityColor(rec.priority)}`}>
                        {rec.priority}
                      </span>
                    </span>
                    <span className="w-24">{getStatusBadge(rec.status)}</span>
                    <span className="w-36 text-right text-gray-500 text-[10px]">{new Date(rec.timestamp).toLocaleString()}</span>
                  </div>
                ))}

                {history.length === 0 && (
                  <div className="p-8 text-center text-xs text-gray-500">
                    No recommendations historical entries are logged inside the persistent DB.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Informational Guidance Panel */}
        <div className="bg-gradient-to-r from-[#0c1328] to-[#060a16] border border-[#14234d] p-5 rounded-xl flex items-start space-x-4">
          <Terminal className="h-6 w-6 text-indigo-400 shrink-0 mt-0.5" />
          <div className="text-xs space-y-1.5 leading-relaxed">
            <h4 className="font-bold text-white uppercase tracking-wider font-sans">
              Non-Automated Containment Policy Framework (Operational Mandate)
            </h4>
            <p className="text-gray-400 font-sans">
              This system executes strictly under human-in-the-loop validation policies. SentinelX generates intelligent mitigation recommendations based on real-time packet parsing, behavioral neural deviations, and MITRE technical matrix overlays.
            </p>
            <div className="pt-2 flex flex-wrap gap-x-6 gap-y-1 text-[11px] font-mono text-gray-500">
              <span className="flex items-center gap-1"><ArrowRight className="h-3 w-3 text-red-500" /> Large Upload → Block outbound traffic</span>
              <span className="flex items-center gap-1"><ArrowRight className="h-3 w-3 text-red-500" /> Credential Attack → Reset password</span>
              <span className="flex items-center gap-1"><ArrowRight className="h-3 w-3 text-red-500" /> Port Scan → Block source IP</span>
              <span className="flex items-center gap-1"><ArrowRight className="h-3 w-3 text-red-500" /> Malware → Isolate endpoint</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
