/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  Terminal, 
  Play, 
  ShieldAlert, 
  CheckCircle, 
  XCircle, 
  Activity, 
  Cpu, 
  User, 
  Lock,
  Clock
} from 'lucide-react';
import { IncidentPlaybookRun, PlaybookStep } from '../types.js';

interface PlaybookOrchestrationProps {
  playbookRuns: IncidentPlaybookRun[];
  onTriggerPlaybook: (actionType: string, target: string) => void;
}

export default function PlaybookOrchestration({ playbookRuns, onTriggerPlaybook }: PlaybookOrchestrationProps) {
  const [selectedRunId, setSelectedRunId] = useState<string | null>(playbookRuns[0]?.id || null);
  const [targetInput, setTargetInput] = useState('10.0.60.100');
  const [actionType, setActionType] = useState('ISOLATE_ENDPOINT');

  const selectedRun = playbookRuns.find(r => r.id === selectedRunId);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED': return <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">COMPLETED</span>;
      case 'FAILED': return <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold bg-red-950 text-red-400 border border-red-800 font-mono">FAILED</span>;
      default: return <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold bg-blue-950 text-blue-400 border border-blue-800 font-mono animate-pulse">RUNNING</span>;
    }
  };

  const getStepStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED': return <CheckCircle className="h-4.5 w-4.5 text-emerald-500" />;
      case 'FAILED': return <XCircle className="h-4.5 w-4.5 text-red-500" />;
      default: return <span className="h-3.5 w-3.5 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></span>;
    }
  };

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col md:flex-row h-full">
      
      {/* Left List Pane: Previous Runs & Dispatcher */}
      <div className="w-full md:w-2/5 border-r border-[#131d38] flex flex-col h-full bg-[#030712]">
        
        {/* Playbook Manual Dispatcher */}
        <div className="p-6 border-b border-[#131d38] bg-[#070c1b]/60">
          <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans mb-4 flex items-center gap-2">
            <Activity className="h-5 w-5 text-red-500" />
            Response Orchestration Dispatcher
          </h3>

          <div className="space-y-4 text-xs">
            {/* Target Select */}
            <div>
              <label className="text-gray-400 uppercase tracking-wider block font-bold text-[9px] mb-1.5 font-mono">Select Response Tactic</label>
              <select
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1b274c] rounded-lg px-3 py-2 text-white focus:outline-none focus:border-red-500 font-sans"
              >
                <option value="ISOLATE_ENDPOINT">ISOLATE ENDPOINT (Host quarantine)</option>
                <option value="BLOCK_IP">BLOCK EXTERNAL IP (Edge blacklist)</option>
                <option value="DISABLE_USER">DISABLE AD ACCOUNT (LDAP account lock)</option>
              </select>
            </div>

            {/* Target Input */}
            <div>
              <label className="text-gray-400 uppercase tracking-wider block font-bold text-[9px] mb-1.5 font-mono">Target Variable</label>
              <input
                type="text"
                placeholder="IP Address or AD Username..."
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1b274c] rounded-lg px-3 py-2 text-white font-mono placeholder-gray-500 focus:outline-none focus:border-red-500"
              />
            </div>

            {/* Dispatch Button */}
            <button
              onClick={() => onTriggerPlaybook(actionType, targetInput)}
              className="w-full flex items-center justify-center space-x-2 bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-700 hover:to-amber-700 text-white rounded-lg py-2.5 font-mono font-bold transition-all shadow-lg shadow-red-950/20"
            >
              <Play className="h-4 w-4" />
              <span>DISPATCH ORCHESTRATOR</span>
            </button>
          </div>
        </div>

        {/* Previous Runs Feed */}
        <div className="p-4 bg-[#050813] border-b border-[#131d38]">
          <h4 className="text-[10px] font-bold uppercase tracking-widest text-gray-400 font-mono">Response Orchestrator Execution Log</h4>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-[#101931]">
          {playbookRuns.map((run) => {
            const isSelected = selectedRunId === run.id;
            return (
              <div 
                key={run.id}
                onClick={() => setSelectedRunId(run.id)}
                className={`p-5 cursor-pointer transition-all ${
                  isSelected ? 'bg-[#0f1936] border-l-4 border-red-500' : 'hover:bg-[#070b16]'
                }`}
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="font-mono text-[9px] font-bold text-gray-500">{run.id}</span>
                  {getStatusBadge(run.status)}
                </div>
                <h4 className="text-xs font-bold text-white font-sans leading-snug">{run.name}</h4>
                <div className="flex justify-between items-center mt-3 text-[10px] font-mono text-gray-500">
                  <span>Target: <span className="text-gray-300 font-semibold">{run.steps[0]?.target || 'N/A'}</span></span>
                  <span>{new Date(run.startTime).toLocaleTimeString()}</span>
                </div>
              </div>
            );
          })}

          {playbookRuns.length === 0 && (
            <div className="p-8 text-center text-xs text-gray-500 font-sans">
              No response playbooks have been triggered yet.
            </div>
          )}
        </div>
      </div>

      {/* Right Content Pane: Interactive Terminal */}
      <div className="w-full md:w-3/5 flex flex-col h-full bg-[#040918] overflow-y-auto p-8">
        {selectedRun ? (
          <div className="flex flex-col h-full">
            {/* Header Block */}
            <div className="border-b border-[#131d38] pb-6 mb-6 flex justify-between items-start">
              <div>
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[8px] font-bold bg-[#131f3f] text-red-400 border border-red-800 font-mono uppercase mb-2">
                  PLAYBOOK RUN RECORD
                </span>
                <h3 className="text-base font-bold text-white font-sans">{selectedRun.name}</h3>
                <p className="text-xs text-gray-400 font-mono mt-1">Initiated by: {selectedRun.triggeredBy} | {new Date(selectedRun.startTime).toLocaleString()}</p>
              </div>
              <div>
                {getStatusBadge(selectedRun.status)}
              </div>
            </div>

            {/* Playbook Steps List */}
            <div className="mb-6 space-y-3.5">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-sans flex items-center gap-1.5">
                <Clock className="h-4.5 w-4.5 text-indigo-400" />
                Response Execution Steps
              </h4>

              {selectedRun.steps.map((step, idx) => (
                <div key={idx} className="bg-[#090f20] border border-[#172343] p-4 rounded-lg flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-3.5">
                    {getStepStatusIcon(step.status)}
                    <div>
                      <h5 className="font-sans font-bold text-white">{step.name}</h5>
                      <p className="text-[10px] text-gray-500 font-mono mt-0.5">Tactic: {step.actionType} | Node: {step.target}</p>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-gray-500 font-bold uppercase">
                    STEP {idx + 1}
                  </span>
                </div>
              ))}
            </div>

            {/* Dynamic Shell Terminal stdout */}
            <div className="flex-1 min-h-[300px] bg-[#020308] border border-[#1b274c] rounded-xl overflow-hidden shadow-2xl flex flex-col font-mono text-xs">
              <div className="bg-[#0b1021] border-b border-[#1b274c] px-4 py-2 flex items-center justify-between select-none">
                <div className="flex items-center space-x-2">
                  <Terminal className="h-4 w-4 text-red-500" />
                  <span className="text-gray-400 text-[10px] font-bold uppercase tracking-wider">SentinelX Secure Shell Output</span>
                </div>
                <div className="flex space-x-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-600"></span>
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-600"></span>
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-600"></span>
                </div>
              </div>

              {/* Shell output scrolling window */}
              <div className="p-5 flex-1 overflow-y-auto text-emerald-400 font-bold space-y-3 bg-[#020308] max-h-[320px]">
                {selectedRun.logs.map((log, idx) => (
                  <p key={idx}>{log}</p>
                ))}
                
                {/* Active step code logs block */}
                {selectedRun.steps.map((step, idx) => (
                  step.outputLog && (
                    <div key={idx} className="pt-3 border-t border-[#101933] text-gray-400 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">
                      <p className="text-red-400 font-bold mb-1">STDOUT (STEP {idx+1}):</p>
                      {step.outputLog}
                    </div>
                  )
                ))}

                {selectedRun.status === 'RUNNING' && (
                  <p className="text-indigo-400 animate-pulse flex items-center gap-1.5">
                    <span>█</span>
                    <span>AWAITING SOCKET HANDSHAKES...</span>
                  </p>
                )}
              </div>
            </div>

          </div>
        ) : (
          <div className="m-auto text-gray-500 font-sans p-8 text-center flex flex-col items-center justify-center gap-3">
            <Terminal className="h-8 w-8 text-indigo-500 opacity-60 animate-bounce" />
            <p className="text-xs max-w-xs leading-relaxed">Trigger or select an orchestration record to open the live secure shell CLI execution feeds.</p>
          </div>
        )}
      </div>

    </div>
  );
}
