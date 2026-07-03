/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  Database, 
  Search, 
  Terminal, 
  ShieldAlert, 
  Calendar, 
  Cpu, 
  ArrowRightLeft,
  ChevronDown,
  ChevronUp,
  Server,
  Network
} from 'lucide-react';
import { UnifiedTelemetryLog, LogSource } from '../types.js';

interface TelemetryLogsViewProps {
  logs: UnifiedTelemetryLog[];
}

export default function TelemetryLogsView({ logs }: TelemetryLogsViewProps) {
  const [search, setSearch] = useState('');
  const [selectedSource, setSelectedSource] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  const filteredLogs = logs.filter(log => {
    const matchesSearch = log.message.toLowerCase().includes(search.toLowerCase()) ||
                          log.host.includes(search) ||
                          (log.userId && log.userId.toLowerCase().includes(search.toLowerCase()));
    const matchesSource = selectedSource === 'ALL' || log.source === selectedSource;
    const matchesSeverity = selectedSeverity === 'ALL' || log.severity === selectedSeverity;
    return matchesSearch && matchesSource && matchesSeverity;
  });

  const getSourceBadgeColor = (source: LogSource) => {
    switch (source) {
      case 'PROCESS_EXECUTION': return 'bg-purple-950 text-purple-400 border-purple-800';
      case 'FIREWALL': return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'AUTH_SERVER': return 'bg-blue-950 text-blue-400 border-blue-800';
      case 'DNS_QUERY': return 'bg-cyan-950 text-cyan-400 border-cyan-800';
      default: return 'bg-gray-900 text-gray-400 border-gray-700';
    }
  };

  const getSeverityBadgeColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'bg-red-950 text-red-400 border-red-800 font-bold';
      case 'ERROR': return 'bg-red-950/40 text-red-400/80 border-red-900/60';
      case 'WARNING': return 'bg-amber-950 text-amber-400 border-amber-800';
      default: return 'bg-gray-900 text-gray-400 border-gray-700';
    }
  };

  const toggleExpandLog = (id: string) => {
    setExpandedLogId(expandedLogId === id ? null : id);
  };

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col h-full p-8 text-gray-200">
      
      {/* Header */}
      <div className="border-b border-[#111930] pb-6 mb-8">
        <h2 className="text-xl font-bold text-white font-sans flex items-center gap-2">
          <Database className="h-5.5 w-5.5 text-red-500" />
          UNIFIED TELEMETRY LOG EXPLORER
        </h2>
        <p className="text-xs text-gray-400 mt-1">Cross-correlated log aggregator gathering operating system, auth directories, and network layer packets.</p>
      </div>

      {/* Filter Toolbar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6 bg-[#090f20]/60 border border-[#172343] p-4 rounded-xl shadow-lg">
        {/* Query Input */}
        <div className="md:col-span-2 relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search by log content, hostname, account ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#050914] border border-[#1b274c] rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-red-500 transition-colors"
          />
        </div>

        {/* Source Dropdown */}
        <select
          value={selectedSource}
          onChange={(e) => setSelectedSource(e.target.value)}
          className="bg-[#050914] border border-[#1b274c] rounded-lg px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-red-500 font-sans"
        >
          <option value="ALL">All Sources</option>
          <option value="WINDOWS_EVENT_LOG">Windows Events</option>
          <option value="AUTH_SERVER">Active Directory</option>
          <option value="PROCESS_EXECUTION">Process Events</option>
          <option value="FIREWALL">Network Firewalls</option>
          <option value="ENDPOINT_TELEMETRY">Endpoint Tracing</option>
        </select>

        {/* Severity Dropdown */}
        <select
          value={selectedSeverity}
          onChange={(e) => setSelectedSeverity(e.target.value)}
          className="bg-[#050914] border border-[#1b274c] rounded-lg px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-red-500 font-sans"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical Only</option>
          <option value="ERROR">Errors & Above</option>
          <option value="WARNING">Warnings</option>
          <option value="INFO">Info</option>
        </select>
      </div>

      {/* Log Feed Table */}
      <div className="flex-1 overflow-y-auto border border-[#172343] rounded-xl bg-[#090f20] shadow-2xl flex flex-col">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="bg-[#0c1223] text-gray-400 uppercase text-[10px] tracking-wider font-mono border-b border-[#141f3d] sticky top-0 z-10">
              <tr>
                <th className="py-3.5 px-5"></th>
                <th className="py-3.5 px-4">Timestamp</th>
                <th className="py-3.5 px-4">Log Source</th>
                <th className="py-3.5 px-4">Host Device</th>
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-5">Event Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#101931] font-mono text-gray-300">
              {filteredLogs.map((log) => {
                const isExpanded = expandedLogId === log.id;
                return (
                  <React.Fragment key={log.id}>
                    <tr 
                      onClick={() => toggleExpandLog(log.id)}
                      className="hover:bg-[#111931] cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4 text-center">
                        {isExpanded ? <ChevronUp className="h-4 w-4 text-gray-500" /> : <ChevronDown className="h-4 w-4 text-gray-500" />}
                      </td>
                      <td className="py-3 px-4 text-gray-400 whitespace-nowrap">{new Date(log.timestamp).toLocaleTimeString()}</td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold border uppercase ${getSourceBadgeColor(log.source)}`}>
                          {log.source.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-white font-semibold whitespace-nowrap">{log.host}</td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold border uppercase ${getSeverityBadgeColor(log.severity)}`}>
                          {log.severity}
                        </span>
                      </td>
                      <td className="py-3 px-5 text-gray-200 font-sans font-medium line-clamp-1">{log.message}</td>
                    </tr>

                    {/* Expandable Technical JSON/Terminal properties */}
                    {isExpanded && (
                      <tr className="bg-[#050814]/80">
                        <td colSpan={6} className="p-6">
                          <div className="bg-[#02040b] border border-[#1b274c] rounded-lg p-5 font-mono text-xs text-gray-300 relative">
                            <div className="absolute right-4 top-4 text-[9px] uppercase tracking-widest text-red-500 font-bold bg-red-950/30 px-2 py-1 border border-red-800/40 rounded">
                              FORENSIC ARTIFACT RECORD
                            </div>
                            
                            <h4 className="text-white font-bold mb-3 border-b border-[#1b274c] pb-2 text-xs flex items-center gap-1.5 uppercase tracking-wide">
                              <Terminal className="h-4 w-4 text-red-500" />
                              System Decoded Metadata Details
                            </h4>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <p className="text-gray-500">Record ID: <span className="text-indigo-400 font-semibold">{log.id}</span></p>
                                <p className="text-gray-500 mt-1">Host Target: <span className="text-white">{log.host}</span></p>
                                {log.userId && <p className="text-gray-500 mt-1">Responsible Security User Account: <span className="text-emerald-400 font-bold">{log.userId}</span></p>}
                                <p className="text-gray-500 mt-1">Telemetry Origin: <span className="text-gray-300 font-semibold">{log.source}</span></p>
                              </div>

                              <div className="bg-[#0a1122] border border-[#1a2647] p-3.5 rounded">
                                <span className="text-gray-400 text-[10px] uppercase font-bold tracking-widest block mb-2 text-red-400">Environment Variables & Commands</span>
                                {log.details.commandLine ? (
                                  <div className="space-y-1">
                                    <p className="text-[10px] text-gray-500">EXEC CMD:</p>
                                    <code className="text-red-300 break-all text-[11px] block">{log.details.commandLine}</code>
                                    <p className="text-[10px] text-gray-500 mt-2">PROCESS BINARY: <span className="text-white">{log.details.processName}</span></p>
                                    <p className="text-[10px] text-gray-500">PATH: <span className="text-gray-400">{log.details.processPath}</span></p>
                                  </div>
                                ) : log.details.srcIp ? (
                                  <div className="text-[11px] space-y-1 text-gray-300">
                                    <p className="flex justify-between"><span>Source Socket:</span> <span className="text-white font-bold">{log.details.srcIp}:{log.details.srcPort}</span></p>
                                    <p className="flex justify-between"><span>Destination Socket:</span> <span className="text-white font-bold">{log.details.dstIp}:{log.details.dstPort}</span></p>
                                  </div>
                                ) : log.details.authStatus ? (
                                  <div className="text-[11px] space-y-1 text-gray-300">
                                    <p className="flex justify-between"><span>Authentication Attempt Result:</span> <span className="text-red-400 font-bold">{log.details.authStatus}</span></p>
                                  </div>
                                ) : (
                                  <span className="text-gray-600 italic">No structured command execution payloads registered.</span>
                                )}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}

              {filteredLogs.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-gray-500 font-sans">
                    No consolidated telemetry logs match the active query constraints.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
