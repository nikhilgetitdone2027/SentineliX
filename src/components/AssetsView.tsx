/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  Cpu, 
  User, 
  Server, 
  ShieldAlert, 
  Clock, 
  Zap, 
  Activity, 
  Layers, 
  ChevronRight,
  Sparkles,
  Search,
  Filter,
  Terminal
} from 'lucide-react';
import { EntityBehaviorProfile, EntityType } from '../types.js';

interface AssetsViewProps {
  profiles: EntityBehaviorProfile[];
  onTriggerPlaybook: (actionType: string, target: string) => void;
}

export default function AssetsView({ profiles, onTriggerPlaybook }: AssetsViewProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(profiles[0]?.entityId || null);
  const [filterType, setFilterType] = useState<string>('ALL');

  const selectedProfile = profiles.find(p => p.entityId === selectedProfileId);

  const filteredProfiles = profiles.filter(p => {
    const matchesSearch = p.entityName.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          p.entityId.includes(searchTerm);
    const matchesFilter = filterType === 'ALL' || p.entityType === filterType;
    return matchesSearch && matchesFilter;
  });

  const getEntityIcon = (type: EntityType) => {
    switch (type) {
      case 'SERVER': return <Server className="h-5 w-5 text-indigo-400" />;
      case 'USER': return <User className="h-5 w-5 text-emerald-400" />;
      default: return <Cpu className="h-5 w-5 text-blue-400" />;
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'text-red-500 border-red-800 bg-red-950/40';
      case 'HIGH': return 'text-amber-500 border-amber-800 bg-amber-950/40';
      case 'MEDIUM': return 'text-yellow-500 border-yellow-800 bg-yellow-950/40';
      default: return 'text-emerald-500 border-emerald-800 bg-emerald-950/40';
    }
  };

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col md:flex-row h-full">
      
      {/* Left Pane: Asset list */}
      <div className="w-full md:w-1/2 border-r border-[#131d38] flex flex-col h-full bg-[#030712]">
        
        {/* Filter Header */}
        <div className="p-6 border-b border-[#131d38] bg-[#070c1b]/60">
          <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans mb-4 flex items-center gap-2">
            <Activity className="h-5 w-5 text-red-500" />
            Behavioral Anomaly Monitoring
          </h3>

          <div className="flex space-x-3">
            {/* Search */}
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search by IP, asset name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-[#0a0f1d] border border-[#1b274c] rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-red-500 transition-colors"
              />
            </div>
            
            {/* Filter */}
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-[#0a0f1d] border border-[#1b274c] rounded-lg px-3 py-2 text-xs text-gray-300 focus:outline-none focus:border-red-500 font-sans"
            >
              <option value="ALL">All Categories</option>
              <option value="SERVER">Servers</option>
              <option value="DEVICE">Workstations</option>
              <option value="USER">User Logins</option>
            </select>
          </div>
        </div>

        {/* Assets List Scroll */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#101931]">
          {filteredProfiles.map((prof) => {
            const isSelected = selectedProfileId === prof.entityId;
            return (
              <div 
                key={prof.entityId}
                onClick={() => setSelectedProfileId(prof.entityId)}
                className={`p-5 flex items-center justify-between cursor-pointer transition-all ${
                  isSelected ? 'bg-[#0f1936] border-l-4 border-red-500' : 'hover:bg-[#070b16]'
                }`}
              >
                <div className="flex items-center space-x-4 min-w-0">
                  <div className="p-2.5 bg-[#0a0f21] border border-[#18264e] rounded-lg shadow-inner">
                    {getEntityIcon(prof.entityType)}
                  </div>
                  <div className="min-w-0">
                    <h4 className="text-xs font-bold text-white truncate font-sans">{prof.entityName}</h4>
                    <p className="text-[10px] text-gray-400 font-mono mt-0.5">{prof.entityId}</p>
                    <p className="text-[9px] text-gray-500 font-sans">{prof.department || 'Infrastructure'}</p>
                  </div>
                </div>

                <div className="flex items-center space-x-4">
                  <div className="text-right">
                    <div className="text-xs font-bold font-mono text-white">{Math.round(prof.anomalyScores.ensembleScore * 100)}%</div>
                    <div className="text-[8px] text-gray-500 uppercase tracking-widest font-mono">ANOMALY INDEX</div>
                  </div>
                  <span className={`inline-flex items-center px-2 py-0.5 text-[9px] font-bold rounded border uppercase font-mono ${getRiskColor(prof.riskLevel)}`}>
                    {prof.riskLevel}
                  </span>
                  <ChevronRight className="h-4 w-4 text-gray-500" />
                </div>
              </div>
            );
          })}

          {filteredProfiles.length === 0 && (
            <div className="p-10 text-center text-gray-500 font-sans">
              No behavioral profiles match the search filters.
            </div>
          )}
        </div>
      </div>

      {/* Right Pane: Core Baseline & ML Diagnostics */}
      <div className="w-full md:w-1/2 flex flex-col h-full bg-[#040918] overflow-y-auto">
        {selectedProfile ? (
          <div className="p-8">
            {/* Header Entity Block */}
            <div className="flex items-start justify-between border-b border-[#131d38] pb-6 mb-6">
              <div>
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold bg-[#131f3f] text-blue-400 border border-blue-800 font-mono uppercase mb-2">
                  {selectedProfile.entityType} PROFILE
                </span>
                <h3 className="text-lg font-bold text-white font-sans">{selectedProfile.entityName}</h3>
                <p className="text-xs text-gray-400 font-mono mt-1">IPV4: {selectedProfile.entityId}</p>
              </div>

              <div className="text-right">
                <div className="text-3xl font-extrabold text-red-500 font-mono">{selectedProfile.riskScore}</div>
                <div className="text-[9px] text-gray-400 uppercase tracking-widest font-mono mt-1">OVERALL RISK SCORE</div>
              </div>
            </div>

            {/* AI Multi-Model Diagnostic Engine Scores */}
            <div className="mb-8">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-sans mb-4 flex items-center gap-1.5">
                <Sparkles className="h-4 w-4 text-red-500 animate-pulse" />
                Multi-Stage Behavioral AI Engine Outputs
              </h4>

              <div className="grid grid-cols-3 gap-4">
                
                {/* Score 1: Isolation Forest */}
                <div className="bg-[#090f20] border border-[#172343] rounded-lg p-3.5 text-center shadow-inner">
                  <div className="text-xs text-gray-400 font-sans">Isolation Forest</div>
                  <div className="text-lg font-extrabold text-white font-mono mt-2">{selectedProfile.anomalyScores.isolationForest.toFixed(2)}</div>
                  <div className="text-[8px] text-gray-500 font-mono uppercase mt-1">Density Outliers</div>
                </div>

                {/* Score 2: Autoencoder */}
                <div className="bg-[#090f20] border border-[#172343] rounded-lg p-3.5 text-center shadow-inner">
                  <div className="text-xs text-gray-400 font-sans">Autoencoder</div>
                  <div className="text-lg font-extrabold text-white font-mono mt-2">{selectedProfile.anomalyScores.autoencoder.toFixed(2)}</div>
                  <div className="text-[8px] text-gray-500 font-mono uppercase mt-1">Reconstruction Error</div>
                </div>

                {/* Score 3: LOF */}
                <div className="bg-[#090f20] border border-[#172343] rounded-lg p-3.5 text-center shadow-inner">
                  <div className="text-xs text-gray-400 font-sans">LOF</div>
                  <div className="text-lg font-extrabold text-white font-mono mt-2">{selectedProfile.anomalyScores.lof.toFixed(2)}</div>
                  <div className="text-[8px] text-gray-500 font-mono uppercase mt-1">Local Spacing</div>
                </div>

              </div>
            </div>

            {/* Explainability Panel */}
            <div className="bg-red-950/15 border border-red-900/30 rounded-xl p-5 mb-8">
              <h4 className="text-xs font-bold text-red-400 uppercase tracking-wider font-sans mb-3 flex items-center gap-1.5">
                <ShieldAlert className="h-4.5 w-4.5" />
                AI Explainability Factors (Anomaly Reasons)
              </h4>
              <ul className="space-y-2 text-xs font-mono text-gray-300">
                {selectedProfile.explainability.map((exp, idx) => (
                  <li key={idx} className="flex items-start space-x-2">
                    <span className="text-red-500 mt-0.5">•</span>
                    <span>{exp}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Baseline comparison split */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8 text-xs">
              
              {/* Historical Baseline */}
              <div className="bg-[#070b15] border border-[#131d38] rounded-xl p-4.5">
                <h5 className="font-bold text-gray-300 border-b border-[#131d38] pb-2 mb-3 uppercase font-sans tracking-wide">Historical Baseline</h5>
                <div className="space-y-2 font-mono text-gray-400">
                  <div className="flex justify-between">
                    <span>Packet Rate (avg):</span>
                    <span className="text-white">{selectedProfile.baseline.avgPacketRate} PPS</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Peak Hours:</span>
                    <span className="text-white">{selectedProfile.baseline.peakActivityHours.slice(0, 3).join(', ')}...</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Payload Entropy (avg):</span>
                    <span className="text-white">{selectedProfile.baseline.averageDataEntropy.toFixed(1)} bits</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Unique Port Baseline:</span>
                    <span className="text-white">{selectedProfile.baseline.uniqueDestinationPortCount} ports</span>
                  </div>
                </div>
              </div>

              {/* Current Sliding Window Activity */}
              <div className="bg-[#070b15] border border-[#131d38] rounded-xl p-4.5">
                <h5 className="font-bold text-gray-300 border-b border-[#131d38] pb-2 mb-3 uppercase font-sans tracking-wide">Sliding-Window Stats</h5>
                <div className="space-y-2 font-mono text-gray-400">
                  <div className="flex justify-between">
                    <span>Packet Rate (curr):</span>
                    <span className={`font-bold ${selectedProfile.currentActivity.packetRate > selectedProfile.baseline.avgPacketRate * 2 ? 'text-red-400' : 'text-white'}`}>
                      {selectedProfile.currentActivity.packetRate} PPS
                    </span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span>Protocols Active:</span>
                    <span className="text-white">{selectedProfile.currentActivity.activeProtocols.join(', ')}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Entropy Index:</span>
                    <span className={`font-bold ${selectedProfile.currentActivity.dataEntropy > 7.0 ? 'text-red-400' : 'text-white'}`}>
                      {selectedProfile.currentActivity.dataEntropy.toFixed(2)} bits
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Ports Queried:</span>
                    <span className="text-white">{selectedProfile.currentActivity.destinationPortsVisited.join(', ')}</span>
                  </div>
                </div>
              </div>

            </div>

            {/* Playbooks containment shortcuts */}
            {selectedProfile.riskLevel === 'CRITICAL' && (
              <div className="border-t border-[#131d38] pt-6">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider font-sans mb-3">Instant Containment Actions</h4>
                <div className="flex flex-col sm:flex-row gap-3">
                  <button 
                    onClick={() => onTriggerPlaybook('ISOLATE_ENDPOINT', selectedProfile.entityId)}
                    className="flex-1 flex items-center justify-center space-x-2 bg-red-900/30 border border-red-700/80 hover:bg-red-800/40 text-red-300 rounded-lg py-2.5 text-xs font-mono font-bold transition-all"
                  >
                    <Terminal className="h-4 w-4" />
                    <span>ISOLATE HOST INTERFACE</span>
                  </button>
                  <button 
                    onClick={() => onTriggerPlaybook('DISABLE_USER', 'svc_sync_finance')}
                    className="flex-1 flex items-center justify-center space-x-2 bg-amber-900/30 border border-amber-700/80 hover:bg-amber-800/40 text-amber-300 rounded-lg py-2.5 text-xs font-mono font-bold transition-all"
                  >
                    <User className="h-4 w-4" />
                    <span>LOCK ACTIVE AD USER</span>
                  </button>
                </div>
              </div>
            )}

          </div>
        ) : (
          <div className="m-auto text-gray-500 font-sans">
            Select an asset profile to view ML logs and explainability diagnostics.
          </div>
        )}
      </div>

    </div>
  );
}
