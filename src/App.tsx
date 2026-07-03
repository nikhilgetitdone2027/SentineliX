/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import DashboardView from './components/DashboardView';
import AssetsView from './components/AssetsView';
import TelemetryLogsView from './components/TelemetryLogsView';
import IncidentsView from './components/IncidentsView';
import NetworkView from './components/NetworkView';
import MitreView from './components/MitreView';
import ThreatIntelView from './components/ThreatIntelView';
import PlaybookOrchestration from './components/PlaybookOrchestration';
import ResponseRecommendationsView from './components/ResponseRecommendationsView';
import CopilotView from './components/CopilotView';

import { 
  NetworkPacket, 
  DpiSessionFlow, 
  EntityBehaviorProfile, 
  UnifiedTelemetryLog, 
  SecurityIncident, 
  IncidentPlaybookRun 
} from './types';
import { Loader2, AlertCircle } from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  
  // App-level data models
  const [packets, setPackets] = useState<NetworkPacket[]>([]);
  const [flows, setFlows] = useState<DpiSessionFlow[]>([]);
  const [profiles, setProfiles] = useState<EntityBehaviorProfile[]>([]);
  const [logs, setLogs] = useState<UnifiedTelemetryLog[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [playbooks, setPlaybooks] = useState<IncidentPlaybookRun[]>([]);
  
  // Incident specific linkages
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [threatBlocked, setThreatBlocked] = useState<boolean>(false);

  // Connection and Loading States
  const [initialLoading, setInitialLoading] = useState<boolean>(true);
  const [apiError, setApiError] = useState<string | null>(null);

  // Authenticated analyst context for sidebar user card
  const currentUser = {
    fullName: 'Aniket Sharma',
    role: 'SECURITY_ANALYST' as const,
    department: 'COGNITIVE SOC'
  };

  // Poll server endpoints every 3 seconds to stay reactive to the simulation
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [
          resPackets, 
          resFlows, 
          resProfiles, 
          resIncidents, 
          resLogs, 
          resPlaybooks
        ] = await Promise.all([
          fetch('/api/packets'),
          fetch('/api/flows'),
          fetch('/api/behavior/profiles'),
          fetch('/api/incidents'),
          fetch('/api/logs'),
          fetch('/api/playbooks')
        ]);

        const [
          dataPackets, 
          dataFlows, 
          dataProfiles, 
          dataIncidents, 
          dataLogs, 
          dataPlaybooks
        ] = await Promise.all([
          resPackets.json(),
          resFlows.json(),
          resProfiles.json(),
          resIncidents.json(),
          resLogs.json(),
          resPlaybooks.json()
        ]);

        setPackets(dataPackets.packets || []);
        setFlows(dataFlows.flows || []);
        setProfiles(dataProfiles.profiles || []);
        setIncidents(dataIncidents.incidents || []);
        setLogs(dataLogs.logs || []);
        setPlaybooks(dataPlaybooks.playbooks || []);

        // Default set selected incident if none selected yet
        if (dataIncidents.incidents && dataIncidents.incidents.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(dataIncidents.incidents[0].id);
        }

        // Keep track of threat block status from active playbooks
        const hasActiveIsolation = (dataPlaybooks.playbooks || []).some(
          (r: IncidentPlaybookRun) => r.status === 'COMPLETED' && r.name.includes('Response ISOLATE_ENDPOINT')
        );
        if (hasActiveIsolation) {
          setThreatBlocked(true);
        }

        setApiError(null);
      } catch (err: any) {
        console.error('Failed to poll security data from Express backend:', err);
        setApiError(err?.message || 'Connection to SentinelX backend lost. Retrying...');
      } finally {
        setInitialLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, [selectedIncidentId]);

  // Integrated Playbook invocation action
  const handleTriggerPlaybook = async (actionType: string, target: string) => {
    try {
      const response = await fetch('/api/playbooks/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          actionType, 
          target, 
          incidentId: selectedIncidentId || 'inc-2026-001' 
        }),
      });
      const data = await response.json();
      const runData = data.playbookRun || data.run;
      if (runData) {
        setPlaybooks(prev => [runData, ...prev]);
        if (actionType === 'ISOLATE_ENDPOINT') {
          setThreatBlocked(true);
        }
        setCurrentTab('playbooks');
      }
    } catch (err) {
      console.error('Failed to trigger responsive playbook command:', err);
    }
  };

  const handleInspectPacket = (pkt: NetworkPacket) => {
    console.log('Inspecting packet payloads:', pkt);
  };

  const handleLogout = () => {
    console.log('User signed out from security console.');
  };

  // Render sub-view components dynamically based on Sidebar selection
  const renderViewContent = () => {
    switch (currentTab) {
      case 'dashboard':
        return (
          <DashboardView 
            packets={packets} 
            flows={flows} 
            incidents={incidents}
            profiles={profiles}
            onInspectPacket={handleInspectPacket}
            setCurrentTab={setCurrentTab}
          />
        );
      case 'assets':
        return (
          <AssetsView 
            profiles={profiles} 
            onTriggerPlaybook={handleTriggerPlaybook} 
          />
        );
      case 'alerts':
        return <TelemetryLogsView logs={logs} />;
      case 'incidents':
        return (
          <IncidentsView 
            incidents={incidents} 
            onTriggerPlaybook={handleTriggerPlaybook} 
            selectedIncidentId={selectedIncidentId}
            setSelectedIncidentId={setSelectedIncidentId}
          />
        );
      case 'network':
        return (
          <NetworkView 
            flows={flows} 
            threatBlocked={threatBlocked} 
          />
        );
      case 'mitre':
        return <MitreView incidents={incidents} />;
      case 'intel':
        return <ThreatIntelView />;
      case 'playbooks':
        return (
          <PlaybookOrchestration 
            playbookRuns={playbooks} 
            onTriggerPlaybook={handleTriggerPlaybook} 
          />
        );
      case 'recommendations':
        return (
          <ResponseRecommendationsView 
            incidents={incidents} 
            onTriggerPlaybook={handleTriggerPlaybook} 
          />
        );
      case 'copilot':
        return (
          <CopilotView 
            incidents={incidents} 
            initialIncidentId={selectedIncidentId} 
          />
        );
      default:
        return (
          <div className="flex-1 flex items-center justify-center text-gray-500 font-sans">
            Under Construction: View screen not available.
          </div>
        );
    }
  };

  // Counts of open security cases
  const openIncidentsCount = incidents.filter(i => i.status !== 'RESOLVED').length;

  if (initialLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-screen w-screen bg-[#02050c] text-gray-100 font-sans p-6">
        <div className="p-8 max-w-sm w-full bg-[#070c1b] border border-[#142247] rounded-2xl shadow-2xl text-center space-y-6">
          <div className="relative flex justify-center">
            <div className="absolute inset-0 m-auto h-16 w-16 bg-red-500/10 rounded-full animate-ping"></div>
            <div className="h-16 w-16 bg-gradient-to-tr from-red-600 to-amber-500 rounded-full flex items-center justify-center shadow-lg shadow-red-950/40 relative">
              <Loader2 className="h-8 w-8 text-white animate-spin" />
            </div>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-bold uppercase tracking-widest text-white">Initializing SentinelX</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Synchronizing behavioral profiles, telemetry loggers, and deep packet buffers...
            </p>
          </div>
          <div className="h-1 w-full bg-[#030712] rounded-full overflow-hidden">
            <div className="h-full bg-gradient-to-r from-red-600 to-amber-500 rounded-full animate-pulse" style={{ width: '80%' }}></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#02050c] text-gray-100 font-sans antialiased">
      {/* Sidebar Navigation */}
      <Sidebar 
        currentTab={currentTab} 
        setCurrentTab={setCurrentTab} 
        openIncidentsCount={openIncidentsCount}
        user={currentUser}
        onLogout={handleLogout}
      />

      {/* Main Panel Area */}
      <main className="flex-1 overflow-hidden flex flex-col h-full bg-[#030712]">
        {apiError && (
          <div className="bg-red-950/80 border-b border-red-800/80 text-red-200 px-6 py-2.5 text-xs font-mono flex items-center gap-2.5 shrink-0 animate-pulse">
            <AlertCircle className="h-4.5 w-4.5 text-red-400 shrink-0" />
            <span>⚠️ <strong>SUB-SYSTEM OFFLINE:</strong> {apiError}</span>
          </div>
        )}
        {renderViewContent()}
      </main>
    </div>
  );
}
