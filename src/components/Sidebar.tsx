/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Database, 
  Terminal, 
  Cpu, 
  Network, 
  Search, 
  Grid, 
  LogOut,
  Sliders,
  AlertOctagon,
  Sparkles
} from 'lucide-react';
import { UserRole } from '../types.js';

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  openIncidentsCount: number;
  user: { fullName: string; role: UserRole; department: string } | null;
  onLogout: () => void;
}

export default function Sidebar({ 
  currentTab, 
  setCurrentTab, 
  openIncidentsCount, 
  user,
  onLogout 
}: SidebarProps) {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
    { id: 'assets', label: 'Assets & Behavioral AI', icon: Cpu },
    { id: 'alerts', label: 'Telemetry & Logs', icon: Database },
    { id: 'incidents', label: 'Incident Room', icon: AlertOctagon, badge: openIncidentsCount },
    { id: 'network', label: 'Network Topology', icon: Network },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Grid },
    { id: 'playbooks', label: 'Response Engine', icon: Terminal },
    { id: 'recommendations', label: 'Response Recommendations', icon: Sliders },
    { id: 'intel', label: 'Threat Intelligence (RAG)', icon: Search },
    { id: 'copilot', label: 'AI SOC Copilot', icon: Sparkles, highlight: true },
  ];

  return (
    <aside className="w-68 bg-[#0a0f1d] border-r border-[#1a243d] flex flex-col justify-between h-full text-gray-300">
      {/* Brand Header */}
      <div>
        <div className="p-6 border-b border-[#1a243d] flex items-center space-x-3 bg-gradient-to-r from-[#0d162d] to-[#0a0f1d]">
          <div className="p-2 bg-gradient-to-br from-red-600 to-amber-600 rounded-lg shadow-lg shadow-red-900/20">
            <ShieldAlert className="h-6 w-6 text-white animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white font-sans">SENTINELX <span className="text-xs text-red-500 font-mono">AI</span></h1>
            <p className="text-[10px] text-gray-400 uppercase tracking-widest font-mono">Cyber Resilience</p>
          </div>
        </div>

        {/* User Card */}
        {user && (
          <div className="p-4 mx-3 my-4 bg-[#111931]/60 border border-[#1b274c]/80 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-[#1e293b] to-red-950/40 border border-red-500/30 flex items-center justify-center text-red-400 font-semibold text-sm">
                AS
              </div>
              <div className="overflow-hidden">
                <h4 className="text-xs font-semibold text-white truncate font-sans">{user.fullName}</h4>
                <p className="text-[10px] text-red-400 font-mono truncate">{user.role}</p>
                <p className="text-[9px] text-gray-500 truncate">{user.department}</p>
              </div>
            </div>
            <div className="mt-2 pt-2 border-t border-[#1b274c] flex items-center justify-between">
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-medium bg-red-950/60 border border-red-800/50 text-red-400 font-mono uppercase">
                CLEARANCE: TS-SCI
              </span>
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
            </div>
          </div>
        )}

        {/* Navigation Menu */}
        <nav className="px-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            
            return (
              <button
                key={item.id}
                onClick={() => setCurrentTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-150 ${
                  isActive 
                    ? 'bg-[#18254c] text-white shadow-inner shadow-indigo-950/30 border-l-2 border-red-500' 
                    : item.highlight
                      ? 'text-amber-400 hover:bg-[#121c38] bg-amber-950/10 hover:text-amber-300'
                      : 'text-gray-400 hover:bg-[#10172d] hover:text-white'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`h-4.5 w-4.5 ${isActive ? 'text-red-400' : item.highlight ? 'text-amber-400 animate-pulse' : 'text-gray-400'}`} />
                  <span className="font-sans font-medium">{item.label}</span>
                </div>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className="px-1.5 py-0.5 text-[9px] font-bold bg-red-600 border border-red-500 text-white rounded-full font-mono animate-bounce">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Controls */}
      <div className="p-4 border-t border-[#1a243d] bg-[#070b15]">
        <button 
          onClick={onLogout}
          className="w-full flex items-center justify-between px-3 py-2 text-xs font-semibold text-gray-500 hover:text-red-400 hover:bg-red-950/10 rounded-md transition-colors"
        >
          <span className="font-sans font-semibold">Terminate Session</span>
          <LogOut className="h-4 w-4" />
        </button>
        <p className="mt-2 text-[9px] text-gray-600 text-center font-mono uppercase tracking-widest">SENTINELX ENGINE v2.6.4</p>
      </div>
    </aside>
  );
}
