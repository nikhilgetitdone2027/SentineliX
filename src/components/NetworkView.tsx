/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  Network, 
  Server, 
  Cpu, 
  ShieldAlert, 
  ExternalLink,
  Lock,
  Globe,
  Radio,
  Clock,
  Info
} from 'lucide-react';
import { DpiSessionFlow } from '../types.js';

interface NetworkViewProps {
  flows: DpiSessionFlow[];
  threatBlocked: boolean;
}

interface Node {
  id: string;
  label: string;
  ip: string;
  type: 'SERVER' | 'DEVICE' | 'GATEWAY' | 'EXTERNAL';
  x: number;
  y: number;
}

export default function NetworkView({ flows, threatBlocked }: NetworkViewProps) {
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  // High-fidelity absolute coordinates for our SVG topology layout
  const nodes: Node[] = [
    { id: 'gw', label: 'Core Firewall Gateway', ip: '192.168.1.1', type: 'GATEWAY', x: 400, y: 150 },
    { id: 'ad', label: 'Active Directory Controller', ip: '10.0.50.10', type: 'SERVER', x: 250, y: 320 },
    { id: 'db', label: 'Financial Transaction DB', ip: '10.0.50.25', type: 'SERVER', x: 550, y: 320 },
    { id: 'eng1', label: 'Engineering Workstation 01', ip: '10.0.60.100', type: 'DEVICE', x: 200, y: 500 },
    { id: 'eng2', label: 'Engineering Workstation 02', ip: '10.0.60.101', type: 'DEVICE', x: 600, y: 500 },
    { id: 'ext', label: 'External Onion Node (Tor)', ip: '185.220.101.43', type: 'EXTERNAL', x: 400, y: 40 }
  ];

  // Map of active link relationships with custom stroke properties
  const links = [
    { from: 'ad', to: 'gw', label: 'LDAP / DNS queries' },
    { from: 'db', to: 'gw', label: 'SQL Backup sync' },
    { from: 'eng1', to: 'ad', label: 'Kerberos tickets' },
    { from: 'eng1', to: 'db', label: 'Query session' },
    { from: 'eng2', to: 'ad', label: 'AD Directory Sync' },
    { from: 'eng2', to: 'gw', label: 'Web traffic' },
    { from: 'eng1', to: 'ext', label: 'C2 TLS tunnel exfiltration', isThreat: true },
    { from: 'gw', to: 'ext', label: 'External Egress' }
  ];

  const getNodeColor = (type: string, ip: string) => {
    if (ip === '10.0.60.100') return !threatBlocked ? 'stroke-red-500 fill-red-950/40 text-red-400' : 'stroke-amber-500 fill-amber-950/20 text-amber-500';
    if (ip === '185.220.101.43') return !threatBlocked ? 'stroke-red-500 fill-red-950/30 text-red-500' : 'stroke-gray-600 fill-gray-900/40 text-gray-600';
    
    switch (type) {
      case 'SERVER': return 'stroke-indigo-500 fill-indigo-950/20 text-indigo-400';
      case 'GATEWAY': return 'stroke-blue-500 fill-blue-950/20 text-blue-400';
      default: return 'stroke-emerald-400 fill-emerald-950/20 text-emerald-400';
    }
  };

  const getFlowNodeCount = (ip: string) => {
    return flows.filter(f => f.srcIp === ip || f.dstIp === ip).length;
  };

  return (
    <div className="flex-1 overflow-hidden bg-[#030712] flex flex-col md:flex-row h-full">
      
      {/* Left Topolgoy Canvas View */}
      <div className="w-full md:w-3/5 flex flex-col h-full bg-[#030712] relative select-none">
        <div className="p-6 border-b border-[#111930] bg-[#070c1b]/40 flex justify-between items-center z-10">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans flex items-center gap-2">
              <Radio className="h-4.5 w-4.5 text-indigo-500 animate-pulse" />
              Operational Network Topology View
            </h3>
            <p className="text-[10px] text-gray-400">Dynamic session stream showing active connections, handshakes, and blocked egress nodes.</p>
          </div>
          <div className="flex space-x-4 text-[9px] font-mono">
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> NORMAL FLOW</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> DETECTED THREAT</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-gray-600"></span> BLOCKED ADVERSARY</span>
          </div>
        </div>

        {/* Real Dynamic Graph Container */}
        <div className="flex-1 relative flex items-center justify-center p-8">
          <svg viewBox="0 0 800 600" className="w-full h-full max-w-[700px] overflow-visible">
            
            {/* Draw Links/Connectors */}
            {links.map((link, idx) => {
              const sourceNode = nodes.find(n => n.id === link.from);
              const targetNode = nodes.find(n => n.id === link.to);
              if (!sourceNode || !targetNode) return null;

              const isThreatLink = link.isThreat;
              let isAnimate = false;
              let strokeColor = 'stroke-indigo-900/60';
              let dashArray = 'none';

              if (isThreatLink) {
                if (!threatBlocked) {
                  strokeColor = 'stroke-red-500/80';
                  dashArray = '5, 5';
                  isAnimate = true;
                } else {
                  strokeColor = 'stroke-gray-800';
                  dashArray = '5, 5';
                }
              } else {
                // Determine if there is active traffic flow between these nodes
                const hasFlow = flows.some(f => 
                  (f.srcIp === sourceNode.ip && f.dstIp === targetNode.ip) ||
                  (f.srcIp === targetNode.ip && f.dstIp === sourceNode.ip)
                );
                if (hasFlow) {
                  strokeColor = 'stroke-emerald-500/60';
                  dashArray = '5, 5';
                  isAnimate = true;
                }
              }

              return (
                <g key={idx}>
                  {/* Outer glow lane */}
                  <line 
                    x1={sourceNode.x} 
                    y1={sourceNode.y} 
                    x2={targetNode.x} 
                    y2={targetNode.y} 
                    className={`${strokeColor}`}
                    strokeWidth={isThreatLink && !threatBlocked ? '3.5' : '1.5'}
                  />
                  
                  {/* Dynamic animating moving signal dots */}
                  {isAnimate && (
                    <line 
                      x1={sourceNode.x} 
                      y1={sourceNode.y} 
                      x2={targetNode.x} 
                      y2={targetNode.y} 
                      stroke={isThreatLink ? '#ef4444' : '#10b981'}
                      strokeWidth="2.5"
                      strokeDasharray={dashArray}
                      className="animate-dash"
                      style={{
                        animation: 'dash 1.2s linear infinite',
                        strokeDashoffset: isThreatLink ? -20 : 20
                      }}
                    />
                  )}
                </g>
              );
            })}

            {/* Draw Nodes */}
            {nodes.map((node) => {
              const nodeColorClasses = getNodeColor(node.type, node.ip);
              const isSelected = selectedNode?.id === node.id;
              
              let NodeIcon = Cpu;
              if (node.type === 'SERVER') NodeIcon = Server;
              if (node.type === 'GATEWAY') NodeIcon = Lock;
              if (node.type === 'EXTERNAL') NodeIcon = Globe;

              return (
                <g 
                  key={node.id} 
                  transform={`translate(${node.x},${node.y})`}
                  className="cursor-pointer group"
                  onClick={() => setSelectedNode(node)}
                >
                  {/* Radial glow around selected node */}
                  {isSelected && (
                    <circle r="36" className="fill-none stroke-red-500/50 stroke-[2px] animate-ping" />
                  )}

                  <circle 
                    r="25" 
                    className={`stroke-[2.5px] transition-all duration-150 ${nodeColorClasses} ${
                      isSelected ? 'stroke-[3.5px] scale-110 shadow-lg' : 'hover:scale-105'
                    }`} 
                  />

                  {/* Icon centering */}
                  <foreignObject x="-11" y="-11" width="22" height="22" className="pointer-events-none select-none">
                    <div className="flex items-center justify-center h-full w-full">
                      <NodeIcon className={`h-4.5 w-4.5 ${nodeColorClasses.split(' ').pop()}`} />
                    </div>
                  </foreignObject>

                  {/* Human Labels */}
                  <text 
                    y="42" 
                    textAnchor="middle" 
                    className="fill-white font-sans text-[10px] font-bold tracking-tight pointer-events-none select-none"
                  >
                    {node.label}
                  </text>
                  <text 
                    y="54" 
                    textAnchor="middle" 
                    className="fill-gray-500 font-mono text-[9px] pointer-events-none select-none"
                  >
                    {node.ip}
                  </text>
                </g>
              );
            })}

          </svg>
          
          <style>{`
            @keyframes dash {
              to {
                stroke-dashoffset: -40;
              }
            }
          `}</style>
        </div>
      </div>

      {/* Right Properties Panel */}
      <div className="w-full md:w-2/5 flex flex-col h-full bg-[#040918] border-l border-[#131d38] overflow-y-auto">
        {selectedNode ? (
          <div className="p-8">
            <div className="border-b border-[#131d38] pb-6 mb-6">
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[8px] font-bold bg-[#131f3f] text-indigo-400 border border-indigo-800 font-mono uppercase mb-2">
                NODE METADATA RECORDS
              </span>
              <h3 className="text-base font-bold text-white font-sans">{selectedNode.label}</h3>
              <p className="text-xs text-gray-400 font-mono mt-1">IPV4 ADDR: {selectedNode.ip}</p>
            </div>

            {/* Dynamic sockets table */}
            <div className="mb-6">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-sans mb-3 flex items-center gap-1.5">
                <Clock className="h-4 w-4 text-red-500" />
                Active Sockets & Sessions
              </h4>

              <div className="space-y-3 font-mono text-xs text-gray-300">
                <div className="bg-[#090f20] border border-[#172343] p-3 rounded">
                  <p className="text-[10px] text-gray-500">SESSION CHANNELS ACTIVE</p>
                  <p className="text-xl font-bold text-white mt-1">{getFlowNodeCount(selectedNode.ip)}</p>
                </div>

                {selectedNode.ip === '10.0.60.100' && !threatBlocked && (
                  <div className="bg-red-950/20 border border-red-900/40 p-4.5 rounded-lg flex items-start space-x-3.5">
                    <ShieldAlert className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5 animate-pulse" />
                    <div>
                      <p className="font-bold text-red-400 uppercase text-[10px]">Critical Security Warning</p>
                      <p className="text-[11px] text-gray-300 mt-1">Host exhibits high egress throughput and is actively tunneling data into raw Tor exit node \`185.220.101.43\`. Establish playbook isolation immediately.</p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Host info logs */}
            <div className="border-t border-[#131d38] pt-6">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider font-sans mb-3">Subnet Topology Notes</h4>
              <div className="bg-[#050914] border border-[#172242] p-4 rounded-lg text-xs font-sans text-gray-400 leading-relaxed font-medium">
                {selectedNode.type === 'GATEWAY' && 'This gateway router marks the boundaries between internal corporate departments (10.0.x.x) and external ISP endpoints. It decodes and handles standard stateful ingress filtering logs.'}
                {selectedNode.type === 'SERVER' && 'This is an internal core virtual directory server. Its behavioral baseline is highly strict, only allowing designated cross-subnet administration and SQL traffic.'}
                {selectedNode.type === 'DEVICE' && 'This is a corporate enterprise workstation assigned to a member of the local engineering team. It maintains browser TLS, SMTP email clients, and internal domain lookups.'}
                {selectedNode.type === 'EXTERNAL' && 'This represents an unverified IP located beyond our network boundary. Flows directed here are scrutinized for protocol anomalies and payload randomness ratios.'}
              </div>
            </div>

          </div>
        ) : (
          <div className="m-auto text-gray-500 font-sans p-8 text-center flex flex-col items-center justify-center gap-3">
            <Info className="h-8 w-8 text-indigo-500 opacity-60 animate-bounce" />
            <p className="text-xs max-w-xs leading-relaxed">Select any active machine node or session connector on the topology graph to inspect live socket bindings and threat diagnostics.</p>
          </div>
        )}
      </div>

    </div>
  );
}
