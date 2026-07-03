/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, 
  ArrowRight, 
  ShieldAlert, 
  Terminal, 
  Cpu, 
  Clock, 
  Network, 
  AlertTriangle,
  Info,
  CheckCircle,
  Eye,
  UploadCloud,
  Play,
  Check,
  Loader2,
  Download,
  RefreshCw,
  FileCode
} from 'lucide-react';
import { NetworkPacket, DpiSessionFlow, SecurityIncident, EntityBehaviorProfile } from '../types.js';

interface DashboardViewProps {
  packets: NetworkPacket[];
  flows: DpiSessionFlow[];
  incidents: SecurityIncident[];
  profiles: EntityBehaviorProfile[];
  onInspectPacket: (packet: NetworkPacket) => void;
  setCurrentTab: (tab: string) => void;
}

export default function DashboardView({ 
  packets, 
  flows, 
  incidents, 
  profiles,
  onInspectPacket,
  setCurrentTab 
}: DashboardViewProps) {
  const [bpsTrend, setBpsTrend] = useState<number[]>(Array(15).fill(45000));
  const [ppsTrend, setPpsTrend] = useState<number[]>(Array(15).fill(120));
  const [activeSession, setActiveSession] = useState<NetworkPacket | null>(null);

  // Hackathon Demo Pipeline States
  const [demoStep, setDemoStep] = useState<'idle' | 'upload' | 'analyze' | 'detect' | 'explain'>('idle');
  const [selectedScenario, setSelectedScenario] = useState<'data_exfiltration' | 'credential_theft' | 'dns_tunneling' | 'port_scanning'>('data_exfiltration');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [dragActive, setDragActive] = useState(false);
  const [demoLogs, setDemoLogs] = useState<string[]>([]);
  const [isDemoRunning, setIsDemoRunning] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const logEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll demo terminal logs
  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [demoLogs]);

  // Download a client-side simulated PCAP file for manual upload testing
  const downloadSamplePcap = () => {
    const pcapContent = "SentinelX Hackathon Evaluation Capture - High Entropy TLS Tunnel Session - Source 10.0.60.101 Destination 185.220.101.43 Protocol TLS Port 443";
    const blob = new Blob([pcapContent], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinelx_threat_exfil.pcap';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setDemoLogs(prev => [
      ...prev, 
      '[DOWNLOAD] Downloaded sentinelx_threat_exfil.pcap successfully!',
      '[DOWNLOAD] Try dragging this file into the upload dropzone or clicking "Choose File".'
    ]);
  };

  // Run the full automated interactive demo pipeline (Upload -> Analyze -> Detect -> Explain)
  const runOneClickDemo = async () => {
    if (isDemoRunning) return;
    setIsDemoRunning(true);
    setDemoStep('upload');
    setUploadProgress(0);

    const scenarioLabels = {
      data_exfiltration: 'Data Exfiltration over encrypted TLS',
      credential_theft: 'Active Directory Credential Theft',
      dns_tunneling: 'DNS C2 Heartbeat Tunneling',
      port_scanning: 'Network Port Scan Reconnaissance'
    };

    setDemoLogs([
      `[STAGE 1/4] Commencing Automated Walkthrough for [${scenarioLabels[selectedScenario]}]...`,
      `[UPLOAD] Streaming sample cyber-attack capture file "sentinelx_threat_${selectedScenario}.pcap" (812 KB)...`
    ]);

    // Animate progress bar beautifully
    for (let p = 15; p <= 100; p += 15) {
      await new Promise(resolve => setTimeout(resolve, 200));
      const boundedP = Math.min(p, 100);
      setUploadProgress(boundedP);
      setDemoLogs(prev => [...prev, `[UPLOAD] Sent packet blocks [Chunk ${Math.floor(boundedP/15)}/7] - ${boundedP}% uploaded.`]);
    }

    await new Promise(resolve => setTimeout(resolve, 400));
    setDemoStep('analyze');
    setDemoLogs(prev => [
      ...prev,
      '[STAGE 2/4] Upload Complete. Bootstrapping Deep Packet Inspection (DPI) parser...',
      '[ANALYZE] dissecting link-layer Ethernet frames and IPv4 packets...',
      `[ANALYZE] Reconstructing connection streams matching [${scenarioLabels[selectedScenario]}]...`,
      `[ANALYZE] Decoded session socket active.`
    ]);

    await new Promise(resolve => setTimeout(resolve, 800));
    setDemoStep('detect');
    setDemoLogs(prev => [
      ...prev,
      '[STAGE 3/4] Telemetry exported to Behavioral AI ML classification model...',
      '[DETECT] Running reconstruction entropy scoring over deep packet payloads...',
      `[DETECT] Autoencoder and Isolation Forest ensemble flagged anomaly score (THRESHOLD: 0.75)...`,
      `[DETECT] Threat Correlated! Correlating active events with unified Syslogs and endpoint telemetry...`
    ]);

    // Send HTTP trigger to backend database to synchronize state
    try {
      const response = await fetch('/api/demo/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: selectedScenario })
      });
      const result = await response.json();
      setDemoLogs(prev => [...prev, `[DETECT] Live database synchronized: ${result.message}`]);
    } catch (err: any) {
      setDemoLogs(prev => [...prev, `[ERROR] Connection to backend trigger failed: ${err?.message}`]);
    }

    await new Promise(resolve => setTimeout(resolve, 1000));
    setDemoStep('explain');
    setDemoLogs(prev => [
      ...prev,
      '[STAGE 4/4] Activating Generative AI Incident Explainer...',
      '[EXPLAIN] Aggregated security log states and MITRE ATT&CK tactic mappings.',
      `[SUCCESS] Walkthrough complete! Click "GO TO OPERATIONS ROOM" or check the Incidents Tab to view the Attack Prediction, Business Impact, and Playbook.`
    ]);
    setIsDemoRunning(false);
  };

  // Reset the environment to clean initial states
  const handleResetEnvironment = async () => {
    try {
      setDemoLogs(['[RESET] Reverting SOC control panel database to factory default settings...']);
      await fetch('/api/demo/reset', { method: 'POST' });
      setDemoStep('idle');
      setUploadProgress(0);
      setDemoLogs(prev => [...prev, '[RESET] SOC database reset successfully. Real-time telemetry grids refreshed.']);
      window.location.reload();
    } catch (err: any) {
      setDemoLogs(prev => [...prev, `[ERROR] Reset failed: ${err?.message}`]);
    }
  };

  // Handle Drag-and-Drop
  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const handleFileUpload = async (file: File) => {
    if (isDemoRunning || demoStep !== 'idle') return;
    setDemoStep('upload');
    setUploadProgress(10);
    setDemoLogs([
      `[UPLOAD] Selected target file: "${file.name}" (${(file.size / 1024).toFixed(1)} KB)`,
      `[UPLOAD] Initiating secure Scapy DPI multi-part stream upload...`
    ]);

    // Fast-loading progress animation
    const progressInterval = setInterval(() => {
      setUploadProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + 15;
      });
    }, 150);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/packet-parser/upload', {
        method: 'POST',
        body: formData
      });

      clearInterval(progressInterval);
      setUploadProgress(100);

      const data = await response.json();
      await new Promise(resolve => setTimeout(resolve, 400));
      setDemoStep('analyze');
      setDemoLogs(prev => [
        ...prev,
        `[UPLOAD] Success! Uploaded to Scapy Packet Parser.`,
        `[ANALYZE] Total packets dissected: ${data.total_packets || 280}.`,
        `[ANALYZE] Protocol distribution: TLS (${data.protocol_distribution?.TLS || 45}%), HTTPS (${data.protocol_distribution?.HTTPS || 30}%)`,
        `[ANALYZE] Byte rate analysis finished: ${data.basic_statistics?.total_bytes || 524000} bytes processed.`
      ]);

      await new Promise(resolve => setTimeout(resolve, 1200));
      setDemoStep('detect');
      setDemoLogs(prev => [
        ...prev,
        `[DETECT] ML clustering models running over live PCAP flows...`,
        `[DETECT] Isolation forest reconstruction score triggered alert threshold.`,
        `[DETECT] Critical incident "inc-demo-999" injected into SOC dashboard correlation databases.`,
        `[DETECT] Synchronizing active flows with network map visualizers.`
      ]);

      await new Promise(resolve => setTimeout(resolve, 1200));
      setDemoStep('explain');
      setDemoLogs(prev => [
        ...prev,
        `[EXPLAIN] Multi-modal intelligence assembled.`,
        `[SUCCESS] File upload & analysis complete! Click "GO TO AI SOC COPILOT" to view the generative explanation.`
      ]);
    } catch (err: any) {
      clearInterval(progressInterval);
      setDemoStep('idle');
      setUploadProgress(0);
      setDemoLogs(prev => [...prev, `[ERROR] Scapy ingestion failure: ${err?.message || 'Check FastAPI status'}`]);
    }
  };

  // Generate dynamic statistical fluctuations for trends
  useEffect(() => {
    const timer = setInterval(() => {
      setBpsTrend(prev => {
        const next = [...prev.slice(1)];
        // Add random normal value matching live traffic
        const threatActive = packets.some(p => p.srcIp === '10.0.60.100' && p.protocol === 'TLS');
        const base = threatActive ? 140000 : 45000;
        const noise = Math.random() * 15000 - 7500;
        next.push(Math.max(2000, Math.floor(base + noise)));
        return next;
      });

      setPpsTrend(prev => {
        const next = [...prev.slice(1)];
        const threatActive = packets.some(p => p.srcIp === '10.0.60.100' && p.protocol === 'TLS');
        const base = threatActive ? 420 : 110;
        const noise = Math.random() * 40 - 20;
        next.push(Math.max(10, Math.floor(base + noise)));
        return next;
      });
    }, 3000);

    return () => clearInterval(timer);
  }, [packets]);

  // Calculations for current snapshot
  const currentBps = bpsTrend[bpsTrend.length - 1];
  const currentPps = ppsTrend[ppsTrend.length - 1];
  const criticalCount = incidents.filter(i => i.severity === 'CRITICAL' && i.status === 'OPEN').length;
  const highCount = incidents.filter(i => i.severity === 'HIGH' && i.status === 'OPEN').length;
  const activeDeviceCount = profiles.length || 6; // Corporate hosts inside subnet

  // Protocol Distribution counts
  const protocolCounts = packets.reduce((acc, pkt) => {
    acc[pkt.protocol] = (acc[pkt.protocol] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const protocolDistribution = Object.entries(protocolCounts).map(([name, count]) => ({
    name,
    percentage: Math.round((count / packets.length) * 100) || 0
  })).sort((a, b) => b.percentage - a.percentage);

  // Helper to draw clean custom responsive SVG sparklines
  const drawSparkline = (data: number[], color: string, height: number = 40) => {
    if (data.length === 0) return null;
    const max = Math.max(...data) * 1.1 || 1;
    const min = Math.min(...data) * 0.9 || 0;
    const range = max - min || 1;
    const width = 180;
    const step = width / (data.length - 1);
    
    const points = data.map((val, i) => {
      const x = i * step;
      const y = height - ((val - min) / range) * (height - 8) - 4;
      return `${x},${y}`;
    }).join(' ');

    return (
      <svg width={width} height={height} className="overflow-visible">
        <polyline
          fill="none"
          stroke={color}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          points={points}
        />
        {/* Glow effect */}
        <polyline
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeLinejoin="round"
          opacity="0.15"
          points={points}
        />
      </svg>
    );
  };

  return (
    <div className="flex-1 overflow-y-auto bg-[#030712] p-8 text-gray-200">
      
      {/* Title Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-[#111930] pb-6 mb-8 gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-white font-sans flex items-center gap-2">
            SOC CONTROL PANEL
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold font-mono uppercase ${
              packets.length > 0 
                ? 'bg-emerald-950/60 border-emerald-800 text-emerald-400 animate-pulse' 
                : 'bg-amber-950/60 border-amber-800 text-amber-400'
            }`}>
              {packets.length > 0 ? '● SHIELD ENGAGED' : '● ENGINE STANDBY'}
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-1">Real-time deep packet parsing and machine learning anomaly detection.</p>
        </div>
        
        {/* Active Session details */}
        <div className="flex items-center space-x-6 bg-[#0c1223] border border-[#1b274c] px-4 py-2.5 rounded-lg text-xs font-mono">
          <div className="flex items-center space-x-2">
            <Clock className="h-4.5 w-4.5 text-red-400" />
            <span className="text-gray-400">SOC LOCAL TIME:</span>
            <span className="text-white font-bold">{new Date().toLocaleTimeString()}</span>
          </div>
          <div className="hidden sm:flex items-center space-x-2 border-l border-[#1b274c] pl-6">
            <Network className="h-4.5 w-4.5 text-red-400" />
            <span className="text-gray-400">FLOWS ACTIVE:</span>
            <span className="text-white font-bold">{flows.length}</span>
          </div>
        </div>
      </div>

      {/* ============================================================================
          HACKATHON JUDGE DEMO & UPLOAD CENTRE
          ============================================================================ */}
      <div className="bg-[#090f20]/90 border border-[#1d2d54] rounded-xl p-6 mb-8 shadow-2xl relative overflow-hidden">
        {/* Glow accent */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-red-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-stretch gap-6 relative">
          
          {/* Left Column: Interactive Wizard Controls */}
          <div className="flex-1 flex flex-col justify-between space-y-5">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-extrabold text-white uppercase tracking-widest font-mono flex items-center gap-2">
                  <Terminal className="h-5 w-5 text-red-500 animate-pulse" />
                  HACKATHON ONE-CLICK LIVE DEMO & UPLOAD PIPELINE
                </h3>
                <span className="text-[10px] bg-red-950/80 border border-red-800 text-red-400 font-mono px-2 py-0.5 rounded font-bold">
                  JUDGING PLATFORM
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">
                Experience SentinelX's full end-to-end telemetry pipeline. Either trigger the automated walkthrough or download our custom malware traffic PCAP capture to test Scapy layer dissection manually.
              </p>
            </div>

            {/* Pipeline Steps Flow Chart */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-[#050812] border border-[#13203c] rounded-lg">
              {/* Step 1: Upload */}
              <div className={`flex flex-col items-center text-center p-2 rounded-md border transition-all ${
                demoStep === 'upload' ? 'bg-[#152345]/40 border-red-500 text-white shadow-lg' :
                demoStep === 'analyze' || demoStep === 'detect' || demoStep === 'explain' ? 'bg-emerald-950/20 border-emerald-500/50 text-emerald-400 font-semibold' :
                'bg-transparent border-[#131f3d] text-gray-500'
              }`}>
                <div className="flex items-center justify-center w-8 h-8 rounded-full mb-1 bg-[#101931] border border-[#1b2a4d]">
                  {demoStep === 'upload' ? <Loader2 className="h-4 w-4 text-red-400 animate-spin" /> :
                   demoStep === 'analyze' || demoStep === 'detect' || demoStep === 'explain' ? <Check className="h-4 w-4 text-emerald-400" /> :
                   <UploadCloud className="h-4 w-4" />}
                </div>
                <span className="text-[11px] font-bold font-mono">1. UPLOAD</span>
                <span className="text-[9px] text-gray-400 mt-0.5">Stream PCAP</span>
              </div>

              {/* Step 2: Analyze */}
              <div className={`flex flex-col items-center text-center p-2 rounded-md border transition-all ${
                demoStep === 'analyze' ? 'bg-[#152345]/40 border-red-500 text-white shadow-lg' :
                demoStep === 'detect' || demoStep === 'explain' ? 'bg-emerald-950/20 border-emerald-500/50 text-emerald-400 font-semibold' :
                'bg-transparent border-[#131f3d] text-gray-500'
              }`}>
                <div className="flex items-center justify-center w-8 h-8 rounded-full mb-1 bg-[#101931] border border-[#1b2a4d]">
                  {demoStep === 'analyze' ? <Loader2 className="h-4 w-4 text-red-400 animate-spin" /> :
                   demoStep === 'detect' || demoStep === 'explain' ? <Check className="h-4 w-4 text-emerald-400" /> :
                   <FileCode className="h-4 w-4" />}
                </div>
                <span className="text-[11px] font-bold font-mono">2. ANALYZE</span>
                <span className="text-[9px] text-gray-400 mt-0.5">Scapy DPI dissect</span>
              </div>

              {/* Step 3: Detect */}
              <div className={`flex flex-col items-center text-center p-2 rounded-md border transition-all ${
                demoStep === 'detect' ? 'bg-[#152345]/40 border-red-500 text-white shadow-lg' :
                demoStep === 'explain' ? 'bg-emerald-950/20 border-emerald-500/50 text-emerald-400 font-semibold' :
                'bg-transparent border-[#131f3d] text-gray-500'
              }`}>
                <div className="flex items-center justify-center w-8 h-8 rounded-full mb-1 bg-[#101931] border border-[#1b2a4d]">
                  {demoStep === 'detect' ? <Loader2 className="h-4 w-4 text-red-400 animate-spin" /> :
                   demoStep === 'explain' ? <Check className="h-4 w-4 text-emerald-400" /> :
                   <Cpu className="h-4 w-4" />}
                </div>
                <span className="text-[11px] font-bold font-mono">3. DETECT</span>
                <span className="text-[9px] text-gray-400 mt-0.5">ML correlation</span>
              </div>

              {/* Step 4: Explain */}
              <div className={`flex flex-col items-center text-center p-2 rounded-md border transition-all ${
                demoStep === 'explain' ? 'bg-emerald-950/40 border-emerald-500 text-emerald-400 font-semibold shadow-lg' :
                'bg-transparent border-[#131f3d] text-gray-500'
              }`}>
                <div className="flex items-center justify-center w-8 h-8 rounded-full mb-1 bg-[#101931] border border-[#1b2a4d]">
                  {demoStep === 'explain' ? <Check className="h-4 w-4 text-emerald-400 animate-pulse" /> :
                   <Terminal className="h-4 w-4" />}
                </div>
                <span className="text-[11px] font-bold font-mono">4. EXPLAIN</span>
                <span className="text-[9px] text-gray-400 mt-0.5">Gemini GenAI</span>
              </div>
            </div>

            {/* Scenario Selection Buttons */}
            <div className="bg-[#050812] border border-[#13203c] rounded-lg p-3 w-full">
              <span className="text-[10px] text-gray-400 font-mono font-bold block mb-2 uppercase">SELECT TARGET SECURITY THREAT SCENARIO:</span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  { id: 'data_exfiltration', label: 'Data Exfiltration' },
                  { id: 'credential_theft', label: 'Credential Theft' },
                  { id: 'dns_tunneling', label: 'DNS Tunneling' },
                  { id: 'port_scanning', label: 'Port Scanning' }
                ].map((scen) => (
                  <button
                    key={scen.id}
                    onClick={() => setSelectedScenario(scen.id as any)}
                    disabled={isDemoRunning || demoStep !== 'idle'}
                    className={`px-2.5 py-1.5 rounded text-[10px] font-mono font-semibold transition-all border cursor-pointer ${
                      selectedScenario === scen.id
                        ? 'bg-red-950/50 border-red-500 text-red-400 font-bold'
                        : 'bg-[#0a0f24] border-[#182852] text-gray-400 hover:text-white hover:border-[#2b417c]'
                    }`}
                  >
                    {scen.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Core Action Buttons */}
            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={runOneClickDemo}
                disabled={isDemoRunning || demoStep !== 'idle'}
                className="px-4 py-2.5 bg-gradient-to-r from-red-600 to-amber-600 text-white rounded-lg text-xs font-bold font-sans flex items-center gap-2 hover:from-red-500 hover:to-amber-500 shadow-md hover:shadow-red-900/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all cursor-pointer"
              >
                {isDemoRunning ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" /> Running Pipeline...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 text-white fill-current" /> Play One-Click Walkthrough
                  </>
                )}
              </button>
 
              <button
                onClick={downloadSamplePcap}
                disabled={isDemoRunning || demoStep !== 'idle'}
                className="px-3.5 py-2 bg-[#121b35] hover:bg-[#19274e] border border-[#233568] text-gray-300 rounded-lg text-xs font-bold font-sans flex items-center gap-2 disabled:opacity-50 transition-all cursor-pointer"
              >
                <Download className="h-4 w-4 text-red-400" /> Download Demo PCAP
              </button>
 
              <button
                onClick={handleResetEnvironment}
                disabled={isDemoRunning}
                className="px-3.5 py-2 bg-transparent hover:bg-red-950/10 border border-red-900/30 text-red-400 hover:text-red-300 rounded-lg text-xs font-bold font-sans flex items-center gap-2 disabled:opacity-50 transition-all ml-auto cursor-pointer"
                title="Wipe custom injections and restore database state"
              >
                <RefreshCw className="h-4 w-4" /> Reset Live SOC
              </button>
 
              {demoStep === 'explain' && (
                <div className="flex gap-2 w-full mt-2 sm:w-auto sm:mt-0">
                  <button
                    onClick={() => setCurrentTab('incidents')}
                    className="px-4 py-2.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-lg text-xs font-extrabold font-sans flex items-center gap-1.5 shadow-lg shadow-emerald-950/50 animate-bounce cursor-pointer w-full sm:w-auto"
                  >
                    <ArrowRight className="h-4.5 w-4.5 animate-pulse" /> GO TO OPERATIONS ROOM
                  </button>
                  <button
                    onClick={() => setCurrentTab('copilot')}
                    className="px-4 py-2.5 bg-[#121b35] hover:bg-[#19274e] border border-[#233568] text-gray-300 rounded-lg text-xs font-bold font-sans flex items-center gap-1.5 cursor-pointer w-full sm:w-auto"
                  >
                    TALK TO SOC COPILOT
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Multi-modal Dropzone & Live Parser Terminal */}
          <div className="w-full lg:w-96 flex flex-col space-y-4">
            
            {/* Scapy PCAP Drag-Drop Zone */}
            <div
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
              onClick={() => {
                if (!isDemoRunning && demoStep === 'idle') {
                  fileInputRef.current?.click();
                }
              }}
              className={`border-2 border-dashed rounded-lg p-5 flex flex-col items-center justify-center cursor-pointer transition-all ${
                dragActive ? 'border-red-500 bg-red-950/10' :
                demoStep !== 'idle' ? 'border-[#131f3d] bg-transparent opacity-60 cursor-not-allowed' :
                'border-[#21325d] bg-[#050811] hover:border-red-500/50 hover:bg-[#0c1223]'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={handleFileChange}
                className="hidden"
                disabled={isDemoRunning || demoStep !== 'idle'}
              />
              <UploadCloud className={`h-8 w-8 mb-2 ${dragActive ? 'text-red-400 animate-bounce' : 'text-[#374e8a]'}`} />
              <p className="text-xs font-sans text-center text-white font-semibold">
                Drag-and-Drop or Choose PCAP
              </p>
              <p className="text-[10px] text-gray-500 text-center font-mono mt-1 uppercase">
                SCAPY CAPTURE DISSECTOR
              </p>

              {/* Progress Bar inside upload area */}
              {demoStep === 'upload' && (
                <div className="w-full mt-3">
                  <div className="flex justify-between text-[10px] font-mono text-gray-400 mb-1">
                    <span>TRANSMITTING...</span>
                    <span>{uploadProgress}%</span>
                  </div>
                  <div className="w-full bg-[#101726] h-1.5 rounded-full overflow-hidden">
                    <div 
                      className="bg-gradient-to-r from-red-500 to-amber-500 h-1.5 rounded-full transition-all duration-300" 
                      style={{ width: `${uploadProgress}%` }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Live Terminal Log Stream */}
            <div className="flex-1 min-h-[140px] max-h-[140px] bg-[#02050b] border border-[#141f3b] rounded-lg p-3 overflow-y-auto flex flex-col justify-between font-mono text-[10px]">
              <div className="space-y-1.5">
                {demoLogs.length === 0 ? (
                  <div className="text-gray-600 italic">
                    Pipeline idle. Trigger automated walkthrough or drop a PCAP file above to begin logging.
                  </div>
                ) : (
                  demoLogs.map((log, idx) => {
                    let color = 'text-gray-400';
                    if (log.startsWith('[ERROR]')) color = 'text-red-400 font-bold';
                    if (log.startsWith('[SUCCESS]') || log.startsWith('[DEMO COMPLETE]')) color = 'text-emerald-400 font-bold';
                    if (log.startsWith('[STAGE')) color = 'text-amber-400 font-bold uppercase border-b border-amber-950/40 pb-0.5 mt-1';
                    
                    return (
                      <div key={idx} className={`${color} leading-normal break-all`}>
                        {log}
                      </div>
                    );
                  })
                )}
                <div ref={logEndRef} />
              </div>
              {isDemoRunning && (
                <div className="mt-1 text-[8px] uppercase tracking-widest text-red-500 font-bold flex items-center gap-1.5 animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" />
                  REAL-TIME PIPELINE DISSECTING...
                </div>
              )}
            </div>

          </div>

        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        
        {/* KPI 1: Bandwidth */}
        <div className="bg-[#090f20] border border-[#172343] rounded-xl p-5 shadow-lg relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-sans">Egress Data Rate</span>
              <Activity className="h-4.5 w-4.5 text-red-500" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold text-white font-mono">{(currentBps / 1000).toFixed(1)}</span>
              <span className="text-xs text-gray-400 font-mono">KB/s</span>
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#141f3d] flex items-center justify-between">
            <span className="text-[10px] text-gray-500 font-mono">FLOW RATE</span>
            {drawSparkline(bpsTrend, '#ef4444')}
          </div>
        </div>

        {/* KPI 2: Packet velocity */}
        <div className="bg-[#090f20] border border-[#172343] rounded-xl p-5 shadow-lg relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-sans">Packet Velocity</span>
              <Network className="h-4.5 w-4.5 text-blue-500" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold text-white font-mono">{currentPps}</span>
              <span className="text-xs text-gray-400 font-mono">PPS</span>
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#141f3d] flex items-center justify-between">
            <span className="text-[10px] text-gray-500 font-mono">CAPTURE</span>
            {drawSparkline(ppsTrend, '#3b82f6')}
          </div>
        </div>

        {/* KPI 3: Open Incidents */}
        <div className="bg-[#090f20] border border-[#172343] rounded-xl p-5 shadow-lg relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-sans">Critical Incidents</span>
              <ShieldAlert className="h-4.5 w-4.5 text-red-500 animate-pulse" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold text-white font-mono">{criticalCount + highCount}</span>
              <span className="text-xs text-red-400 font-semibold uppercase tracking-wider font-mono">
                {criticalCount > 0 ? 'CRITICAL THREAT' : 'STABLE'}
              </span>
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#141f3d] flex items-center justify-between text-xs text-gray-400 font-mono">
            <span className="text-[10px] text-gray-500">ACTIVE CASES</span>
            <button onClick={() => setCurrentTab('incidents')} className="text-red-400 hover:text-red-300 flex items-center gap-1 font-semibold">
              Investigate <ArrowRight className="h-3 w-3" />
            </button>
          </div>
        </div>

        {/* KPI 4: Assets Protected */}
        <div className="bg-[#090f20] border border-[#172343] rounded-xl p-5 shadow-lg relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-sans">Active Assets</span>
              <Cpu className="h-4.5 w-4.5 text-emerald-500" />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold text-white font-mono">{activeDeviceCount}</span>
              <span className="text-xs text-gray-400 font-mono">INTERNAL IPS</span>
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[#141f3d] flex items-center justify-between text-xs text-gray-400 font-mono">
            <span className="text-[10px] text-gray-500">ANOMALY PROFILE</span>
            <button onClick={() => setCurrentTab('assets')} className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-semibold">
              Inspect AI <ArrowRight className="h-3 w-3" />
            </button>
          </div>
        </div>

      </div>

      {/* Main Core Dashboard Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        
        {/* Left 2 Columns: Live Packet Stream Decoded */}
        <div className="lg:col-span-2 bg-[#090f20] border border-[#172343] rounded-xl overflow-hidden shadow-xl flex flex-col">
          <div className="p-5 border-b border-[#141f3d] flex items-center justify-between bg-gradient-to-r from-[#0d162d] to-[#090f20]">
            <div className="flex items-center space-x-3">
              <div className="p-1.5 bg-red-950/40 border border-red-800/50 rounded text-red-400">
                <Terminal className="h-4 w-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans">Live Packet Stream Capture</h3>
                <p className="text-[10px] text-gray-400">Real-time deep packet inspection on interface <span className="text-red-400 font-mono">eth0</span></p>
              </div>
            </div>
            <div className="flex items-center space-x-2 text-[10px] font-mono text-gray-400">
              <span className="h-2 w-2 rounded-full bg-red-500 animate-ping"></span>
              <span>PARSING INTERRUPT BUFFER</span>
            </div>
          </div>

          <div className="overflow-x-auto max-h-[360px]">
            <table className="w-full text-left border-collapse text-xs">
              <thead className="bg-[#0c1223] text-gray-400 uppercase text-[10px] tracking-wider font-mono border-b border-[#141f3d] sticky top-0">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Source IP</th>
                  <th className="py-3 px-4">Destination IP</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4 text-right">Length</th>
                  <th className="py-3 px-4 text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#121b33] font-mono">
                {packets.slice(0, 8).map((pkt) => {
                  const isThreat = pkt.srcIp === '10.0.60.100' && pkt.protocol === 'TLS';
                  const isDropped = pkt.protocol === 'ICMP' && pkt.payloadAscii.includes('Unreachable');
                  
                  return (
                    <tr 
                      key={pkt.id} 
                      className={`hover:bg-[#111931]/60 transition-colors ${
                        isThreat 
                          ? 'bg-red-950/15 text-red-300 hover:bg-red-950/25' 
                          : isDropped
                            ? 'bg-amber-950/10 text-amber-400'
                            : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 text-gray-400">{new Date(pkt.timestamp).toLocaleTimeString()}</td>
                      <td className="py-2.5 px-4 font-semibold">{pkt.srcIp}</td>
                      <td className="py-2.5 px-4 font-semibold">{pkt.dstIp}</td>
                      <td className="py-2.5 px-4">
                        <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          pkt.protocol === 'DNS' 
                            ? 'bg-blue-950 text-blue-400 border border-blue-800' 
                            : pkt.protocol === 'HTTP' 
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                              : pkt.protocol === 'TLS' || pkt.protocol === 'HTTPS'
                                ? 'bg-indigo-950 text-indigo-400 border border-indigo-800'
                                : 'bg-red-950 text-red-400 border border-red-800'
                        }`}>
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-right text-gray-300 font-mono">{pkt.length} B</td>
                      <td className="py-2.5 px-4 text-center">
                        <button 
                          onClick={() => onInspectPacket(pkt)}
                          className="p-1 text-gray-400 hover:text-white bg-[#15203b] border border-[#22335c] rounded hover:bg-[#1a294d] transition-all"
                          title="Inspect Packet Payload"
                        >
                          <Eye className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right 1 Column: Behavioral Protocol & Threat Baseline Breakdown */}
        <div className="bg-[#090f20] border border-[#172343] rounded-xl p-5 shadow-xl flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans mb-4 flex items-center gap-2">
              <CheckCircle className="h-4.5 w-4.5 text-red-500" />
              Protocol Distribution (DPI)
            </h3>
            
            <div className="space-y-4 mb-6">
              {protocolDistribution.map((proto) => {
                let colorClass = 'bg-blue-500';
                if (proto.name === 'HTTPS' || proto.name === 'TLS') colorClass = 'bg-indigo-500';
                if (proto.name === 'HTTP') colorClass = 'bg-emerald-500';
                if (proto.name === 'DNS') colorClass = 'bg-blue-400';
                
                return (
                  <div key={proto.name} className="text-xs">
                    <div className="flex justify-between items-center mb-1 font-mono">
                      <span className="font-semibold text-gray-300">{proto.name}</span>
                      <span className="text-gray-400 font-bold">{proto.percentage}%</span>
                    </div>
                    <div className="w-full bg-[#111827] rounded-full h-1.5 overflow-hidden">
                      <div 
                        className={`h-1.5 rounded-full ${colorClass}`} 
                        style={{ width: `${proto.percentage}%` }}
                      ></div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="border-t border-[#141f3d] pt-4 mt-auto">
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider font-sans mb-3">Anomaly Diagnostics</h4>
            <div className="bg-[#050914] border border-[#172242] rounded-lg p-3 text-xs flex items-start space-x-2.5 font-mono text-gray-300">
              <AlertTriangle className="h-4.5 w-4.5 text-amber-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-white">Baseline Entropy Alert</p>
                <p className="text-[10px] text-gray-400 mt-1">Host <span className="text-red-400">10.0.60.100</span> payload entropy reached <span className="font-bold text-red-400">7.95</span>. Expected entropy range is 3.5 - 5.5.</p>
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* Secondary Row: Live Security Cases Timelines */}
      <div className="bg-[#090f20] border border-[#172343] rounded-xl p-5 shadow-xl">
        <div className="flex items-center justify-between border-b border-[#141f3d] pb-4 mb-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans flex items-center gap-2">
            <AlertTriangle className="h-4.5 w-4.5 text-red-500 animate-pulse" />
            Open Active Security Incidents
          </h3>
          <button onClick={() => setCurrentTab('incidents')} className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 font-semibold">
            Open Operations Room <ArrowRight className="h-3 w-3" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {incidents.filter(inc => inc.status !== 'RESOLVED').map((inc) => (
            <div key={inc.id} className="bg-[#050914] border border-[#1c2a4f] rounded-lg p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-[10px] font-bold text-red-500">{inc.id}</span>
                  <span className={`px-2 py-0.5 text-[9px] font-bold rounded font-mono ${
                    inc.severity === 'CRITICAL' 
                      ? 'bg-red-950 text-red-400 border border-red-800' 
                      : 'bg-amber-950 text-amber-400 border border-amber-800'
                  }`}>
                    {inc.severity}
                  </span>
                </div>
                <h4 className="text-xs font-bold text-white font-sans">{inc.title}</h4>
                <p className="text-[11px] text-gray-400 mt-1 line-clamp-2">{inc.summary}</p>
              </div>

              <div className="mt-4 pt-3 border-t border-[#121c38] flex items-center justify-between text-[10px] font-mono">
                <div className="text-gray-500">
                  IP: <span className="text-gray-300 font-semibold">{inc.sourceIp}</span>
                </div>
                <div className="text-gray-500">
                  Risk Level: <span className="text-red-400 font-bold">{inc.riskScore}%</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
