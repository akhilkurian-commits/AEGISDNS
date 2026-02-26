
import React, { useState, useEffect, useCallback, useRef } from 'react';
import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import { 
  Shield, 
  LayoutDashboard, 
  FileText, 
  Search, 
  Settings, 
  Activity, 
  AlertTriangle, 
  Database,
  Terminal,
  Download,
  Upload,
  BarChart3,
  Cpu,
  FileSearch,
  CheckCircle2,
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  Radio,
  Wifi,
  Zap,
  MapPin,
  Globe,
  Bell,
  BellRing,
  Info
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  ScatterChart, 
  Scatter, 
  ZAxis,
  Cell,
  Brush,
  ReferenceLine,
  Label
} from 'recharts';
import { DNSQuery, AppState, ForensicReport, ThreatLevel } from './types';
import { generateMockData, getStats, classifyQuery, parseLogContent, calculateEntropy, calculateThreatScore, checkIpReputation } from './utils/forensics';
import { analyzeForensics } from './services/geminiService';
import { fetchGeolocation } from './services/geoService';

// --- Components ---

const SidebarItem: React.FC<{ 
  icon: React.ReactNode; 
  label: string; 
  active?: boolean; 
  onClick: () => void;
  badge?: string;
}> = ({ icon, label, active, onClick, badge }) => (
  <button 
    onClick={onClick}
    className={`w-full flex items-center justify-between px-4 py-3 rounded-lg transition-all ${
      active ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'text-slate-400 hover:text-white hover:bg-slate-800'
    }`}
  >
    <div className="flex items-center gap-3">
      {icon}
      <span className="font-medium">{label}</span>
    </div>
    {badge && (
      <span className="text-[10px] font-bold bg-emerald-500 text-white px-1.5 rounded-full animate-pulse uppercase tracking-tighter">
        {badge}
      </span>
    )}
  </button>
);

const StatCard: React.FC<{ label: string; value: string | number; subtext: string; icon: React.ReactNode }> = ({ label, value, subtext, icon }) => (
  <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
    <div className="flex justify-between items-start mb-4">
      <div className="p-2 bg-slate-800 rounded-lg text-emerald-400">
        {icon}
      </div>
      <span className="text-xs font-mono text-slate-500">{subtext}</span>
    </div>
    <div className="text-2xl font-bold text-white mb-1">{value}</div>
    <div className="text-sm text-slate-400">{label}</div>
  </div>
);

const FilterSelect: React.FC<{ 
  label: string; 
  value: string; 
  options: { label: string; value: string }[]; 
  onChange: (val: string) => void 
}> = ({ label, value, options, onChange }) => (
  <div className="flex flex-col gap-1">
    <label className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">{label}</label>
    <select 
      value={value} 
      onChange={(e) => onChange(e.target.value)}
      className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 outline-none focus:ring-1 focus:ring-emerald-500 appearance-none cursor-pointer hover:bg-slate-700 transition-colors"
    >
      {options.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
    </select>
  </div>
);

const WorldMap: React.FC<{ logs: DNSQuery[] }> = ({ logs }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [topology, setTopology] = useState<any>(null);

  useEffect(() => {
    fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
      .then(res => res.json())
      .then(data => setTopology(data));
  }, []);

  useEffect(() => {
    if (!svgRef.current || !topology) return;

    const svg = d3.select(svgRef.current);
    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    svg.selectAll("*").remove();

    const projection = d3.geoMercator()
      .scale(width / 6.5)
      .translate([width / 2, height / 1.5]);

    const path = d3.geoPath().projection(projection);

    const g = svg.append("g");

    // Draw countries
    g.append("g")
      .selectAll("path")
      .data((topojson.feature(topology, topology.objects.countries) as any).features)
      .enter()
      .append("path")
      .attr("d", path as any)
      .attr("fill", "#1e293b")
      .attr("stroke", "#334155")
      .attr("stroke-width", 0.5);

    // Filter logs with coordinates
    const points = logs.filter(l => l.lat !== undefined && l.lng !== undefined);

    // Draw points
    g.selectAll("circle")
      .data(points)
      .enter()
      .append("circle")
      .attr("cx", (d: any) => projection([d.lng!, d.lat!])![0])
      .attr("cy", (d: any) => projection([d.lng!, d.lat!])![1])
      .attr("r", (d: any) => d.label === 'Tunneling' ? 4 : 2)
      .attr("fill", (d: any) => d.label === 'Tunneling' ? "#ef4444" : "#10b981")
      .attr("opacity", 0.7)
      .attr("class", (d: any) => d.label === 'Tunneling' ? "animate-pulse" : "")
      .append("title")
      .text((d: any) => `${d.query}\n${d.location}\nThreat: ${d.threatScore}`);

    // Add ripples for threats
    g.selectAll(".ripple")
      .data(points.filter(p => p.label === 'Tunneling'))
      .enter()
      .append("circle")
      .attr("class", "ripple")
      .attr("cx", (d: any) => projection([d.lng!, d.lat!])![0])
      .attr("cy", (d: any) => projection([d.lng!, d.lat!])![1])
      .attr("r", 4)
      .attr("fill", "none")
      .attr("stroke", "#ef4444")
      .attr("stroke-width", 1)
      .style("opacity", 0.8)
      .transition()
      .duration(2000)
      .ease(d3.easeLinear)
      .attr("r", 20)
      .style("opacity", 0)
      .on("end", function repeat() {
        d3.select(this)
          .attr("r", 4)
          .style("opacity", 0.8)
          .transition()
          .duration(2000)
          .ease(d3.easeLinear)
          .attr("r", 20)
          .style("opacity", 0)
          .on("end", repeat);
      });

  }, [topology, logs]);

  return (
    <div className="w-full h-full bg-slate-950 rounded-xl border border-slate-800 overflow-hidden relative">
      <svg ref={svgRef} className="w-full h-full" />
      <div className="absolute bottom-4 left-4 bg-slate-900/80 backdrop-blur-md border border-slate-800 p-3 rounded-lg text-[10px] space-y-2">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-500" />
          <span className="text-slate-400 uppercase tracking-widest font-bold">Normal Traffic</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          <span className="text-slate-400 uppercase tracking-widest font-bold">Detected Tunneling</span>
        </div>
      </div>
    </div>
  );
};

const InteractiveTimeline: React.FC<{ timeline: { time: string; event: string }[] }> = ({ timeline }) => {
  const [selectedEvent, setSelectedEvent] = useState<{ time: string; event: string } | null>(null);

  const chartData = timeline.map((item, index) => ({
    ...item,
    timestamp: new Date(item.time).getTime(),
    y: 1,
    index
  })).sort((a, b) => a.timestamp - b.timestamp);

  if (chartData.length === 0) return null;

  const minTime = chartData[0].timestamp;
  const maxTime = chartData[chartData.length - 1].timestamp;
  const padding = (maxTime - minTime) * 0.1 || 10000;

  return (
    <div className="space-y-6">
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-6 shadow-inner">
        <div className="flex justify-between items-center mb-6">
          <h4 className="text-emerald-400 uppercase text-xs tracking-widest font-bold flex items-center gap-2">
            <Activity className="w-4 h-4" /> Interactive Attack Timeline
          </h4>
          <div className="text-[10px] text-slate-500 mono uppercase">Zoom & Pan enabled</div>
        </div>
        
        <div className="h-[250px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart margin={{ top: 20, right: 30, bottom: 20, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis 
                type="number" 
                dataKey="timestamp" 
                name="Time" 
                domain={[minTime - padding, maxTime + padding]}
                tickFormatter={(unixTime) => new Date(unixTime).toLocaleTimeString()}
                stroke="#64748b"
                fontSize={10}
              />
              <YAxis type="number" dataKey="y" hide domain={[0, 2]} />
              <ZAxis type="number" range={[100, 100]} />
              <Tooltip 
                cursor={{ strokeDasharray: '3 3' }} 
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg shadow-xl max-w-xs">
                        <div className="text-[10px] text-emerald-500 mono mb-1">{new Date(data.timestamp).toLocaleString()}</div>
                        <div className="text-xs text-white leading-relaxed">{data.event}</div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Scatter 
                name="Events" 
                data={chartData} 
                onClick={(data) => setSelectedEvent(data)}
                className="cursor-pointer"
              >
                {chartData.map((entry, index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={selectedEvent?.time === entry.time ? '#10b981' : '#334155'} 
                    stroke={selectedEvent?.time === entry.time ? '#fff' : 'none'}
                    strokeWidth={2}
                  />
                ))}
              </Scatter>
              <Brush 
                dataKey="timestamp" 
                height={30} 
                stroke="#10b981" 
                fill="#0f172a"
                tickFormatter={(unixTime) => new Date(unixTime).toLocaleTimeString()}
              />
            </ScatterChart>
          </ResponsiveContainer>
        </div>
      </div>

      {selectedEvent && (
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-6 animate-in slide-in-from-top-2">
          <div className="flex justify-between items-start mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-emerald-500/20 rounded-lg text-emerald-400">
                <FileSearch size={20} />
              </div>
              <div>
                <h5 className="font-bold text-white">Event Details</h5>
                <p className="text-[10px] text-slate-500 mono uppercase">{new Date(selectedEvent.time).toLocaleString()}</p>
              </div>
            </div>
            <button 
              onClick={() => setSelectedEvent(null)}
              className="text-slate-500 hover:text-white transition-colors"
            >
              <Zap size={16} className="rotate-45" />
            </button>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed bg-slate-900/50 p-4 rounded-lg border border-slate-800">
            {selectedEvent.event}
          </p>
        </div>
      )}
    </div>
  );
};

const App: React.FC = () => {
  const [state, setState] = useState<AppState>({
    logs: [],
    liveLogs: [],
    alerts: [],
    isAnalyzing: false,
    isLive: true,
    activeView: 'dashboard',
    stats: null,
    report: null
  });

  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('ALL');
  const [filterRCode, setFilterRCode] = useState('ALL');
  const [filterThreat, setFilterThreat] = useState('ALL');
  const [filterReputation, setFilterReputation] = useState('ALL');
  
  const pcapInputRef = useRef<HTMLInputElement>(null);
  const logInputRef = useRef<HTMLInputElement>(null);
  const liveScrollRef = useRef<HTMLDivElement>(null);

  // Simulation: Add live DNS queries periodically
  useEffect(() => {
    if (!state.isLive) return;

    const interval = setInterval(async () => {
      const isMalicious = Math.random() < 0.1;
      const domains = ["apple.com", "microsoft.net", "akamai.net", "facebook.io", "zoom.us", "slack.com"];
      const maliciousTunnels = [
        "tx.a4b3.c2server.ru",
        "init.z9x8y7.exfil.dns",
        "ping.v1.enc.base64payload.attacker.com"
      ];
      
      const queryStr = isMalicious 
        ? maliciousTunnels[Math.floor(Math.random() * maliciousTunnels.length)]
        : domains[Math.floor(Math.random() * domains.length)];
      
      const publicIps = ['8.8.8.8', '1.1.1.1', '13.248.169.48', '172.217.1.14'];
      const sourceIp = Math.random() > 0.6 
        ? publicIps[Math.floor(Math.random() * publicIps.length)]
        : `192.168.1.${Math.floor(Math.random() * 200) + 1}`;

      const entropy = calculateEntropy(queryStr);
      const geo = await fetchGeolocation(sourceIp);
      
      const newQuery: DNSQuery = {
        id: Math.random().toString(36).substr(2, 9),
        timestamp: new Date().toISOString(),
        sourceIp,
        query: queryStr,
        type: 'A',
        length: queryStr.length,
        entropy,
        location: geo.location,
        lat: geo.lat,
        lng: geo.lng,
        reputation: checkIpReputation(sourceIp),
        isNew: isMalicious,
        threatScore: 0,
      };

      const classification = classifyQuery(newQuery);
      newQuery.label = classification.label;
      newQuery.confidence = classification.confidence;
      newQuery.threatScore = calculateThreatScore(newQuery);

      setState(prev => {
        const updatedLogs = [newQuery, ...prev.logs].slice(0, 1000);
        const newAlerts = [...prev.alerts];
        
        if (newQuery.label === 'Tunneling') {
          newAlerts.unshift({
            id: Math.random().toString(36).substr(2, 9),
            timestamp: newQuery.timestamp,
            type: newQuery.threatScore > 80 ? 'C2_PATTERN' : (newQuery.entropy > 4.5 ? 'HIGH_ENTROPY' : 'TUNNELING_DETECTED'),
            severity: newQuery.threatScore > 85 ? 'CRITICAL' : (newQuery.threatScore > 60 ? 'HIGH' : 'MEDIUM'),
            message: `Suspicious activity detected from ${newQuery.sourceIp} targeting ${newQuery.query}`,
            queryId: newQuery.id,
            isRead: false
          });
        }

        return {
          ...prev,
          liveLogs: [newQuery, ...prev.liveLogs].slice(0, 50),
          logs: updatedLogs,
          alerts: newAlerts.slice(0, 100),
          stats: getStats(updatedLogs)
        };
      });
    }, 3000);

    return () => clearInterval(interval);
  }, [state.isLive]);

  const loadLogs = useCallback(async () => {
    setState(prev => ({ ...prev, isAnalyzing: true }));
    const initialLogs = generateMockData();
    
    // Fetch geolocation for the first few logs sequentially to avoid burst rate limits
    const logsWithGeo = [...initialLogs];
    for (let i = 0; i < Math.min(initialLogs.length, 10); i++) {
      const geo = await fetchGeolocation(logsWithGeo[i].sourceIp);
      logsWithGeo[i] = { 
        ...logsWithGeo[i], 
        location: geo.location,
        lat: geo.lat,
        lng: geo.lng
      };
    }

    setState(prev => ({
      ...prev,
      logs: logsWithGeo,
      stats: getStats(logsWithGeo),
      isAnalyzing: false
    }));
  }, []);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const runAIForensics = async () => {
    if (state.logs.length === 0) return;
    setState(prev => ({ ...prev, isAnalyzing: true }));
    setError(null);
    try {
      const report = await analyzeForensics(state.logs);
      setState(prev => ({ ...prev, report, isAnalyzing: false, activeView: 'forensics' }));
    } catch (err: any) {
      console.error(err);
      setError("AI Analysis failed. Please check your API configuration.");
      setState(prev => ({ ...prev, isAnalyzing: false }));
    }
  };

  const handleFileUpload = (type: 'pcap' | 'log') => {
    if (type === 'pcap') pcapInputRef.current?.click();
    else logInputRef.current?.click();
  };

  const onFileChange = async (e: React.ChangeEvent<HTMLInputElement>, type: 'pcap' | 'log') => {
    const file = e.target.files?.[0];
    if (!file) return;
    setState(prev => ({ ...prev, isAnalyzing: true }));
    setError(null);
    setSuccessMsg(null);

    try {
      if (type === 'log') {
        const text = await file.text();
        const parsed = parseLogContent(text);
        if (parsed.length === 0) throw new Error("No valid DNS queries found.");
        
        const parsedWithGeo = [...parsed];
        for (let i = 0; i < Math.min(parsed.length, 10); i++) {
          const geo = await fetchGeolocation(parsedWithGeo[i].sourceIp);
          parsedWithGeo[i] = { 
            ...parsedWithGeo[i], 
            location: geo.location,
            lat: geo.lat,
            lng: geo.lng,
            threatScore: calculateThreatScore({ ...parsedWithGeo[i], location: geo.location })
          };
        }

        setState(prev => {
          const newLogs = [...parsedWithGeo, ...prev.logs];
          const newAlerts = [...prev.alerts];
          
          parsedWithGeo.forEach(log => {
            if (log.label === 'Tunneling') {
              newAlerts.unshift({
                id: Math.random().toString(36).substr(2, 9),
                timestamp: log.timestamp,
                type: log.threatScore > 80 ? 'C2_PATTERN' : (log.entropy > 4.5 ? 'HIGH_ENTROPY' : 'TUNNELING_DETECTED'),
                severity: log.threatScore > 85 ? 'CRITICAL' : (log.threatScore > 60 ? 'HIGH' : 'MEDIUM'),
                message: `Suspicious activity detected in imported logs from ${log.sourceIp}`,
                queryId: log.id,
                isRead: false
              });
            }
          });

          return { 
            ...prev, 
            logs: newLogs, 
            alerts: newAlerts.slice(0, 100),
            stats: getStats(newLogs), 
            isAnalyzing: false 
          };
        });
        setSuccessMsg(`Imported ${parsed.length} records.`);
      } else {
        await new Promise(r => setTimeout(r, 2000));
        const mockPcapLogs = generateMockData().slice(0, 25);
        const pcapWithGeo = [...mockPcapLogs];
        for (let i = 0; i < Math.min(mockPcapLogs.length, 10); i++) {
          const geo = await fetchGeolocation(pcapWithGeo[i].sourceIp);
          pcapWithGeo[i] = { 
            ...pcapWithGeo[i], 
            location: geo.location,
            lat: geo.lat,
            lng: geo.lng,
            threatScore: calculateThreatScore({ ...pcapWithGeo[i], location: geo.location })
          };
        }
        setState(prev => {
          const newLogs = [...pcapWithGeo, ...prev.logs];
          const newAlerts = [...prev.alerts];
          
          pcapWithGeo.forEach(log => {
            if (log.label === 'Tunneling') {
              newAlerts.unshift({
                id: Math.random().toString(36).substr(2, 9),
                timestamp: log.timestamp,
                type: log.threatScore > 80 ? 'C2_PATTERN' : (log.entropy > 4.5 ? 'HIGH_ENTROPY' : 'TUNNELING_DETECTED'),
                severity: log.threatScore > 85 ? 'CRITICAL' : (log.threatScore > 60 ? 'HIGH' : 'MEDIUM'),
                message: `Threat detected in PCAP trace from ${log.sourceIp}`,
                queryId: log.id,
                isRead: false
              });
            }
          });

          return { 
            ...prev, 
            logs: newLogs, 
            alerts: newAlerts.slice(0, 100),
            stats: getStats(newLogs), 
            isAnalyzing: false 
          };
        });
        setSuccessMsg(`Extracted 25 packets from ${file.name}`);
      }
    } catch (err: any) {
      setError(err.message || "Upload failed.");
      setState(prev => ({ ...prev, isAnalyzing: false }));
    } finally {
      e.target.value = ''; 
    }
  };

  const threatColor = (level?: ThreatLevel) => {
    switch (level) {
      case ThreatLevel.CRITICAL: return 'text-red-500 bg-red-500/10 border-red-500/20';
      case ThreatLevel.HIGH: return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case ThreatLevel.MEDIUM: return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      default: return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
    }
  };

  const filteredLogs = state.logs.filter(log => {
    const matchesSearch = log.query.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          log.sourceIp.includes(searchTerm) ||
                          log.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === 'ALL' || log.type === filterType;
    const matchesRCode = filterRCode === 'ALL' || log.responseCode === filterRCode;
    const matchesThreat = filterThreat === 'ALL' || (
      filterThreat === 'CRITICAL' ? log.threatScore > 80 :
      filterThreat === 'HIGH' ? log.threatScore > 50 :
      filterThreat === 'MEDIUM' ? log.threatScore > 20 :
      log.threatScore <= 20
    );
    const matchesReputation = filterReputation === 'ALL' || log.reputation === filterReputation;
    return matchesSearch && matchesType && matchesRCode && matchesThreat && matchesReputation;
  });

  return (
    <div className="flex h-screen bg-[#020617] text-slate-200 overflow-hidden font-sans">
      <input type="file" ref={pcapInputRef} className="hidden" accept=".pcap,.cap" onChange={(e) => onFileChange(e, 'pcap')} />
      <input type="file" ref={logInputRef} className="hidden" accept=".log,.txt,.csv" onChange={(e) => onFileChange(e, 'log')} />

      <aside className="w-64 border-r border-slate-800 p-4 flex flex-col gap-8">
        <div className="flex items-center gap-3 px-2 mt-2">
          <div className="p-2 bg-emerald-500 rounded-lg shadow-lg shadow-emerald-500/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <span className="font-bold text-xl tracking-tight uppercase">Aegis<span className="text-emerald-500">Dns</span></span>
        </div>

        <nav className="flex flex-col gap-2">
          <SidebarItem icon={<LayoutDashboard size={20} />} label="Dashboard" active={state.activeView === 'dashboard'} onClick={() => setState(s => ({ ...s, activeView: 'dashboard' }))} />
          <SidebarItem icon={<Radio size={20} />} label="Live Monitor" active={state.activeView === 'live'} badge="Live" onClick={() => setState(s => ({ ...s, activeView: 'live' }))} />
          <SidebarItem icon={<Globe size={20} />} label="Threat Map" active={state.activeView === 'map'} onClick={() => setState(s => ({ ...s, activeView: 'map' }))} />
          <SidebarItem 
            icon={<BellRing size={20} />} 
            label="Alerts" 
            active={state.activeView === 'alerts'} 
            badge={state.alerts.filter(a => !a.isRead).length > 0 ? `${state.alerts.filter(a => !a.isRead).length}` : undefined} 
            onClick={() => setState(s => ({ ...s, activeView: 'alerts' }))} 
          />
          <SidebarItem icon={<Database size={20} />} label="DNS Logs" active={state.activeView === 'logs'} onClick={() => setState(s => ({ ...s, activeView: 'logs' }))} />
          <SidebarItem icon={<Cpu size={20} />} label="Forensic Lab" active={state.activeView === 'forensics'} onClick={() => setState(s => ({ ...s, activeView: 'forensics' }))} />
          <SidebarItem icon={<FileText size={20} />} label="Reports" active={state.activeView === 'reports'} onClick={() => setState(s => ({ ...s, activeView: 'reports' }))} />
        </nav>

        <div className="mt-auto">
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-2 h-2 rounded-full ${state.isLive ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
              <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">{state.isLive ? 'System Live' : 'Monitoring Paused'}</span>
            </div>
            <p className="text-[10px] text-slate-500 mono leading-relaxed">Engine: Aegis-2.4<br/>Mode: {state.isLive ? 'Real-time Ingress' : 'Post-Mortem'}</p>
          </div>
        </div>
      </aside>

      <main className="flex-1 flex flex-col overflow-hidden">
        <header className="h-16 border-b border-slate-800 flex items-center justify-between px-8 bg-[#020617]/50 backdrop-blur-md sticky top-0 z-10">
          <div className="flex items-center gap-4">
            <h1 className="text-lg font-semibold capitalize">{state.activeView === 'live' ? 'Live Watch' : state.activeView}</h1>
            {state.isLive && state.activeView === 'live' && (
              <div className="flex items-center gap-2 px-3 py-1 bg-emerald-500/10 text-emerald-400 rounded-full text-xs border border-emerald-500/20 font-bold uppercase tracking-widest animate-pulse">
                <Wifi className="w-3 h-3" />
                Interception Active
              </div>
            )}
          </div>
          <div className="flex items-center gap-3">
             <button onClick={() => setState(s => ({ ...s, isLive: !s.isLive }))} className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 border ${state.isLive ? 'bg-red-500/10 text-red-500 border-red-500/20' : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'}`}>
              <Zap className="w-4 h-4" />
              {state.isLive ? "Pause Feed" : "Resume Feed"}
            </button>
             <button onClick={runAIForensics} disabled={state.isAnalyzing || state.logs.length === 0} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2 shadow-lg shadow-emerald-900/20">
              <Cpu className="w-4 h-4" />
              Analyze
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8 scroll-smooth">
          {error && <div className="mb-6 p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl flex items-center gap-3"><AlertTriangle className="w-5 h-5" />{error}</div>}
          {successMsg && <div className="mb-6 p-4 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl flex items-center gap-3"><CheckCircle2 className="w-5 h-5" />{successMsg}</div>}

          {state.activeView === 'alerts' && (
            <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-300">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-bold text-white flex items-center gap-3">
                  <BellRing className="text-red-500" /> Security Alerts
                </h2>
                <button 
                  onClick={() => setState(prev => ({ ...prev, alerts: prev.alerts.map(a => ({ ...a, isRead: true })) }))}
                  className="text-xs text-slate-400 hover:text-white transition-colors"
                >
                  Mark all as read
                </button>
              </div>

              <div className="grid gap-4">
                {state.alerts.length === 0 && (
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
                    <div className="bg-slate-800 w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-4">
                      <ShieldCheck className="text-emerald-500" />
                    </div>
                    <h3 className="text-white font-medium mb-1">No active threats</h3>
                    <p className="text-slate-500 text-sm">Your DNS traffic appears clean.</p>
                  </div>
                )}
                {state.alerts.map((alert) => (
                  <div 
                    key={alert.id} 
                    className={`bg-slate-900 border rounded-xl p-5 transition-all hover:border-slate-700 ${alert.isRead ? 'border-slate-800 opacity-70' : 'border-red-500/30 bg-red-500/[0.02]'}`}
                    onClick={() => setState(prev => ({ ...prev, alerts: prev.alerts.map(a => a.id === alert.id ? { ...a, isRead: true } : a) }))}
                  >
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-500' : 'bg-orange-500/20 text-orange-500'}`}>
                          <AlertTriangle size={18} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold uppercase tracking-widest text-slate-500">{alert.type.replace('_', ' ')}</span>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                              alert.severity === 'CRITICAL' ? 'bg-red-500 text-white' : 
                              alert.severity === 'HIGH' ? 'bg-orange-500 text-white' : 'bg-yellow-500 text-black'
                            }`}>
                              {alert.severity}
                            </span>
                          </div>
                          <h3 className="text-white font-medium mt-1">{alert.message}</h3>
                        </div>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono">{new Date(alert.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between mt-4 pt-4 border-t border-slate-800/50">
                      <div className="flex items-center gap-4">
                        <button className="text-[10px] text-emerald-400 hover:underline flex items-center gap-1">
                          <Search size={12} /> Inspect Query
                        </button>
                        <button className="text-[10px] text-slate-400 hover:text-white flex items-center gap-1">
                          <Shield size={12} /> Block Source IP
                        </button>
                      </div>
                      {!alert.isRead && <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]" />}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {state.activeView === 'dashboard' && (
            <div className="space-y-8 animate-in fade-in duration-500">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard label="Live Queries/min" value={Math.floor(Math.random() * 20) + 10} subtext="Ingress" icon={<Wifi size={24} />} />
                <StatCard label="Tunnel Detections" value={state.logs.filter(l => l.label === 'Tunneling').length} subtext="Threat Pool" icon={<ShieldAlert size={24} />} />
                <StatCard label="Avg Payload Entropy" value={state.stats?.avgEntropy || 0} subtext="Statistical" icon={<Terminal size={24} />} />
                <StatCard label="Threat Index" value={state.report ? 88 : 14} subtext="Real-time" icon={<AlertTriangle size={24} />} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-6 flex items-center gap-2"><BarChart3 className="w-5 h-5 text-emerald-500" />Global Payload Distribution</h3>
                  <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                        <XAxis type="number" dataKey="length" name="Length" unit=" ch" stroke="#64748b" />
                        <YAxis type="number" dataKey="entropy" name="Entropy" stroke="#64748b" />
                        <ZAxis type="number" range={[60, 100]} />
                        <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#fff' }} />
                        <Scatter name="Queries" data={state.logs.slice(0, 100)}>
                          {state.logs.slice(0, 100).map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.label === 'Tunneling' ? '#ef4444' : '#10b981'} fillOpacity={0.6} />
                          ))}
                        </Scatter>
                      </ScatterChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
                  <h3 className="text-lg font-semibold mb-6 flex items-center gap-2 text-red-400"><ShieldAlert className="w-5 h-5" />Critical Detections</h3>
                  <div className="space-y-3">
                    {state.logs.filter(l => l.label === 'Tunneling').slice(0, 6).map((log) => (
                      <div key={log.id} className="p-3 bg-red-500/5 border border-red-500/10 rounded-lg group hover:bg-red-500/10 transition-all cursor-crosshair">
                        <div className="text-[10px] text-slate-500 mono flex justify-between mb-1">
                          <span>ID: {log.id}</span>
                          <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="text-xs font-mono text-red-400 truncate">{log.query}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {state.activeView === 'map' && (
            <div className="flex-1 flex flex-col space-y-4 animate-in fade-in duration-500">
               <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                  <div className="flex items-center gap-6">
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-1">Active Nodes</div>
                      <div className="text-xl font-bold font-mono text-white">{new Set(state.logs.filter(l => l.lat !== undefined).map(l => l.sourceIp)).size}</div>
                    </div>
                    <div className="w-px h-8 bg-slate-800" />
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-1">Global Hotspots</div>
                      <div className="text-xl font-bold font-mono text-orange-500">{new Set(state.logs.filter(l => l.label === 'Tunneling' && l.lat !== undefined).map(l => l.location)).size}</div>
                    </div>
                  </div>
                  <div className="text-xs text-slate-400 italic">Real-time geospatial telemetry active</div>
               </div>
               <div className="flex-1 min-h-0">
                  <WorldMap logs={state.logs} />
               </div>
            </div>
          )}

          {state.activeView === 'live' && (
            <div className="flex flex-col h-full space-y-4 animate-in fade-in duration-300">
               <div className="bg-slate-950 border border-slate-800 rounded-xl p-6 flex items-center justify-between shadow-inner">
                  <div className="flex items-center gap-8">
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-1">Sensor Status</div>
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
                        <span className="text-sm font-bold text-white uppercase tracking-tighter">Promiscuous Mode</span>
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-1">Frames Captured</div>
                      <div className="text-xl font-bold font-mono text-emerald-400">{state.logs.length}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-1">Peak Entropy</div>
                      <div className="text-xl font-bold font-mono text-orange-500">{Math.max(...state.logs.map(l => l.entropy), 0).toFixed(2)}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="p-2 bg-slate-900 rounded border border-slate-800 text-xs text-slate-400">Filtering: <b>NONE</b></div>
                  </div>
               </div>

               <div className="flex-1 bg-black border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col">
                  <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 flex justify-between items-center">
                    <div className="flex gap-4">
                      <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Live Traffic Stream</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-red-600 animate-pulse" />
                      <span className="text-[10px] font-bold text-red-500 uppercase">Live Trace</span>
                    </div>
                  </div>
                  <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-1 custom-scrollbar">
                    {state.liveLogs.length === 0 && (
                      <div className="h-full flex items-center justify-center text-slate-700 italic">Waiting for DNS ingress...</div>
                    )}
                    {state.liveLogs.map((log) => (
                      <div key={log.id} className={`flex items-start gap-4 p-2 rounded transition-all ${log.label === 'Tunneling' ? `bg-red-500/10 text-red-400 border-l-2 border-red-500 ${log.isNew ? 'animate-flash-red' : 'animate-pulse'}` : 'text-slate-400 hover:bg-white/5'}`}>
                        <span className="text-slate-600 shrink-0">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                        <span className={`shrink-0 font-bold w-12 text-center text-[10px] px-1 py-0.5 rounded border ${log.type === 'TXT' ? 'bg-amber-500/10 text-amber-500 border-amber-500/20' : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'}`}>{log.type}</span>
                        <span className="break-all flex-1">{log.query}</span>
                        <div className="shrink-0 flex items-center gap-1 text-[10px] text-slate-500 bg-slate-900/50 px-2 py-0.5 rounded border border-slate-800">
                          <MapPin className="w-3 h-3 text-emerald-500" />
                          {log.location || 'Resolving...'}
                        </div>
                        <span className={`shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded ${log.label === 'Tunneling' ? 'bg-red-600 text-white' : 'bg-slate-800 text-slate-400'}`}>
                          {log.label === 'Tunneling' ? 'ALERT' : 'OK'}
                        </span>
                        <span className="shrink-0 text-slate-600 text-[10px]">SRC: {log.sourceIp}</span>
                      </div>
                    ))}
                  </div>
               </div>
            </div>
          )}

          {state.activeView === 'logs' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden animate-in slide-in-from-bottom-4 shadow-2xl">
              <div className="p-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm space-y-4">
                <div className="flex justify-between items-center">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 w-4 h-4" />
                    <input 
                      placeholder="Search queries, IPs..." 
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="bg-slate-800 border border-slate-700 rounded-lg py-2 pl-10 pr-4 text-sm focus:ring-1 focus:ring-emerald-500 w-80 outline-none text-slate-200 transition-all focus:bg-slate-750" 
                    />
                  </div>
                  <div className="flex gap-2">
                    <button className="px-4 py-2 bg-slate-800 text-xs font-bold uppercase tracking-widest rounded-lg hover:bg-slate-700 transition-colors flex items-center gap-2 border border-slate-700">
                      <Download className="w-3 h-3" />
                      Export CSV
                    </button>
                    <button onClick={loadLogs} className="px-4 py-2 bg-emerald-600 text-xs font-bold uppercase tracking-widest rounded-lg hover:bg-emerald-500 transition-colors flex items-center gap-2 shadow-lg shadow-emerald-900/20">
                      <Activity className="w-3 h-3" />
                      Refresh Feed
                    </button>
                  </div>
                </div>

                <div className="flex flex-wrap gap-6 pt-2">
                  <FilterSelect 
                    label="Query Type" 
                    value={filterType} 
                    onChange={setFilterType}
                    options={[
                      { label: 'All Types', value: 'ALL' },
                      { label: 'A (IPv4)', value: 'A' },
                      { label: 'AAAA (IPv6)', value: 'AAAA' },
                      { label: 'TXT (Text)', value: 'TXT' },
                      { label: 'CNAME', value: 'CNAME' },
                      { label: 'MX (Mail)', value: 'MX' },
                    ]}
                  />
                  <FilterSelect 
                    label="Response Code" 
                    value={filterRCode} 
                    onChange={setFilterRCode}
                    options={[
                      { label: 'All Codes', value: 'ALL' },
                      { label: 'NOERROR', value: 'NOERROR' },
                      { label: 'NXDOMAIN', value: 'NXDOMAIN' },
                      { label: 'SERVFAIL', value: 'SERVFAIL' },
                      { label: 'REFUSED', value: 'REFUSED' },
                    ]}
                  />
                  <FilterSelect 
                    label="Threat Level" 
                    value={filterThreat} 
                    onChange={setFilterThreat}
                    options={[
                      { label: 'All Levels', value: 'ALL' },
                      { label: 'Critical (>80)', value: 'CRITICAL' },
                      { label: 'High (>50)', value: 'HIGH' },
                      { label: 'Medium (>20)', value: 'MEDIUM' },
                      { label: 'Low (≤20)', value: 'LOW' },
                    ]}
                  />
                  <FilterSelect 
                    label="Reputation" 
                    value={filterReputation} 
                    onChange={setFilterReputation}
                    options={[
                      { label: 'All Status', value: 'ALL' },
                      { label: 'Malicious', value: 'MALICIOUS' },
                      { label: 'Suspicious', value: 'SUSPICIOUS' },
                      { label: 'Clean', value: 'CLEAN' },
                      { label: 'Unknown', value: 'UNKNOWN' },
                    ]}
                  />
                  <div className="flex items-end pb-0.5">
                    <button 
                      onClick={() => {
                        setSearchTerm('');
                        setFilterType('ALL');
                        setFilterRCode('ALL');
                        setFilterThreat('ALL');
                        setFilterReputation('ALL');
                      }}
                      className="text-[10px] font-bold uppercase tracking-widest text-slate-500 hover:text-emerald-400 transition-colors"
                    >
                      Clear Filters
                    </button>
                  </div>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm border-collapse">
                  <thead>
                    <tr className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-widest border-b border-slate-800 font-bold">
                      <th className="px-6 py-4">Artifact ID</th>
                      <th className="px-6 py-4">Timestamp</th>
                      <th className="px-6 py-4">Source Origin</th>
                      <th className="px-6 py-4">Reputation</th>
                      <th className="px-6 py-4">Location</th>
                      <th className="px-6 py-4">Type</th>
                      <th className="px-6 py-4">DNS Query Payload</th>
                      <th className="px-6 py-4">RCode</th>
                      <th className="px-6 py-4 text-center">Threat Score</th>
                      <th className="px-6 py-4 text-center">Stats</th>
                      <th className="px-6 py-4 text-right">Detection Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {filteredLogs.map((log) => {
                      const isMalicious = log.label === 'Tunneling';
                      return (
                        <tr key={log.id} className={`transition-all duration-200 ${isMalicious ? 'bg-red-500/[0.03] hover:bg-red-500/[0.07]' : 'hover:bg-slate-800/30'}`}>
                          <td className="px-6 py-4 text-slate-600 mono text-[10px] select-all group">
                            <div className="flex items-center gap-2"><Fingerprint className={`w-3 h-3 ${isMalicious ? 'text-red-500/50' : 'text-slate-700'}`} />{log.id.toUpperCase()}</div>
                          </td>
                          <td className="px-6 py-4 text-slate-400 mono text-xs whitespace-nowrap">{new Date(log.timestamp).toLocaleTimeString()}</td>
                          <td className="px-6 py-4 text-slate-300 mono text-xs"><span className="bg-slate-800 px-2 py-0.5 rounded border border-slate-700">{log.sourceIp}</span></td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-2">
                              <div className={`w-2 h-2 rounded-full ${
                                log.reputation === 'MALICIOUS' ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]' :
                                log.reputation === 'SUSPICIOUS' ? 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]' :
                                log.reputation === 'CLEAN' ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]' :
                                'bg-slate-600'
                              }`} />
                              <span className={`text-[10px] font-bold uppercase tracking-tighter ${
                                log.reputation === 'MALICIOUS' ? 'text-red-500' :
                                log.reputation === 'SUSPICIOUS' ? 'text-orange-500' :
                                log.reputation === 'CLEAN' ? 'text-emerald-500' :
                                'text-slate-500'
                              }`}>
                                {log.reputation || 'UNKNOWN'}
                              </span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-2 text-xs text-slate-400">
                              <Globe className="w-3 h-3 text-emerald-500" />
                              {log.location || 'Unknown'}
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${log.type === 'TXT' ? 'bg-amber-500/10 text-amber-500 border-amber-500/20' : 'bg-slate-800 text-slate-400 border-slate-700'}`}>
                              {log.type}
                            </span>
                          </td>
                          <td className="px-6 py-4"><div className="max-w-md"><p className={`font-mono text-xs break-all leading-relaxed ${isMalicious ? 'text-red-400 font-semibold' : 'text-emerald-400/90'}`}>{log.query}</p>{isMalicious && <div className="flex items-center gap-2 mt-1"><span className="text-[9px] bg-red-500 text-white px-1 rounded font-bold uppercase tracking-tighter">High Entropy Payload</span></div>}</div></td>
                          <td className="px-6 py-4">
                            <span className={`text-[10px] font-mono ${log.responseCode === 'NXDOMAIN' ? 'text-red-400' : 'text-slate-500'}`}>
                              {log.responseCode}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-center">
                            <div className="flex flex-col items-center gap-1">
                              <span className={`text-xs font-bold ${
                                log.threatScore > 80 ? 'text-red-500' : 
                                log.threatScore > 50 ? 'text-orange-500' : 
                                log.threatScore > 20 ? 'text-yellow-500' : 'text-emerald-500'
                              }`}>
                                {log.threatScore}
                              </span>
                              <div className="w-12 h-1 bg-slate-800 rounded-full overflow-hidden">
                                <div 
                                  className={`h-full transition-all duration-500 ${
                                    log.threatScore > 80 ? 'bg-red-500' : 
                                    log.threatScore > 50 ? 'bg-orange-500' : 
                                    log.threatScore > 20 ? 'bg-yellow-500' : 'bg-emerald-500'
                                  }`} 
                                  style={{ width: `${log.threatScore}%` }} 
                                />
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex flex-col items-center gap-1">
                              <div className="flex items-center gap-3 text-[10px] mono"><span className="text-slate-500">LEN: <b className="text-slate-300">{log.length}</b></span><span className="text-slate-500">ENT: <b className={log.entropy > 4 ? 'text-orange-400' : 'text-slate-300'}>{log.entropy.toFixed(2)}</b></span></div>
                              <div className="w-16 h-1 bg-slate-800 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all duration-500 ${isMalicious ? 'bg-red-500' : 'bg-emerald-500'}`} style={{ width: `${Math.min(100, (log.entropy / 6) * 100)}%` }} /></div>
                            </div>
                          </td>
                          <td className="px-6 py-4 text-right">
                            <div className="inline-flex flex-col items-end gap-1">
                              <div className={`flex items-center gap-2 px-3 py-1 rounded-lg border text-[11px] font-bold uppercase tracking-tight shadow-sm ${isMalicious ? 'bg-red-500/10 text-red-500 border-red-500/20 shadow-red-500/5' : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20 shadow-emerald-500/5'}`}>{isMalicious ? <ShieldAlert className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}{log.label}</div>
                              <span className={`text-[10px] mono font-medium ${isMalicious ? 'text-red-400/70' : 'text-slate-500'}`}>Confidence: {(log.confidence! * 100).toFixed(1)}%</span>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {state.activeView === 'forensics' && (
            <div className="space-y-8 animate-in fade-in zoom-in-95 duration-500">
              {state.report ? (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                  <div className="lg:col-span-2 space-y-8">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
                      <div className="flex items-center justify-between mb-8">
                        <h2 className="text-2xl font-bold">Forensic Inspection Report</h2>
                        <div className={`px-4 py-1.5 rounded-full text-sm font-bold border ${threatColor(state.report.threatLevel)}`}>
                          {state.report.threatLevel} THREAT
                        </div>
                      </div>
                      
                      <div className="prose prose-invert max-w-none">
                        <h4 className="text-emerald-400 uppercase text-xs tracking-widest mb-2 font-bold">Executive Summary</h4>
                        <p className="text-slate-300 leading-relaxed mb-6 italic">{state.report.summary}</p>
                        
                        <h4 className="text-emerald-400 uppercase text-xs tracking-widest mb-4 font-bold">Remediation Steps</h4>
                        <div className="bg-slate-800/50 p-6 rounded-xl border border-emerald-500/20 text-sm text-slate-300 leading-relaxed">
                          {state.report.recommendation}
                        </div>
                      </div>
                    </div>

                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
                      <h4 className="text-emerald-400 uppercase text-xs tracking-widest mb-6 font-bold">Attack Timeline Reconstruction</h4>
                      <InteractiveTimeline timeline={state.report.timeline} />
                    </div>
                  </div>

                  <div className="space-y-8">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
                      <h4 className="text-emerald-400 uppercase text-xs tracking-widest mb-4 font-bold flex items-center gap-2"><Terminal className="w-4 h-4" />Network Artifacts (IOCs)</h4>
                      <div className="space-y-2">
                        {state.report.indicators.map((ioc, idx) => (
                          <div key={idx} className="bg-slate-800 px-3 py-2 rounded font-mono text-xs text-slate-300 break-all border-l-2 border-emerald-500">{ioc}</div>
                        ))}
                      </div>
                    </div>
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
                      <h4 className="text-red-400 uppercase text-xs tracking-widest mb-4 font-bold flex items-center gap-2"><AlertTriangle className="w-4 h-4" />Identified Tunnels</h4>
                      <div className="space-y-2">
                        {state.report.detectedTunnels.map((domain, idx) => (
                          <div key={idx} className="bg-red-500/5 px-3 py-2 rounded font-mono text-xs text-red-400 border border-red-500/20">{domain}</div>
                        ))}
                      </div>
                    </div>
                    <button className="w-full py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl font-bold flex items-center justify-center gap-3 transition-all shadow-lg shadow-emerald-900/40"><Download className="w-5 h-5" />Download Case File</button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center min-h-[500px] border-2 border-dashed border-slate-800 rounded-3xl text-center p-12 bg-slate-900/20 group">
                   <div className="w-20 h-20 bg-slate-900 border border-slate-800 rounded-2xl flex items-center justify-center mb-6 text-emerald-500 shadow-2xl group-hover:border-emerald-500/50 transition-all"><Cpu size={40} className={state.isAnalyzing ? "animate-spin" : ""} /></div>
                  <h2 className="text-2xl font-bold mb-3 text-white">AegisDNS Forensic Lab</h2>
                  <p className="text-slate-400 max-w-md mb-10 leading-relaxed">Ingest raw network traffic artifacts to classify covert patterns and generate comprehensive digital forensic reports.</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full max-w-2xl">
                    <button onClick={() => handleFileUpload('pcap')} className="p-8 bg-slate-900 border border-slate-800 rounded-2xl text-left hover:border-emerald-500/40 hover:bg-slate-800/40 transition-all group/btn"><FileSearch className="w-10 h-10 text-emerald-500 mb-4 group-hover/btn:scale-110 transition-transform" /><h4 className="text-base font-bold text-slate-100 uppercase mb-2 tracking-wide">PCAP Ingestion</h4><p className="text-xs text-slate-500 leading-relaxed">Binary packet capture analysis for deep-frame DNS payload extraction and decryption.</p></button>
                    <button onClick={() => handleFileUpload('log')} className="p-8 bg-slate-900 border border-slate-800 rounded-2xl text-left hover:border-emerald-500/40 hover:bg-slate-800/40 transition-all group/btn"><FileText className="w-10 h-10 text-emerald-400 mb-4 group-hover/btn:scale-110 transition-transform" /><h4 className="text-base font-bold text-slate-100 uppercase mb-2 tracking-wide">Zeek/Bind Logs</h4><p className="text-xs text-slate-500 leading-relaxed">Import structured DNS logs (TSV/CSV/TXT) from standard Intrusion Detection Systems.</p></button>
                  </div>
                </div>
              )}
            </div>
          )}

          {state.activeView === 'reports' && (
            <div className="max-w-4xl mx-auto animate-in slide-in-from-bottom-4">
              <div className="flex justify-between items-center mb-8">
                <div><h2 className="text-2xl font-bold">Investigation Repository</h2><p className="text-slate-500 text-sm">Historical forensic case files and detected patterns archive.</p></div>
                <button className="px-4 py-2 bg-emerald-600 rounded-lg text-sm font-medium hover:bg-emerald-500 transition-colors shadow-lg shadow-emerald-900/20">Export Workspace</button>
              </div>
              <div className="space-y-4">
                {state.report ? (
                  <div className="bg-slate-900 border border-emerald-500/30 p-6 rounded-xl flex items-center justify-between group hover:border-emerald-500 transition-all cursor-pointer">
                    <div className="flex items-center gap-5"><div className="w-12 h-12 bg-emerald-500/10 rounded-lg flex items-center justify-center text-emerald-400"><CheckCircle2 size={24} /></div><div><h4 className="font-semibold text-slate-200">Active_Investigation_{new Date().toLocaleDateString().replace(/\//g, '_')}.pdf</h4><p className="text-xs text-slate-500">Recently Generated • Threat Level: {state.report.threatLevel}</p></div></div>
                    <div className="flex items-center gap-3"><button className="p-2 text-slate-500 group-hover:text-emerald-400 transition-colors"><Download size={20} /></button></div>
                  </div>
                ) : null}
                {[1, 2].map(i => (
                  <div key={i} className="bg-slate-900 border border-slate-800 p-6 rounded-xl flex items-center justify-between group hover:border-emerald-500/50 transition-all cursor-pointer">
                    <div className="flex items-center gap-5"><div className="w-12 h-12 bg-slate-800 rounded-lg flex items-center justify-center text-emerald-400"><FileText size={24} /></div><div><h4 className="font-semibold text-slate-200">Historical_Incident_IR_00{i}.pdf</h4><p className="text-xs text-slate-500">Archived 2 days ago • Analyst: Aegis-Core</p></div></div>
                    <div className="flex items-center gap-3"><span className="text-[10px] font-bold px-2 py-0.5 bg-red-500/10 text-red-400 border border-red-500/20 rounded uppercase">Medium</span><button className="p-2 text-slate-500 group-hover:text-emerald-400 transition-colors"><Download size={20} /></button></div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default App;
