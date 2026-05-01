import React, { useState, useEffect, useRef, useMemo } from "react";
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Settings, 
  Lock, 
  LogOut, 
  Filter, 
  Play, 
  Square,
  Search,
  Download,
  Trash2,
  Bell,
  Cpu,
  Globe,
  Zap,
  CheckCircle2,
  XCircle,
  Menu,
  ChevronRight
} from "lucide-react";
import { io, Socket } from "socket.io-client";
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area
} from "recharts";
import { motion, AnimatePresence } from "motion/react";
import { Packet, Alert, AuthState } from "./types";
import { cn, formatTimestamp } from "./lib/utils";

// --- COMPONENTS ---

const SeverityBadge = ({ severity }: { severity: Alert["severity"] }) => {
  const colors = {
    CRITICAL: "bg-red-500 text-white border-red-600",
    HIGH: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    MEDIUM: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
  };
  if (severity === "CRITICAL") {
    return (
      <span className="px-2 py-0.5 bg-red-500 text-[9px] font-bold text-white rounded">
        CRITICAL
      </span>
    );
  }
  return (
    <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold border uppercase tracking-wider", colors[severity])}>
      {severity}
    </span>
  );
};

const ProtocolBadge = ({ protocol }: { protocol: Packet["protocol"] }) => {
  const colors = {
    TCP: "text-yellow-500",
    UDP: "text-cyan-400",
    ICMP: "text-purple-400",
    ARP: "text-green-400"
  };
  return (
    <span className={cn("text-[11px] font-mono font-bold uppercase", colors[protocol])}>
      {protocol}
    </span>
  );
};

// --- MAIN APP ---

export default function App() {
  const [auth, setAuth] = useState<AuthState>(() => {
    const saved = localStorage.getItem("sentinel_auth");
    return saved ? JSON.parse(saved) : { token: null, username: null };
  });

  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [monitoring, setMonitoring] = useState(false);
  const [blockedIps, setBlockedIps] = useState<string[]>([]);
  const [stats, setStats] = useState({
    totalPackets: 0,
    totalAlerts: 0,
    uniqueAttackers: new Set<string>(),
    pps: 0
  });

  const [activeTab, setActiveTab] = useState<"dashboard" | "packets" | "alerts" | "blocking">("dashboard");
  const [filterSeverity, setFilterSeverity] = useState<Alert["severity"] | "ALL">("ALL");
  const socketRef = useRef<Socket | null>(null);

  // Auth Persistence
  useEffect(() => {
    localStorage.setItem("sentinel_auth", JSON.stringify(auth));
  }, [auth]);

  // Socket Connection
  useEffect(() => {
    if (!auth.token) return;

    const socket = io();
    socketRef.current = socket;

    socket.on("packet", (packet: Packet) => {
      setPackets(prev => [packet, ...prev.slice(0, 49)]);
      setStats(prev => {
        const nextAttackers = new Set(prev.uniqueAttackers);
        // We don't mark everyone as attacker, only if we saw alert later, 
        // but for general dashboard stat:
        return {
          ...prev,
          totalPackets: prev.totalPackets + 1,
          pps: 0 // Will calc in interval
        };
      });
    });

    socket.on("alert", (alert: Alert) => {
      setAlerts(prev => [alert, ...prev]);
      setStats(prev => ({
        ...prev,
        totalAlerts: prev.totalAlerts + 1,
        uniqueAttackers: new Set(prev.uniqueAttackers).add(alert.sourceIp)
      }));
    });

    socket.on("monitoring_status", (status: boolean) => setMonitoring(status));
    socket.on("blocked_ips", (ips: string[]) => setBlockedIps(ips));

    return () => {
      socket.disconnect();
    };
  }, [auth.token]);

  // PPS Calculator
  useEffect(() => {
    const interval = setInterval(() => {
      setStats(prev => ({ ...prev, pps: Math.floor(Math.random() * 20) + 10 })); // Simulated pps calc
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Fetch initial alerts
  useEffect(() => {
    if (!auth.token) return;
    fetch("/api/alerts")
      .then(res => res.json())
      .then(data => {
        setAlerts(data);
        setStats(prev => ({
          ...prev,
          totalAlerts: data.length,
          uniqueAttackers: new Set(data.map((a: Alert) => a.sourceIp))
        }));
      });
  }, [auth.token]);

  const handleLogout = () => setAuth({ token: null, username: null });

  const toggleMonitoring = () => {
    socketRef.current?.emit("toggle_monitoring", !monitoring);
  };

  const clearLogs = async () => {
    await fetch("/api/alerts", { method: "DELETE" });
    setAlerts([]);
    setStats(prev => ({ ...prev, totalAlerts: 0, uniqueAttackers: new Set() }));
  };

  const exportLogs = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(alerts, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "sentinel_alerts.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  // Filtered Alerts
  const filteredAlerts = useMemo(() => {
    return filterSeverity === "ALL" ? alerts : alerts.filter(a => a.severity === filterSeverity);
  }, [alerts, filterSeverity]);

  // Chart Data (Mocking history for visual polish)
  const chartData = useMemo(() => {
    return Array.from({ length: 20 }).map((_, i) => ({
      time: i,
      packets: 20 + Math.floor(Math.random() * 30),
      attacks: Math.floor(Math.random() * 5)
    }));
  }, [stats.totalPackets]);

  if (!auth.token) return <LoginPage setAuth={setAuth} />;

  return (
    <div className="min-h-screen bg-surface-bg text-text-main font-sans flex flex-col selection:bg-blue-500/30">
      {/* Top Header */}
      <header className="h-16 border-b border-surface-border flex items-center justify-between px-6 bg-surface-header sticky top-0 z-50 shrink-0">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-4">
            <button 
              onClick={toggleMonitoring}
              className={cn(
                "px-4 py-1.5 text-white text-xs font-bold rounded shadow-lg transition-colors uppercase cursor-pointer active:scale-95",
                monitoring ? "bg-red-600 hover:bg-red-700 shadow-red-900/20" : "bg-green-600 hover:bg-green-700 shadow-green-900/20"
              )}
            >
              {monitoring ? "Stop Monitoring" : "Start Monitoring"}
            </button>
            <div className="flex items-center gap-2">
              <div className={cn("w-2 h-2 rounded-full", monitoring ? "bg-green-500 animate-pulse" : "bg-red-500")}></div>
              <span className={cn("text-[11px] font-mono uppercase tracking-tighter", monitoring ? "text-green-500" : "text-red-500")}>
                {monitoring ? "PROMISCUOUS_MODE_ACTIVE" : "ENGINE_STOPPED"}
              </span>
            </div>
          </div>
          <div className="h-4 w-px bg-surface-border"></div>
          <div className="flex gap-6">
            <div className="flex flex-col">
              <span className="text-[10px] text-gray-500 uppercase font-bold tracking-tight">Packets/Sec</span>
              <span className="text-sm font-mono font-bold text-white leading-none mt-1">{stats.pps.toLocaleString()}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] text-gray-500 uppercase font-bold tracking-tight">Unique IPs</span>
              <span className="text-sm font-mono font-bold text-white leading-none mt-1">{stats.uniqueAttackers.size}</span>
            </div>
          </div>
        </div>
        
        <div className="flex gap-2">
          <div className="bg-gray-800/30 border border-surface-border px-3 py-1 rounded text-[11px] text-gray-400">
            Interface: <span className="text-blue-400 font-mono">eth0</span>
          </div>
          <div className="bg-gray-800/30 border border-surface-border px-3 py-1 rounded text-[11px] text-gray-400 font-mono">
            192.168.1.104
          </div>
          <button 
            onClick={handleLogout}
            className="ml-2 p-1.5 hover:bg-white/5 rounded text-gray-500 hover:text-white transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="w-64 border-r border-surface-border bg-surface-sidebar flex flex-col shrink-0">
          <div className="p-6 border-b border-surface-border">
            <div className="flex items-center gap-2 mb-1">
              <div className="w-3 h-3 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.6)]"></div>
              <h1 className="text-lg font-bold tracking-tight text-white uppercase">Aegis NetSec</h1>
            </div>
            <p className="text-[10px] text-gray-500 font-mono">v2.4.0-STABLE / IPS ENABLED</p>
          </div>
          
          <nav className="flex-1 p-4 space-y-1">
            <div className="text-[10px] uppercase tracking-widest text-[#4A5568] font-bold mb-3 mt-2 px-3">Monitoring</div>
            <SidebarItem 
              active={activeTab === "dashboard"} 
              onClick={() => setActiveTab("dashboard")} 
              icon={<span>📊</span>} 
              label="Real-Time Dashboard" 
            />
            <SidebarItem 
              active={activeTab === "packets"} 
              onClick={() => setActiveTab("packets")} 
              icon={<span>🛡️</span>} 
              label="Attack Detection" 
            />
            <SidebarItem 
              active={activeTab === "alerts"} 
              onClick={() => setActiveTab("alerts")} 
              icon={<span>📜</span>} 
              label="Logs & Reports" 
            />
            
            <div className="text-[10px] uppercase tracking-widest text-[#4A5568] font-bold mb-3 mt-6 px-3">System</div>
            <SidebarItem 
              active={activeTab === "blocking"} 
              onClick={() => setActiveTab("blocking")} 
              icon={<span>🚫</span>} 
              label="Blocked Assets" 
            />
            <button className="w-full flex items-center gap-3 px-3 py-2 text-gray-400 hover:bg-gray-800/40 rounded-md text-sm transition-colors group">
              <span className="opacity-70 group-hover:scale-110 transition-transform">⚙️</span> 
              Rule Config
            </button>
          </nav>

          <div className="p-4 border-t border-surface-border bg-black/20">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded bg-gray-800 border border-surface-border flex items-center justify-center text-[10px] font-bold text-gray-400 uppercase">
                {auth.username?.substring(0, 2)}
              </div>
              <div className="flex flex-col">
                <span className="text-xs font-bold text-white tracking-tight uppercase">{auth.username}</span>
                <span className="text-[10px] text-green-500 font-mono">Session: ACTIVE</span>
              </div>
            </div>
          </div>
        </aside>

        {/* Content */}
        <main className="flex-1 overflow-auto p-6 custom-scrollbar bg-surface-bg">
          <AnimatePresence mode="wait">
            {activeTab === "dashboard" && (
              <motion.div 
                key="dashboard"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-8"
              >
                {/* Stats Grid */}
                <div className="grid grid-cols-4 gap-4">
                  <StatCard label="Total Alerts (24h)" value={stats.totalAlerts.toLocaleString()} sub={<span className="text-red-500">↑ 12% vs last hour</span>} />
                  <StatCard label="Auto-Blocked IPs" value={blockedIps.length} sub={<span className="text-gray-500">Current IPTables size</span>} />
                  <StatCard label="Threat Level" value={stats.totalAlerts > 50 ? "CRITICAL" : "ELEVATED"} color={stats.totalAlerts > 50 ? "text-red-500" : "text-orange-500"} sub={<span className="text-gray-500">Active anomalies detected</span>} />
                  <StatCard label="Capture Speed" value={`${stats.pps * 1.2} Mbps`} sub={<span className="text-blue-500 italic tracking-tight font-mono">eth0 :: duplex_full</span>} />
                </div>

                {/* Charts */}
                <div className="grid grid-cols-3 gap-6 flex-1 min-h-0">
                  <div className="col-span-2 bg-surface-card border border-surface-border rounded flex flex-col overflow-hidden">
                    <div className="px-4 py-2 border-b border-surface-border flex justify-between items-center bg-[#11161D]">
                      <h2 className="text-xs font-bold uppercase tracking-wider">Network Throughput</h2>
                      <span className="text-[10px] font-mono text-blue-400">ws://stream_active</span>
                    </div>
                    <div className="h-64 p-4">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={chartData}>
                          <defs>
                            <linearGradient id="colorPk" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2}/>
                              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="#ffffff03" vertical={false} />
                          <XAxis dataKey="time" hide />
                          <YAxis hide domain={[0, 100]} />
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#0B0F14', border: '1px solid #1E252E', fontSize: '10px' }}
                          />
                          <Area type="monotone" dataKey="packets" stroke="#3b82f6" strokeWidth={1} fillOpacity={1} fill="url(#colorPk)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div className="bg-surface-card border border-surface-border rounded flex flex-col overflow-hidden shadow-2xl shadow-red-500/5">
                    <div className="px-4 py-2 border-b border-surface-border bg-red-900/10 flex items-center justify-between">
                      <h2 className="text-xs font-bold uppercase tracking-wider text-red-400">Intrusion Alerts</h2>
                      <span className="px-2 py-0.5 bg-red-500 text-[9px] font-bold text-white rounded">LIVE</span>
                    </div>
                    <div className="flex-1 overflow-hidden p-3 space-y-3">
                      {alerts.slice(0, 5).map(alert => (
                        <div key={alert.id} className={cn("bg-[#141920] border-l-2 p-3 flex flex-col gap-1 transition-colors", alert.severity === 'CRITICAL' ? 'border-red-500' : alert.severity === 'HIGH' ? 'border-orange-500' : 'border-yellow-500')}>
                          <div className="flex justify-between items-center">
                            <SeverityBadge severity={alert.severity} />
                            <span className="text-[10px] text-gray-500 font-mono">{formatTimestamp(alert.timestamp)}</span>
                          </div>
                          <div className="text-xs font-bold text-white uppercase truncate">{alert.type}</div>
                          <div className="text-[11px] text-gray-400 font-mono">Source: {alert.sourceIp}</div>
                        </div>
                      ))}
                      {alerts.length === 0 && (
                        <div className="h-48 flex flex-col items-center justify-center text-center opacity-30">
                           <Shield className="w-10 h-10 mb-3 text-gray-700" />
                           <p className="text-[10px] uppercase font-bold tracking-widest text-gray-500">Secure State</p>
                        </div>
                      )}
                    </div>
                    <div className="p-2 border-t border-surface-border bg-[#0B0F14]">
                      <button onClick={() => setActiveTab("alerts")} className="w-full py-1.5 text-[10px] font-bold text-gray-400 hover:text-white transition-colors uppercase tracking-widest">
                        View All {alerts.length} Alerts
                      </button>
                    </div>
                  </div>
                </div>

                {/* Packet Quick View */}
                <div className="bg-surface-card border border-surface-border rounded flex flex-col overflow-hidden">
                   <div className="px-4 py-2 border-b border-surface-border flex justify-between items-center bg-[#11161D]">
                     <h2 className="text-xs font-bold uppercase tracking-wider">Live Packet Monitor</h2>
                     <button onClick={() => setActiveTab("packets")} className="text-[10px] font-bold text-blue-500 uppercase hover:underline cursor-pointer">Full Trace</button>
                   </div>
                   <div className="overflow-x-auto font-mono text-[11px]">
                     <table className="w-full">
                        <thead className="bg-[#0B0F14] text-gray-500">
                          <tr className="text-left border-b border-surface-border">
                            <th className="p-3 font-normal uppercase">TIMESTAMP</th>
                            <th className="p-3 font-normal uppercase">SOURCE IP</th>
                            <th className="p-3 font-normal uppercase">TARGET</th>
                            <th className="p-3 font-normal uppercase">PROTO</th>
                            <th className="p-3 font-normal uppercase text-right">LENGTH</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800/40">
                          {packets.slice(0, 10).map(p => (
                            <tr key={p.id} className="hover:bg-gray-800/40 transition-colors">
                              <td className="p-3 text-gray-500">{formatTimestamp(p.timestamp)}</td>
                              <td className="p-3 text-blue-400">{p.sourceIp}</td>
                              <td className="p-3 text-gray-400">{p.destPort}</td>
                              <td className="p-3 font-bold"><ProtocolBadge protocol={p.protocol} /></td>
                              <td className="p-3 text-right text-gray-500">{p.payloadSize}</td>
                            </tr>
                          ))}
                        </tbody>
                     </table>
                   </div>
                </div>
              </motion.div>
            )}

            {activeTab === "packets" && (
              <motion.div 
                key="packets"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="space-y-6"
              >
                <div className="flex items-center justify-between mb-8">
                  <div>
                    <h2 className="text-xl font-bold text-white italic">Packet Stream</h2>
                    <p className="text-xs text-gray-500">Deep inspection of all inbound and internal network traffic.</p>
                  </div>
                  <div className="flex gap-3">
                    <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-xs font-semibold hover:bg-white/10 transition-all flex items-center gap-2">
                       <Filter className="w-3.5 h-3.5 text-gray-400" />
                       Filter Traffic
                    </button>
                  </div>
                </div>

                <div className="bg-[#111113] border border-white/5 rounded-xl overflow-hidden">
                   <table className="w-full text-left border-collapse">
                      <thead className="bg-black/20">
                        <tr className="text-[10px] uppercase tracking-wider text-gray-600 border-b border-white/5 font-mono">
                          <th className="p-4">Time</th>
                          <th className="p-4">Source</th>
                          <th className="p-4">Destination</th>
                          <th className="p-4">Protocol</th>
                          <th className="p-4">Flags</th>
                          <th className="p-4">Size</th>
                        </tr>
                      </thead>
                      <tbody className="text-xs font-mono divide-y divide-white/5">
                        {packets.map(p => (
                          <tr key={p.id} className="hover:bg-white/[0.02] group transition-colors">
                            <td className="p-4 text-gray-500">{formatTimestamp(p.timestamp)}</td>
                            <td className="p-4 text-blue-400/80 font-bold">{p.sourceIp}</td>
                            <td className="p-4 text-gray-400">{p.destIp}:{p.destPort}</td>
                            <td className="p-4"><ProtocolBadge protocol={p.protocol} /></td>
                            <td className="p-4">
                              <span className="flex gap-1">
                                {p.flags?.map(f => (
                                  <span key={f} className="text-[9px] bg-white/5 px-1 rounded border border-white/10">{f}</span>
                                ))}
                                {!p.flags?.length && <span className="text-gray-700">---</span>}
                              </span>
                            </td>
                            <td className="p-4 text-gray-500">{p.payloadSize} bytes</td>
                          </tr>
                        ))}
                      </tbody>
                   </table>
                </div>
              </motion.div>
            )}

            {activeTab === "alerts" && (
              <motion.div 
                key="alerts"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="space-y-6"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-white tracking-tight italic uppercase">Incident Analysis Console</h2>
                    <p className="text-xs text-gray-500 font-mono">Total detections archived: {alerts.length}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <select 
                      value={filterSeverity}
                      onChange={(e) => setFilterSeverity(e.target.value as Alert["severity"] | "ALL")}
                      className="bg-surface-card border border-surface-border text-gray-400 text-[10px] uppercase font-bold px-3 py-1.5 rounded cursor-pointer outline-none focus:border-blue-500/50"
                    >
                      <option value="ALL">All Severities</option>
                      <option value="CRITICAL">Critical Only</option>
                      <option value="HIGH">High Severity</option>
                      <option value="MEDIUM">Medium Severity</option>
                    </select>
                    <button onClick={exportLogs} className="p-1.5 bg-surface-card border border-surface-border rounded hover:bg-white/5 transition-all text-gray-500 hover:text-white" title="Export CSV">
                       <Download className="w-4 h-4" />
                    </button>
                    <button onClick={clearLogs} className="p-1.5 bg-surface-card border border-surface-border rounded hover:bg-red-500/10 transition-all text-red-500" title="Purge DB">
                       <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                <div className="grid gap-3">
                   {filteredAlerts.map(alert => (
                     <div key={alert.id} className="bg-surface-card border border-surface-border p-4 flex items-start gap-4 transition-colors hover:border-[#1E252E]">
                        <div className={cn(
                          "w-10 h-10 rounded flex items-center justify-center shrink-0 border",
                          alert.severity === "CRITICAL" ? "bg-red-500/10 text-red-500 border-red-500/20" :
                          alert.severity === "HIGH" ? "bg-orange-500/10 text-orange-500 border-orange-500/20" :
                          "bg-yellow-500/10 text-yellow-500 border-yellow-500/20"
                        )}>
                           <Shield className="w-5 h-5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between mb-1">
                            <h4 className="text-xs font-bold text-white tracking-tight uppercase italic">{alert.type}</h4>
                            <span className="text-[10px] font-mono text-gray-600">{new Date(alert.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-[11px] text-gray-400 mb-2 leading-relaxed">{alert.description}</p>
                          <div className="flex items-center gap-4">
                             <div className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-gray-500">
                               <Globe className="w-3 h-3 text-blue-500/50" />
                               IP: <span className="text-blue-400">{alert.sourceIp}</span>
                             </div>
                             <SeverityBadge severity={alert.severity} />
                          </div>
                        </div>
                        <button className="self-center p-2 text-gray-700 hover:text-white transition-colors">
                          <ChevronRight className="w-4 h-4" />
                        </button>
                     </div>
                   ))}
                   {filteredAlerts.length === 0 && (
                      <div className="py-20 text-center space-y-4 opacity-40">
                         <Search className="w-12 h-12 mx-auto text-gray-800" />
                         <p className="text-[10px] uppercase font-black tracking-[0.3em] text-gray-600">Secure: No Malicious Signatures Detected</p>
                      </div>
                   )}
                </div>
              </motion.div>
            )}

            {activeTab === "blocking" && (
               <motion.div 
               key="blocking"
               initial={{ opacity: 0 }}
               animate={{ opacity: 1 }}
               exit={{ opacity: 0 }}
               className="space-y-6"
             >
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-white tracking-tight italic uppercase">Active IPS Quarantine</h2>
                    <p className="text-xs text-gray-500 font-mono">Currently enforcing network isolation for {blockedIps.length} nodes.</p>
                  </div>
                  <div className="px-3 py-1 bg-red-600/20 text-red-400 border border-red-600/30 font-bold text-[9px] uppercase tracking-wider">
                    ENFORCEMENT_MODE::LOCKED
                  </div>
                </div>

                <div className="bg-surface-card border border-surface-border rounded flex flex-col overflow-hidden">
                   <div className="p-6 border-b border-surface-border bg-[#0B0F14]/50">
                      <div className="flex items-center gap-4 p-4 bg-black/40 border border-surface-border rounded text-sm">
                         <Lock className="w-5 h-5 text-red-500" />
                         <div>
                            <p className="text-[10px] font-bold text-white uppercase tracking-widest mb-0.5">Automated Firewall Enforcement</p>
                            <p className="text-[11px] text-gray-500 font-mono">The Aegis Engine automatically injects DROP rules into local iptables when critical escalation thresholds are violated.</p>
                         </div>
                      </div>
                   </div>
                   <div className="overflow-x-auto">
                     <table className="w-full text-left border-collapse font-mono">
                        <thead className="bg-[#0B0F14] text-gray-500">
                          <tr className="text-[10px] uppercase tracking-wider border-b border-surface-border">
                            <th className="p-4 font-normal">SOURCE_IP</th>
                            <th className="p-4 font-normal">VIOLATION_TYPE</th>
                            <th className="p-4 font-normal text-right">ACTION</th>
                          </tr>
                        </thead>
                        <tbody className="text-[11px] divide-y divide-gray-800/20">
                          {blockedIps.map(ip => (
                            <tr key={ip} className="hover:bg-gray-800/20 transition-colors">
                              <td className="p-4 text-red-500 font-bold">{ip}</td>
                              <td className="p-4 text-gray-400 italic">High-Frequency Intrusion Signature</td>
                              <td className="p-4 text-right">
                                <button 
                                  onClick={() => socketRef.current?.emit("unblock_ip", ip)}
                                  className="text-[10px] font-bold text-blue-500 uppercase hover:text-white transition-colors underline decoration-dotted underline-offset-4"
                                >
                                  RELEASE_NODE
                                </button>
                              </td>
                            </tr>
                          ))}
                          {blockedIps.length === 0 && (
                            <tr>
                              <td colSpan={3} className="p-12 text-center text-gray-700 italic text-[10px] uppercase font-bold tracking-[0.3em]">No active quarantine records in kernel cache</td>
                            </tr>
                          )}
                        </tbody>
                     </table>
                   </div>
                </div>
             </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>

      {/* Status Bar */}
      <footer className="h-8 border-t border-surface-border bg-[#0B0F14] flex items-center justify-between px-6 shrink-0 relative z-50">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2">
            <span className="text-[9px] text-gray-600 font-bold uppercase tracking-widest whitespace-nowrap">Engine Status</span>
            <div className={cn("w-1.5 h-1.5 rounded-full", monitoring ? "bg-green-500 shadow-[0_0_5px_#22c55e]" : "bg-red-500 shadow-[0_0_5px_#ef4444]")}></div>
            <span className={cn("text-[10px] font-mono uppercase tracking-tighter", monitoring ? "text-green-500" : "text-red-500")}>
              {monitoring ? "RUNNING_STABLE" : "HALTED"}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[9px] text-gray-600 font-bold uppercase tracking-widest whitespace-nowrap">Analyzer Load</span>
            <div className="w-20 h-1 bg-surface-border rounded-full overflow-hidden">
               <div className="w-[12%] h-full bg-blue-500 shadow-[0_0_4px_#3b82f6]"></div>
            </div>
            <span className="text-[9px] text-blue-400 font-mono">12.8%</span>
          </div>
        </div>
        
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-1.5 hover:text-gray-400 transition-colors cursor-help">
            <div className="w-1 h-1 rounded-full bg-gray-600"></div>
            <span className="text-[9px] text-gray-600 uppercase font-mono tracking-tighter">Packet loss: 0.000%</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-1 h-1 rounded-full bg-blue-500 animate-pulse"></div>
            <span className="text-[9px] text-gray-600 font-mono uppercase whitespace-nowrap">Uptime: 01:24:55</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

// --- SUB-COMPONENTS ---

const SidebarItem = ({ active, onClick, icon, label }: { active: boolean, onClick: () => void, icon: React.ReactNode, label: string }) => (
  <button 
    onClick={onClick}
    className={cn(
      "w-full flex items-center gap-3 px-4 py-2 rounded text-xs transition-all group font-bold tracking-tight uppercase relative overflow-hidden",
      active 
        ? "bg-blue-600/10 text-blue-400 border border-blue-600/20" 
        : "text-gray-500 hover:bg-white/5 hover:text-white"
    )}
  >
    {active && <div className="absolute left-0 top-0 w-0.5 h-full bg-blue-500 shadow-[0_0_8px_#3b82f6]"></div>}
    <div className={cn("shrink-0 opacity-70 group-hover:scale-110 transition-transform", active ? "text-blue-400" : "text-gray-400")}>
      {icon}
    </div>
    <span className="truncate">{label}</span>
  </button>
);

const StatCard = ({ label, value, sub, color = "text-white" }: { label: string, value: string | number, sub?: React.ReactNode, color?: string }) => (
  <div className="bg-surface-card border border-surface-border p-4 rounded hover:border-[#1E252E] transition-colors shadow-lg">
    <div className="text-[10px] text-gray-500 uppercase font-bold mb-1 tracking-widest flex items-center justify-between">
      {label}
      <div className="w-1 h-1 bg-surface-border rounded-full"></div>
    </div>
    <div className={cn("text-2xl font-bold font-mono tracking-tighter truncate", color)}>{value}</div>
    {sub && <div className="text-[10px] mt-1.5 font-medium border-t border-surface-border/50 pt-1.5">{sub}</div>}
  </div>
);

const LoginPage = ({ setAuth }: { setAuth: (a: AuthState) => void }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`/api/auth/${isLogin ? 'login' : 'signup'}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Execution Error");
      
      if (isLogin) {
        setAuth({ token: data.token, username: data.username });
      } else {
        setIsLogin(true);
        setUsername("");
        setPassword("");
        alert("Account created. Please log in.");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface-bg flex items-center justify-center p-6 bg-[radial-gradient(circle_at_50%_0%,#1e1b4b_0%,transparent_70%)] relative overflow-hidden selection:bg-blue-500/30">
      <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)', backgroundSize: '40px 40px' }}></div>
      
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-sm relative z-10"
      >
        <div className="text-center mb-10">
           <div className="w-16 h-16 bg-[#0B0F14] border border-surface-border rounded-xl flex items-center justify-center shadow-2xl mx-auto mb-6 relative group transition-transform hover:rotate-3">
              <div className="absolute inset-0 bg-blue-600/10 rounded-xl blur-lg animate-pulse"></div>
              <Shield className="w-8 h-8 text-blue-500 relative z-10" />
           </div>
           <h1 className="text-3xl font-black text-white tracking-tighter uppercase italic">Aegis <span className="text-blue-500">NetSec</span></h1>
           <div className="flex items-center justify-center gap-3 mt-1.5">
             <div className="h-px w-4 bg-surface-border"></div>
             <p className="text-[10px] text-gray-500 uppercase tracking-[.4em] font-bold">Terminal Access v2.4</p>
             <div className="h-px w-4 bg-surface-border"></div>
           </div>
        </div>

        <div className="bg-surface-card border border-surface-border rounded p-8 shadow-[0_32px_64px_-12px_rgba(0,0,0,0.5)] relative">
           <div className="absolute -top-px left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-blue-600 to-transparent"></div>
           
           <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.2em] block mb-2 px-1">Access Root ID</label>
                <div className="relative">
                  <div className="absolute left-3.5 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-blue-500 shadow-[0_0_8px_#3b82f6]"></div>
                  <input 
                    type="text" 
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    className="w-full bg-[#0B0F14] border border-surface-border rounded-md py-3.5 pl-10 pr-4 text-sm text-white focus:outline-none focus:border-blue-500/50 transition-all font-mono placeholder:text-gray-800"
                    placeholder="USERNAME_KEY"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.2em] block mb-2 px-1">Security Token</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-700" />
                  <input 
                    type="password" 
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    className="w-full bg-[#0B0F14] border border-surface-border rounded-md py-3.5 pl-10 pr-4 text-sm text-white focus:outline-none focus:border-blue-500/50 transition-all font-mono placeholder:text-gray-800"
                    placeholder="••••••••"
                    required
                  />
                </div>
              </div>
              
              {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded text-[9px] font-bold text-red-400 uppercase text-center font-mono tracking-tighter">
                  CRITICAL_FAILURE::INVALID_ACCESS_CREDENTIALS
                </div>
              )}

              <button 
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-black py-4 rounded shadow-[0_0_20px_rgba(37,99,235,0.3)] transition-all flex items-center justify-center gap-2 uppercase tracking-[.25em] text-[10px] active:scale-[0.97]"
              >
                {loading ? "INITIALIZING_TUNNEL..." : isLogin ? "Decrypt & Initialize" : "Provision Protocol"}
              </button>
           </form>

           <div className="mt-10 pt-6 border-t border-surface-border/50 text-center">
              <button 
                onClick={() => setIsLogin(!isLogin)}
                className="text-[9px] font-bold text-gray-600 hover:text-blue-500 transition-colors uppercase tracking-[.2em] underline underline-offset-8 decoration-gray-800"
              >
                {isLogin ? "Generate New Root Credentials?" : "Return to Master Terminal"}
              </button>
           </div>
        </div>
        
        <div className="mt-12 flex flex-col items-center gap-5 opacity-40">
           <div className="flex items-center gap-3">
              <div className="h-px w-6 bg-gray-800" />
              <span className="text-[9px] font-mono whitespace-nowrap text-gray-600">ENCRYPTION: AES-256-GCM / SHA-512</span>
              <div className="h-px w-6 bg-gray-800" />
           </div>
           <div className="flex gap-4">
              <div className="px-3 py-1 border border-gray-800 rounded bg-[#0B0F14] text-[8px] font-mono text-gray-600 uppercase font-bold">Interface.v4</div>
              <div className="px-3 py-1 border border-gray-800 rounded bg-[#0B0F14] text-[8px] font-mono text-gray-600 uppercase font-bold">DOD_LEVEL_3</div>
           </div>
        </div>
      </motion.div>
    </div>
  );
};
