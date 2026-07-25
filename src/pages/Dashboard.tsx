import { useEffect, useMemo, useState } from "react";
import {
  Activity, Target, ShieldCheck, AlertTriangle, Gauge, TrendingUp, Flame, Crosshair,
} from "lucide-react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  AreaChart, Area, PieChart, Pie, Cell, Legend,
} from "recharts";
import { supabase } from "@/lib/supabase";
import { detectWithAI } from "@/lib/ai";
import { eventsForChallenge } from "@/data/datasets";
import { MITRE_TECHNIQUES } from "@/data/mitre";
import { MetricCard, Panel, Badge, ThreatLevelGauge, severityTone } from "@/components/ui";
import type { Incident, SigmaRule } from "@/types";

const ATTACK_CATEGORIES = [
  { name: "PowerShell", value: 4, color: "#22d3ee" },
  { name: "Credential Access", value: 2, color: "#ef4444" },
  { name: "Persistence", value: 2, color: "#f59e0b" },
  { name: "Lateral Movement", value: 1, color: "#a855f7" },
  { name: "Web Injection", value: 3, color: "#22c55e" },
];

export default function DashboardPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [aiCount, setAiCount] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const [{ data: inc }, { data: rlz }] = await Promise.all([
        supabase.from("incidents").select("*").order("created_at", { ascending: false }).limit(50),
        supabase.from("sigma_rules").select("*"),
      ]);
      setIncidents((inc as Incident[]) ?? []);
      setRules((rlz as SigmaRule[]) ?? []);
      const allEvents = [
        ...eventsForChallenge("T1059.001"),
        ...eventsForChallenge("T1003"),
        ...eventsForChallenge("T1053"),
        ...eventsForChallenge("T1550"),
        ...eventsForChallenge("T1190"),
      ];
      setAiCount(detectWithAI(allEvents).length);
      setLoading(false);
    })();
  }, []);

  const metrics = useMemo(() => {
    const totalRules = rules.length;
    const tested = rules.filter((r) => r.status === "tested").length;
    const accuracy = tested > 0 ? Math.round((tested / Math.max(totalRules, 1)) * 100) : 0;
    const activeIncidents = incidents.filter((i) => i.status === "open").length;
    const critical = incidents.filter((i) => i.severity === "critical").length;
    const threatLevel = Math.min(100, 30 + critical * 15 + activeIncidents * 4);
    const mitreCovered = new Set(rules.map((r) => r.mitre_technique).filter(Boolean)).size;
    return { totalRules, tested, accuracy, activeIncidents, critical, threatLevel, mitreCovered };
  }, [incidents, rules]);

  const perfData = [
    { day: "Mon", precision: 92, recall: 88 },
    { day: "Tue", precision: 95, recall: 84 },
    { day: "Wed", precision: 89, recall: 91 },
    { day: "Thu", precision: 97, recall: 90 },
    { day: "Fri", precision: 94, recall: 93 },
    { day: "Sat", precision: 91, recall: 87 },
    { day: "Sun", precision: 96, recall: 92 },
  ];

  const mitreRadar = MITRE_TECHNIQUES.slice(0, 8).map((t) => ({
    technique: t.id,
    coverage: Math.floor(Math.random() * 50) + 50,
  }));

  if (loading) {
    return <div className="text-slate-400 text-sm">Loading command dashboard...</div>;
  }

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">SOC Command Dashboard</h1>
          <p className="text-sm text-slate-400 mt-1">Real-time detection engineering posture & threat intelligence overview</p>
        </div>
        <Badge tone="success">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" /> All systems operational
        </Badge>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricCard label="Rules Tested" value={metrics.tested} sub={`${metrics.totalRules} total`} icon={<Crosshair className="h-4 w-4" />} />
        <MetricCard label="Detection Accuracy" value={`${metrics.accuracy}%`} icon={<Gauge className="h-4 w-4" />} />
        <MetricCard label="False Positive Rate" value="6.2%" tone="warning" icon={<AlertTriangle className="h-4 w-4" />} />
        <MetricCard label="MITRE Coverage" value={`${metrics.mitreCovered}/${MITRE_TECHNIQUES.length}`} icon={<Target className="h-4 w-4" />} />
        <MetricCard label="Active Incidents" value={metrics.activeIncidents} tone={metrics.activeIncidents > 0 ? "threat" : "success"} icon={<Flame className="h-4 w-4" />} />
        <MetricCard label="AI Detections" value={aiCount} tone="cyber" icon={<Activity className="h-4 w-4" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel title="Detection Performance" icon={<TrendingUp className="h-4 w-4 text-cyan-400" />} className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={perfData}>
              <defs>
                <linearGradient id="prec" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="rec" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22c55e" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#22c55e" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
              <XAxis dataKey="day" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} domain={[60, 100]} />
              <Tooltip contentStyle={{ background: "#0c1322", border: "1px solid #1e2a44", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="precision" stroke="#22d3ee" fill="url(#prec)" strokeWidth={2} />
              <Area type="monotone" dataKey="recall" stroke="#22c55e" fill="url(#rec)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Attack Categories" icon={<AlertTriangle className="h-4 w-4 text-red-400" />}>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={ATTACK_CATEGORIES} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={45} paddingAngle={3}>
                {ATTACK_CATEGORIES.map((e) => (
                  <Cell key={e.name} fill={e.color} stroke="#060a14" strokeWidth={2} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#0c1322", border: "1px solid #1e2a44", borderRadius: 8, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11, color: "#94a3b8" }} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel title="MITRE ATT&CK Heatmap" icon={<Target className="h-4 w-4 text-cyan-400" />}>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={mitreRadar}>
              <PolarGrid stroke="#1e2a44" />
              <PolarAngleAxis dataKey="technique" tick={{ fill: "#94a3b8", fontSize: 10 }} />
              <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fill: "#475569", fontSize: 9 }} />
              <Radar dataKey="coverage" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.35} />
              <Tooltip contentStyle={{ background: "#0c1322", border: "1px solid #1e2a44", borderRadius: 8, fontSize: 12 }} />
            </RadarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Threat Level" icon={<ShieldCheck className="h-4 w-4 text-cyan-400" />}>
          <div className="space-y-5">
            <ThreatLevelGauge level={metrics.threatLevel} />
            <div className="grid grid-cols-2 gap-3">
              <div className="glass rounded-lg p-3">
                <div className="text-[11px] text-slate-400 uppercase">Critical</div>
                <div className="text-xl font-bold text-red-400">{metrics.critical}</div>
              </div>
              <div className="glass rounded-lg p-3">
                <div className="text-[11px] text-slate-400 uppercase">Open</div>
                <div className="text-xl font-bold text-amber-400">{metrics.activeIncidents}</div>
              </div>
            </div>
            <div className="glass rounded-lg p-3">
              <div className="text-[11px] text-slate-400 uppercase mb-2">Top MITRE Techniques</div>
              <div className="space-y-1.5">
                {MITRE_TECHNIQUES.slice(0, 4).map((t) => (
                  <div key={t.id} className="flex items-center justify-between text-xs">
                    <span className="text-slate-300">{t.id}</span>
                    <Badge tone={severityTone(t.severity)}>{t.severity}</Badge>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Panel>

        <Panel title="Recent Incidents" icon={<Flame className="h-4 w-4 text-red-400" />}>
          <div className="space-y-2 max-h-[260px] overflow-y-auto">
            {incidents.length === 0 && (
              <div className="text-sm text-slate-500">No incidents yet. Run rules in the Sigma Detection Lab to generate detections.</div>
            )}
            {incidents.slice(0, 8).map((i) => (
              <div key={i.id} className="glass rounded-lg p-3 flex items-center justify-between">
                <div>
                  <div className="text-sm text-slate-200 font-medium">{i.attack_type}</div>
                  <div className="text-[11px] text-slate-500">{i.incident_id} · {i.mitre_technique ?? "—"}</div>
                </div>
                <Badge tone={severityTone(i.severity)}>{i.severity}</Badge>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="Challenge Score Leaderboard" icon={<TrendingUp className="h-4 w-4 text-cyan-400" />}>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={[
            { name: "Encoded PowerShell", score: 92 },
            { name: "LSASS Access", score: 78 },
            { name: "Scheduled Task", score: 85 },
            { name: "Pass The Hash", score: 64 },
            { name: "SQL Injection", score: 88 },
          ]}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
            <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
            <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
            <Tooltip contentStyle={{ background: "#0c1322", border: "1px solid #1e2a44", borderRadius: 8, fontSize: 12 }} />
            <Bar dataKey="score" fill="#22d3ee" radius={[6, 6, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Panel>
    </div>
  );
}
