import { useState } from "react";
import { Network, ShieldAlert, Crosshair, FileText, Download, Server, Clock, Globe, Activity, User, ChevronRight, X } from "lucide-react";
import { MITRE_TECHNIQUES, getMitre } from "@/data/mitre";
import { eventsForChallenge } from "@/data/datasets";
import { Panel, Badge, severityTone } from "@/components/ui";
import type { SecurityEvent, MitreTechnique } from "@/types";

interface AttackReport {
  technique: MitreTechnique;
  events: SecurityEvent[];
  maliciousEvents: SecurityEvent[];
  servers: string[];
  ips: string[];
  timestamps: string[];
  users: string[];
  attackTimeline: { time: string; event: string; detail: string }[];
}

function buildReport(technique: MitreTechnique): AttackReport {
  const events = eventsForChallenge(technique.id);
  const maliciousEvents = events.filter((e) => e.is_malicious);
  const servers = Array.from(
    new Set(
      events
        .map((e) => {
          const img = String(e.Image ?? e.ServiceFileName ?? e.SourceImage ?? "unknown");
          const parts = img.split("\\");
          return parts[parts.length - 1] ?? "unknown";
        })
        .filter(Boolean),
    ),
  );
  const ips = Array.from(
    new Set(
      events
        .map((e) => String(e.IpAddress ?? e.DestinationIp ?? e.ClientIP ?? ""))
        .filter(Boolean),
    ),
  );
  const timestamps = events.map((e) => e.timestamp).sort();
  const users = Array.from(
    new Set(
      events
        .map((e) => String(e.User ?? e.TargetUserName ?? e.Creator ?? ""))
        .filter(Boolean),
    ),
  );
  const attackTimeline = maliciousEvents.map((e) => ({
    time: e.timestamp,
    event: e.category,
    detail: String(e.CommandLine ?? e.Uri ?? e.TaskName ?? e.Action ?? e.Image ?? e.EventID ?? ""),
  }));
  return { technique, events, maliciousEvents, servers, ips, timestamps, users, attackTimeline };
}

function generatePdf(report: AttackReport) {
  const win = window.open("", "_blank");
  if (!win) return;
  const t = report.technique;
  const html = `<!DOCTYPE html><html><head><title>Incident Report — ${t.id}</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1e293b; }
    h1 { color: #0e7490; border-bottom: 2px solid #0891b2; padding-bottom: 8px; }
    h2 { color: #0e7490; margin-top: 24px; }
    table { width: 100%; border-collapse: collapse; margin: 12px 0; }
    th, td { border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; font-size: 13px; }
    th { background: #f1f5f9; color: #0e7490; }
    .header { display: flex; justify-content: space-between; align-items: center; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    .critical { background: #fef2f2; color: #dc2626; }
    .high { background: #fffbeb; color: #d97706; }
    .medium { background: #f0fdfa; color: #0d9488; }
    .meta { background: #f8fafc; padding: 16px; border-radius: 8px; margin: 16px 0; }
    .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .meta-item { font-size: 13px; }
    .meta-label { color: #64748b; font-size: 11px; text-transform: uppercase; }
    .footer { margin-top: 40px; border-top: 1px solid #cbd5e1; padding-top: 12px; font-size: 11px; color: #64748b; }
  </style></head><body>
  <div class="header">
    <div>
      <h1>ThreatZero Sentinel X — Incident Report</h1>
      <p style="color:#64748b;">AI-Powered Cyber Threat Intelligence & Detection Engineering Platform</p>
    </div>
    <div class="badge ${t.severity}">${t.severity.toUpperCase()}</div>
  </div>
  <div class="meta">
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-label">Attack Name</div><div><strong>${t.name}</strong></div></div>
      <div class="meta-item"><div class="meta-label">MITRE Technique</div><div><strong>${t.id}</strong></div></div>
      <div class="meta-item"><div class="meta-label">Tactic</div><div>${t.tactic}</div></div>
      <div class="meta-item"><div class="meta-label">Severity</div><div>${t.severity}</div></div>
      <div class="meta-item"><div class="meta-label">Generated</div><div>${new Date().toLocaleString()}</div></div>
      <div class="meta-item"><div class="meta-label">Total Events</div><div>${report.events.length}</div></div>
      <div class="meta-item"><div class="meta-label">Malicious Events</div><div>${report.maliciousEvents.length}</div></div>
      <div class="meta-item"><div class="meta-label">Affected Servers</div><div>${report.servers.join(", ") || "N/A"}</div></div>
      <div class="meta-item"><div class="meta-label">Source IPs</div><div>${report.ips.join(", ") || "N/A"}</div></div>
      <div class="meta-item"><div class="meta-label">Affected Users</div><div>${report.users.join(", ") || "N/A"}</div></div>
      <div class="meta-item"><div class="meta-label">First Seen</div><div>${report.timestamps[0] ?? "N/A"}</div></div>
      <div class="meta-item"><div class="meta-label">Last Seen</div><div>${report.timestamps[report.timestamps.length - 1] ?? "N/A"}</div></div>
    </div>
  </div>
  <h2>Technique Description</h2>
  <p>${t.description}</p>
  <h2>Attack Timeline</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Event Type</th><th>Detail</th></tr></thead>
    <tbody>
      ${report.attackTimeline.map((a) => `<tr><td>${a.time}</td><td>${a.event}</td><td style="font-family:monospace;font-size:11px;">${a.detail.substring(0, 120)}</td></tr>`).join("")}
    </tbody>
  </table>
  <h2>Malicious Events Detail</h2>
  <table>
    <thead><tr><th>Event ID</th><th>Timestamp</th><th>Category</th><th>Key Fields</th></tr></thead>
    <tbody>
      ${report.maliciousEvents.map((e) => `<tr><td>${e.id}</td><td>${e.timestamp}</td><td>${e.category}</td><td style="font-family:monospace;font-size:11px;">${Object.entries(e).filter(([k]) => !["id","timestamp","category","is_malicious"].includes(k)).map(([k,v]) => `${k}=${v}`).slice(0,3).join(" ")}</td></tr>`).join("")}
    </tbody>
  </table>
  <h2>Benign Events (for comparison)</h2>
  <table>
    <thead><tr><th>Event ID</th><th>Timestamp</th><th>Category</th></tr></thead>
    <tbody>
      ${report.events.filter((e) => !e.is_malicious).map((e) => `<tr><td>${e.id}</td><td>${e.timestamp}</td><td>${e.category}</td></tr>`).join("")}
    </tbody>
  </table>
  <div class="footer">
    <p>Generated by ThreatZero Sentinel X — Confidential. For authorized SOC analyst use only.</p>
    <p>Report ID: RPT-${t.id}-${Date.now()}</p>
  </div>
  <script>window.onload = () => { window.print(); }</script>
  </body></html>`;
  win.document.write(html);
  win.document.close();
}

export default function MitrePage() {
  const [selected, setSelected] = useState<AttackReport | null>(null);

  const tactics = Array.from(new Set(MITRE_TECHNIQUES.map((t) => t.tactic.split(",")[0].trim())));

  const openReport = (technique: MitreTechnique) => {
    setSelected(buildReport(technique));
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-white tracking-tight">MITRE ATT&CK Intelligence</h1>
        <p className="text-sm text-slate-400 mt-1">Technique mapping, tactic coverage, severity classification, and complete attack report visualization</p>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass rounded-xl p-4">
          <div className="text-[11px] uppercase text-slate-500">Techniques Tracked</div>
          <div className="text-2xl font-bold text-cyan-300">{MITRE_TECHNIQUES.length}</div>
        </div>
        <div className="glass rounded-xl p-4">
          <div className="text-[11px] uppercase text-slate-500">Tactics Covered</div>
          <div className="text-2xl font-bold text-cyan-300">{tactics.length}</div>
        </div>
        <div className="glass rounded-xl p-4">
          <div className="text-[11px] uppercase text-slate-500">Critical Techniques</div>
          <div className="text-2xl font-bold text-red-400">{MITRE_TECHNIQUES.filter((t) => t.severity === "critical").length}</div>
        </div>
        <div className="glass rounded-xl p-4">
          <div className="text-[11px] uppercase text-slate-500">High Severity</div>
          <div className="text-2xl font-bold text-amber-400">{MITRE_TECHNIQUES.filter((t) => t.severity === "high").length}</div>
        </div>
      </div>

      <Panel title="Technique Coverage Matrix — Click for Full Attack Report" icon={<Network className="h-4 w-4 text-cyan-400" />}>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {MITRE_TECHNIQUES.map((t) => (
            <button key={t.id} onClick={() => openReport(t)} className="text-left glass glass-hover rounded-lg p-4 border border-slate-700/40 hover:border-cyan-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-bold text-cyan-300">{t.id}</span>
                <div className="flex items-center gap-1.5">
                  <Badge tone={severityTone(t.severity)}>{t.severity}</Badge>
                  <ChevronRight className="h-3.5 w-3.5 text-slate-500" />
                </div>
              </div>
              <div className="text-sm font-medium text-slate-200">{t.name}</div>
              <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-1">
                <Crosshair className="h-3 w-3" /> {t.tactic}
              </div>
              <p className="text-xs text-slate-400 mt-2 leading-relaxed line-clamp-2">{t.description}</p>
            </button>
          ))}
        </div>
      </Panel>

      <Panel title="Tactic Coverage" icon={<ShieldAlert className="h-4 w-4 text-red-400" />}>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {tactics.map((tac) => {
            const techs = MITRE_TECHNIQUES.filter((t) => t.tactic.includes(tac));
            return (
              <div key={tac} className="glass rounded-lg p-3">
                <div className="text-sm font-semibold text-slate-200">{tac}</div>
                <div className="text-[11px] text-slate-500 mt-1">{techs.length} technique(s)</div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {techs.map((t) => (
                    <span key={t.id} className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 rounded px-1.5 py-0.5">{t.id}</span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      {/* Attack Report Modal */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onClick={() => setSelected(null)}>
          <div className="glass rounded-2xl max-w-4xl w-full max-h-[85vh] overflow-y-auto border border-cyan-500/30" onClick={(e) => e.stopPropagation()}>
            <div className="sticky top-0 z-10 flex items-center justify-between px-6 py-4 border-b border-slate-700/40 bg-[#0a0f1a]/95 backdrop-blur">
              <div className="flex items-center gap-2">
                <FileText className="h-5 w-5 text-cyan-400" />
                <h2 className="text-lg font-bold text-white">Attack Report — {selected.technique.id}</h2>
              </div>
              <div className="flex gap-2">
                <button onClick={() => generatePdf(selected)} className="btn-cyber rounded-lg px-3 py-1.5 text-xs flex items-center gap-1.5">
                  <Download className="h-3.5 w-3.5" /> Export PDF
                </button>
                <button onClick={() => setSelected(null)} className="rounded-lg p-1.5 text-slate-400 hover:text-white hover:bg-slate-700/30">
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-5">
              {/* Header */}
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h3 className="text-xl font-bold text-white">{selected.technique.name}</h3>
                  <div className="text-sm text-slate-400 mt-0.5">{selected.technique.tactic}</div>
                </div>
                <Badge tone={severityTone(selected.technique.severity)}>{selected.technique.severity.toUpperCase()}</Badge>
              </div>

              {/* Key facts grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="glass rounded-lg p-3">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase text-slate-500"><Server className="h-3 w-3" /> Servers</div>
                  <div className="text-sm text-slate-200 mt-1">{selected.servers.join(", ") || "N/A"}</div>
                </div>
                <div className="glass rounded-lg p-3">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase text-slate-500"><Globe className="h-3 w-3" /> Source IPs</div>
                  <div className="text-sm text-slate-200 mt-1">{selected.ips.join(", ") || "N/A"}</div>
                </div>
                <div className="glass rounded-lg p-3">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase text-slate-500"><User className="h-3 w-3" /> Affected Users</div>
                  <div className="text-sm text-slate-200 mt-1">{selected.users.join(", ") || "N/A"}</div>
                </div>
                <div className="glass rounded-lg p-3">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase text-slate-500"><Activity className="h-3 w-3" /> Events</div>
                  <div className="text-sm text-slate-200 mt-1">{selected.events.length} total, {selected.maliciousEvents.length} malicious</div>
                </div>
              </div>

              {/* Time range */}
              <div className="glass rounded-lg p-3 flex items-center gap-3">
                <Clock className="h-4 w-4 text-cyan-400" />
                <div className="text-sm">
                  <span className="text-slate-400">First seen: </span><span className="text-slate-200">{selected.timestamps[0] ?? "N/A"}</span>
                  <span className="text-slate-600 mx-2">→</span>
                  <span className="text-slate-400">Last seen: </span><span className="text-slate-200">{selected.timestamps[selected.timestamps.length - 1] ?? "N/A"}</span>
                </div>
              </div>

              {/* Description */}
              <div>
                <div className="text-[11px] uppercase text-slate-500 mb-1">Technique Description</div>
                <p className="text-sm text-slate-300 leading-relaxed">{selected.technique.description}</p>
              </div>

              {/* Attack timeline */}
              <div>
                <div className="text-[11px] uppercase text-slate-500 mb-2">Attack Timeline</div>
                <div className="space-y-2">
                  {selected.attackTimeline.map((a, i) => (
                    <div key={i} className="flex gap-3 items-start">
                      <div className="flex flex-col items-center">
                        <div className="h-2 w-2 rounded-full bg-red-400 mt-1.5" />
                        {i < selected.attackTimeline.length - 1 && <div className="w-0.5 h-6 bg-slate-700" />}
                      </div>
                      <div className="flex-1 glass rounded-lg p-2.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] text-cyan-400 font-mono">{a.time}</span>
                          <Badge tone="threat">{a.event}</Badge>
                        </div>
                        <div className="text-xs text-slate-300 mt-1 font-mono break-all">{a.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Malicious events table */}
              <div>
                <div className="text-[11px] uppercase text-slate-500 mb-2">Malicious Events Detail</div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-[10px] uppercase text-slate-500 border-b border-slate-700/40">
                        <th className="text-left py-1.5 px-2">Event ID</th>
                        <th className="text-left py-1.5 px-2">Timestamp</th>
                        <th className="text-left py-1.5 px-2">Category</th>
                        <th className="text-left py-1.5 px-2">Key Fields</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selected.maliciousEvents.map((e) => (
                        <tr key={e.id} className="border-b border-slate-700/20">
                          <td className="py-1.5 px-2 text-cyan-300 font-mono">{e.id}</td>
                          <td className="py-1.5 px-2 text-slate-400 font-mono">{e.timestamp}</td>
                          <td className="py-1.5 px-2 text-slate-300">{e.category}</td>
                          <td className="py-1.5 px-2 text-slate-400 font-mono text-[10px]">
                            {Object.entries(e).filter(([k]) => !["id","timestamp","category","is_malicious"].includes(k)).map(([k,v]) => `${k}=${v}`).slice(0,4).join("  ")}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
