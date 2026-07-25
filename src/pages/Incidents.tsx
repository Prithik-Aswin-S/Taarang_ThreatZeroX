import { useEffect, useState } from "react";
import { FileSearch, ArrowLeft, Clock, Crosshair, Brain, ShieldCheck, ListChecks, FileText } from "lucide-react";
import { supabase } from "@/lib/supabase";
import { detectWithAI, explainDetection, recommendedActions } from "@/lib/ai";
import { eventsForChallenge } from "@/data/datasets";
import { getMitre } from "@/data/mitre";
import { Panel, Badge, severityTone } from "@/components/ui";
import type { Incident } from "@/types";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    const { data } = await supabase.from("incidents").select("*").order("created_at", { ascending: false }).limit(50);
    setIncidents((data as Incident[]) ?? []);
    setLoading(false);
  };

  useEffect(() => {
    (async () => {
      const { data, error } = await supabase.from("incidents").select("*").limit(1);
      if ((!data || data.length === 0) && !error) {
        const detections = detectWithAI([
          ...eventsForChallenge("T1059.001"),
          ...eventsForChallenge("T1003"),
          ...eventsForChallenge("T1053"),
          ...eventsForChallenge("T1550"),
          ...eventsForChallenge("T1190"),
        ]);
        const rows = detections.map((d) => ({
          incident_id: `INC-${d.event_id}`,
          attack_type: d.attack_type,
          mitre_technique: d.mitre_technique,
          severity: d.threat_score >= 85 ? "critical" : d.threat_score >= 65 ? "high" : "medium",
          threat_score: d.threat_score,
          status: "open",
          matched_events: eventsForChallenge(d.mitre_technique ?? "").filter((e) => e.is_malicious).slice(0, 5),
          ai_explanation: explainDetection(d),
          recommended_actions: recommendedActions(d.mitre_technique ?? ""),
        }));
        if (rows.length > 0) {
          await supabase.from("incidents").insert(rows);
        }
      }
      await load();
    })();
  }, []);

  if (loading) return <div className="text-slate-400 text-sm">Loading incidents...</div>;

  if (selected) {
    const mitre = getMitre(selected.mitre_technique ?? "");
    return (
      <div className="space-y-4">
        <button onClick={() => setSelected(null)} className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-cyan-300">
          <ArrowLeft className="h-4 w-4" /> Back to incidents
        </button>

        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-8 space-y-4">
            <Panel title="Attack Timeline" icon={<Clock className="h-4 w-4 text-cyan-400" />}>
              <div className="space-y-3">
                {selected.matched_events.map((e, i) => (
                  <div key={e.id} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="h-2 w-2 rounded-full bg-cyan-400 mt-1.5" />
                      {i < selected.matched_events.length - 1 && <div className="w-px flex-1 bg-slate-700" />}
                    </div>
                    <div className="glass rounded-lg p-3 flex-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-slate-400">{e.timestamp}</span>
                        <Badge tone="threat">malicious</Badge>
                      </div>
                      <div className="text-sm text-slate-200 mt-1 font-mono">{String(e.Image ?? e.Uri ?? e.EventID ?? "")}</div>
                      <div className="text-[11px] text-slate-500 mt-0.5 font-mono break-all">{String(e.CommandLine ?? e.Uri ?? "")}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="Matched Logs" icon={<FileText className="h-4 w-4 text-cyan-400" />}>
              <div className="space-y-1.5 max-h-64 overflow-y-auto">
                {selected.matched_events.map((e) => (
                  <pre key={e.id} className="text-[11px] font-mono text-slate-300 bg-[#0a0f1a] rounded p-2 break-all whitespace-pre-wrap">{JSON.stringify(e, null, 0).slice(0, 500)}</pre>
                ))}
              </div>
            </Panel>
          </div>

          <div className="col-span-4 space-y-4">
            <Panel title="Incident Overview" icon={<Crosshair className="h-4 w-4 text-cyan-400" />}>
              <div className="space-y-2">
                <div className="flex justify-between text-sm"><span className="text-slate-400">ID</span><span className="text-slate-200 font-mono">{selected.incident_id}</span></div>
                <div className="flex justify-between text-sm"><span className="text-slate-400">Attack</span><span className="text-slate-200">{selected.attack_type}</span></div>
                <div className="flex justify-between text-sm"><span className="text-slate-400">MITRE</span><span className="text-cyan-300">{selected.mitre_technique}</span></div>
                {mitre && <div className="text-[11px] text-slate-500">{mitre.name} · {mitre.tactic}</div>}
                <div className="flex justify-between text-sm"><span className="text-slate-400">Severity</span><Badge tone={severityTone(selected.severity)}>{selected.severity}</Badge></div>
                <div className="flex justify-between text-sm"><span className="text-slate-400">Threat Score</span><span className="text-red-400 font-bold">{selected.threat_score}/100</span></div>
                <div className="flex justify-between text-sm"><span className="text-slate-400">Status</span><Badge tone="warning">{selected.status}</Badge></div>
              </div>
            </Panel>

            <Panel title="AI Explanation" icon={<Brain className="h-4 w-4 text-cyan-400" />}>
              <div className="text-sm text-slate-300 leading-relaxed">{selected.ai_explanation ?? "No AI explanation available."}</div>
            </Panel>

            <Panel title="Recommended Actions" icon={<ListChecks className="h-4 w-4 text-cyan-400" />}>
              <ul className="space-y-2 text-sm text-slate-300">
                {selected.recommended_actions.map((a, i) => (
                  <li key={i} className="flex gap-2"><ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" /> {a}</li>
                ))}
              </ul>
            </Panel>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-white tracking-tight">Incident Investigation</h1>
        <p className="text-sm text-slate-400 mt-1">Detailed incident view — timeline, matched logs, MITRE mapping, AI explanation & response</p>
      </header>

      <Panel title="Incident Queue" icon={<FileSearch className="h-4 w-4 text-cyan-400" />}>
        {incidents.length === 0 ? (
          <div className="text-sm text-slate-500">No incidents yet. Run rules in the Sigma Detection Lab or generate AI detections to populate the queue.</div>
        ) : (
          <div className="space-y-2">
            {incidents.map((i) => (
              <button key={i.id} onClick={() => setSelected(i)} className="w-full text-left glass glass-hover rounded-lg p-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`h-2 w-2 rounded-full ${i.severity === "critical" ? "bg-red-500 pulse-ring" : i.severity === "high" ? "bg-amber-400" : "bg-cyan-400"}`} />
                  <div>
                    <div className="text-sm font-medium text-slate-200">{i.attack_type}</div>
                    <div className="text-[11px] text-slate-500">{i.incident_id} · {i.mitre_technique} · {new Date(i.timestamp).toLocaleString()}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-red-400 font-bold">{i.threat_score}</span>
                  <Badge tone={severityTone(i.severity)}>{i.severity}</Badge>
                  <Badge tone="warning">{i.status}</Badge>
                </div>
              </button>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
