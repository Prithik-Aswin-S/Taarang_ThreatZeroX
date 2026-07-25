import { useEffect, useState } from "react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Cell } from "recharts";
import { Cpu, Brain } from "lucide-react";
import { eventsForChallenge } from "@/data/datasets";
import { detectWithAI, explainDetection } from "@/lib/ai";
import { Panel, Badge } from "@/components/ui";
import type { AiDetection } from "@/types";

export default function ExplainabilityPage() {
  const [detections, setDetections] = useState<AiDetection[]>([]);
  const [selected, setSelected] = useState<AiDetection | null>(null);

  useEffect(() => {
    const all = [
      ...eventsForChallenge("T1059.001"),
      ...eventsForChallenge("T1003"),
      ...eventsForChallenge("T1053"),
      ...eventsForChallenge("T1550"),
      ...eventsForChallenge("T1190"),
    ];
    const dets = detectWithAI(all);
    setDetections(dets);
    setSelected(dets[0] ?? null);
  }, []);

  const chartData = selected?.shap_features.map((f) => ({ name: f.feature, value: f.contribution })) ?? [];
  const colors = ["#22d3ee", "#0891b2", "#f59e0b", "#ef4444"];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-white tracking-tight">Explainable AI (SHAP)</h1>
        <p className="text-sm text-slate-400 mt-1">Understand why the model flagged each event — feature contribution breakdown</p>
      </header>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-4 space-y-2">
          <div className="text-[11px] uppercase text-slate-500 px-1">Detections</div>
          <div className="space-y-2 max-h-[calc(100vh-220px)] overflow-y-auto">
            {detections.map((d) => (
              <button
                key={d.id}
                onClick={() => setSelected(d)}
                className={`w-full text-left glass glass-hover rounded-lg p-3 border transition-all ${selected?.id === d.id ? "border-cyan-500/40" : "border-slate-700/40"}`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-slate-200">{d.attack_type}</span>
                  <Badge tone={d.threat_score >= 75 ? "threat" : "warning"}>{d.threat_score}</Badge>
                </div>
                <div className="text-[11px] text-cyan-400 mt-0.5">{d.mitre_technique}</div>
              </button>
            ))}
          </div>
        </div>

        <div className="col-span-8 space-y-4">
          {selected && (
            <>
              <Panel title="Why was this detected?" icon={<Brain className="h-4 w-4 text-cyan-400" />}>
                <div className="glass rounded-lg p-3 text-sm text-slate-300 leading-relaxed mb-4">
                  {explainDetection(selected)}
                </div>
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={chartData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
                    <XAxis type="number" stroke="#64748b" fontSize={11} domain={[0, 50]} unit="%" />
                    <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={11} width={180} />
                    <Tooltip contentStyle={{ background: "#0c1322", border: "1px solid #1e2a44", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                      {chartData.map((_, i) => (
                        <Cell key={i} fill={colors[i % colors.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </Panel>

              <Panel title="Feature Contribution Breakdown" icon={<Cpu className="h-4 w-4 text-cyan-400" />}>
                <div className="space-y-3">
                  {selected.shap_features.map((f, i) => (
                    <div key={f.feature}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-slate-300">{f.feature}</span>
                        <span className="text-cyan-300">{f.contribution}%</span>
                      </div>
                      <div className="h-2 rounded-full bg-slate-700/50 overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${f.contribution * 2}%`, background: colors[i % colors.length] }} />
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-4 glass rounded-lg p-3 text-xs text-slate-400">
                  Model: <span className="text-cyan-300">{selected.model_version}</span> · Confidence: <span className="text-emerald-400">{(selected.confidence * 100).toFixed(0)}%</span> · Event: <span className="text-slate-300">{selected.event_id}</span>
                </div>
              </Panel>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
