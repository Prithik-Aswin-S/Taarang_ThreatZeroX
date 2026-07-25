import { useEffect, useMemo, useState } from "react";
import { Brain, Sparkles, ArrowRight, Copy, CheckCircle2 } from "lucide-react";
import { eventsForChallenge } from "@/data/datasets";
import { detectWithAI, explainDetection } from "@/lib/ai";
import { supabase } from "@/lib/supabase";
import { getMitre } from "@/data/mitre";
import { Panel, Badge } from "@/components/ui";
import type { AiDetection } from "@/types";

export default function AiAssistantPage() {
  const [detections, setDetections] = useState<AiDetection[]>([]);
  const [selected, setSelected] = useState<AiDetection | null>(null);
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState(false);

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

  const mitreInfo = useMemo(() => (selected ? getMitre(selected.mitre_technique ?? "") : null), [selected]);

  const copySigma = () => {
    if (!selected?.suggested_sigma) return;
    navigator.clipboard.writeText(selected.suggested_sigma);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const saveAsRule = async () => {
    if (!selected?.suggested_sigma) return;
    const titleMatch = selected.suggested_sigma.match(/^title:\s*(.+)$/m);
    await supabase.from("sigma_rules").insert({
      title: titleMatch ? titleMatch[1].trim() : `AI Rule - ${selected.mitre_technique}`,
      yaml_content: selected.suggested_sigma,
      mitre_technique: selected.mitre_technique,
      status: "draft",
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-white tracking-tight">AI Sigma Assistant</h1>
        <p className="text-sm text-slate-400 mt-1">ML threat detection → behaviour analysis → MITRE mapping → Sigma rule suggestion</p>
      </header>

      <div className="glass rounded-xl p-4 flex items-center gap-3 text-sm">
        <Sparkles className="h-5 w-5 text-cyan-400 shrink-0" />
        <span className="text-slate-300">Workflow: </span>
        <span className="text-cyan-300">Threat detected by ML</span>
        <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
        <span className="text-cyan-300">Analyse behaviour</span>
        <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
        <span className="text-cyan-300">Map MITRE technique</span>
        <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
        <span className="text-cyan-300">Suggest Sigma rule</span>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-4 space-y-2">
          <div className="text-[11px] uppercase text-slate-500 px-1">AI Detections ({detections.length})</div>
          <div className="space-y-2 max-h-[calc(100vh-280px)] overflow-y-auto">
            {detections.map((d) => {
              const m = getMitre(d.mitre_technique ?? "");
              return (
                <button
                  key={d.id}
                  onClick={() => setSelected(d)}
                  className={`w-full text-left glass glass-hover rounded-lg p-3 border transition-all ${selected?.id === d.id ? "border-cyan-500/40" : "border-slate-700/40"}`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-slate-200">{d.attack_type}</span>
                    <Badge tone={d.threat_score >= 75 ? "threat" : "warning"}>{d.threat_score}</Badge>
                  </div>
                  <div className="text-[11px] text-cyan-400 mt-1">{d.mitre_technique} · {m?.tactic}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">conf {d.confidence} · {d.model_version}</div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="col-span-8 space-y-4">
          {selected && mitreInfo && (
            <>
              <Panel title="AI Detection Analysis" icon={<Brain className="h-4 w-4 text-cyan-400" />}>
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div className="glass rounded-lg p-3">
                    <div className="text-[10px] text-slate-500 uppercase">Attack Type</div>
                    <div className="text-sm text-slate-200 font-medium">{selected.attack_type}</div>
                  </div>
                  <div className="glass rounded-lg p-3">
                    <div className="text-[10px] text-slate-500 uppercase">MITRE</div>
                    <div className="text-sm text-cyan-300 font-medium">{mitreInfo.id} — {mitreInfo.name}</div>
                  </div>
                  <div className="glass rounded-lg p-3">
                    <div className="text-[10px] text-slate-500 uppercase">Threat Score</div>
                    <div className="text-sm text-red-400 font-bold">{selected.threat_score}/100</div>
                  </div>
                  <div className="glass rounded-lg p-3">
                    <div className="text-[10px] text-slate-500 uppercase">Confidence</div>
                    <div className="text-sm text-emerald-400 font-bold">{(selected.confidence * 100).toFixed(0)}%</div>
                  </div>
                </div>
                <div className="glass rounded-lg p-3 text-sm text-slate-300 leading-relaxed">
                  <span className="text-cyan-400 font-medium">AI Explanation: </span>
                  {explainDetection(selected)}
                </div>
              </Panel>

              <Panel title="Suggested Sigma Rule" icon={<Sparkles className="h-4 w-4 text-cyan-400" />}
                actions={
                  <div className="flex gap-2">
                    <button onClick={copySigma} className="text-xs flex items-center gap-1 text-slate-400 hover:text-cyan-300">
                      {copied ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />} {copied ? "Copied" : "Copy"}
                    </button>
                    <button onClick={saveAsRule} className="text-xs flex items-center gap-1 text-slate-400 hover:text-cyan-300">
                      {saved ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : null} {saved ? "Saved" : "Save as rule"}
                    </button>
                  </div>
                }
              >
                <pre className="text-xs font-mono text-slate-200 bg-[#0a0f1a] rounded-lg p-4 overflow-x-auto whitespace-pre-wrap">{selected.suggested_sigma}</pre>
              </Panel>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
