import { useState } from "react";
import Editor from "@monaco-editor/react";
import { Play, GraduationCap, Target, Award, CheckCircle2, XCircle, ArrowLeft, Trophy } from "lucide-react";
import { CHALLENGES } from "@/data/challenges";
import { eventsForChallenge } from "@/data/datasets";
import { validateRule, runRule } from "@/lib/sigma";
import { supabase } from "@/lib/supabase";
import { getMitre } from "@/data/mitre";
import { Panel, Badge, MetricCard } from "@/components/ui";
import type { RunRuleResponse, ValidationResponse } from "@/types";

export default function AcademyPage() {
  const [active, setActive] = useState<string | null>(null);
  const [yaml, setYaml] = useState("");
  const [validation, setValidation] = useState<ValidationResponse | null>(null);
  const [result, setResult] = useState<RunRuleResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scoreSaved, setScoreSaved] = useState(false);

  const challenge = CHALLENGES.find((c) => c.id === active);

  const open = (id: string) => {
    const c = CHALLENGES.find((x) => x.id === id)!;
    setActive(id);
    setYaml(c.starterYaml);
    setValidation(null);
    setResult(null);
    setError(null);
  };

  const handleRun = async () => {
    if (!challenge) return;
    setRunning(true);
    setError(null);
    try {
      const v = await validateRule(yaml);
      setValidation(v);
      if (!v.valid) {
        setError("Fix validation errors before running.");
        setRunning(false);
        return;
      }
      const events = eventsForChallenge(challenge.mitre);
      const res = await runRule(yaml, events);
      setResult(res);
      const f1 = res.precision + res.recall > 0 ? (2 * res.precision * res.recall) / (res.precision + res.recall) : 0;
      const score = Math.round(f1 * 100);
      await supabase.from("challenge_scores").insert({
        challenge_title: challenge.title,
        mitre_technique: challenge.mitre,
        yaml_content: yaml,
        precision: res.precision,
        recall: res.recall,
        false_positive_rate: res.false_positive_rate,
        f1_score: Number(f1.toFixed(4)),
        score,
        matches: res.matches,
      });
      setScoreSaved(true);
      setTimeout(() => setScoreSaved(false), 2500);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  if (!challenge) {
    return (
      <div className="space-y-6">
        <header>
          <h1 className="text-2xl font-bold text-white tracking-tight">ThreatZero Detection Academy</h1>
          <p className="text-sm text-slate-400 mt-1">Gamified SOC training — build Sigma rules that catch real attacks</p>
        </header>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {CHALLENGES.map((c) => {
            const m = getMitre(c.mitre);
            return (
              <button key={c.id} onClick={() => open(c.id)} className="glass glass-hover rounded-xl p-5 text-left">
                <div className="flex items-center justify-between mb-3">
                  <GraduationCap className="h-6 w-6 text-cyan-400" />
                  <Badge tone={c.difficulty === "Expert" ? "threat" : c.difficulty === "Hard" ? "warning" : "cyber"}>{c.difficulty}</Badge>
                </div>
                <div className="text-sm font-semibold text-white">{c.title}</div>
                <div className="text-[11px] text-cyan-400 mt-1">{c.mitre}</div>
                {m && <div className="text-[11px] text-slate-500 mt-0.5">{m.tactic}</div>}
                <p className="text-xs text-slate-400 mt-2 line-clamp-2">{c.briefing}</p>
              </button>
            );
          })}
        </div>
      </div>
    );
  }

  const mitreInfo = getMitre(challenge.mitre);
  const f1 = result && result.precision + result.recall > 0 ? (2 * result.precision * result.recall) / (result.precision + result.recall) : 0;

  return (
    <div className="space-y-4">
      <button onClick={() => setActive(null)} className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-cyan-300">
        <ArrowLeft className="h-4 w-4" /> Back to challenges
      </button>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-4 space-y-4">
          <Panel title="Mission Briefing" icon={<Target className="h-4 w-4 text-cyan-400" />}>
            <div className="flex items-center gap-2 mb-2">
              <Badge tone="cyber">{challenge.mitre}</Badge>
              <Badge tone={challenge.difficulty === "Expert" ? "threat" : "warning"}>{challenge.difficulty}</Badge>
            </div>
            <h3 className="text-lg font-bold text-white">{challenge.title}</h3>
            {mitreInfo && <div className="text-xs text-slate-400 mt-1">{mitreInfo.name} · {mitreInfo.tactic}</div>}
            <p className="text-sm text-slate-300 mt-3 leading-relaxed">{challenge.briefing}</p>
            <div className="mt-4 glass rounded-lg p-3 text-xs">
              <div className="text-slate-500 uppercase text-[10px] mb-1">Targets</div>
              <div className="flex justify-between"><span className="text-slate-300">Precision ≥</span><span className="text-cyan-300">{(challenge.targetPrecision * 100).toFixed(0)}%</span></div>
              <div className="flex justify-between"><span className="text-slate-300">Recall ≥</span><span className="text-cyan-300">{(challenge.targetRecall * 100).toFixed(0)}%</span></div>
            </div>
          </Panel>

          {result && (
            <Panel title="Score" icon={<Award className="h-4 w-4 text-amber-400" />}>
              <div className="text-center py-2">
                <div className="text-5xl font-bold text-cyan-300">{Math.round(f1 * 100)}</div>
                <div className="text-xs text-slate-500 mt-1">F1 Score</div>
              </div>
              <div className="grid grid-cols-2 gap-2 mt-3">
                <MetricCard label="Precision" value={`${(result.precision * 100).toFixed(0)}%`} tone={result.precision >= challenge.targetPrecision ? "success" : "warning"} />
                <MetricCard label="Recall" value={`${(result.recall * 100).toFixed(0)}%`} tone={result.recall >= challenge.targetRecall ? "success" : "warning"} />
                <MetricCard label="FPR" value={`${(result.false_positive_rate * 100).toFixed(0)}%`} tone={result.false_positive_rate < 0.1 ? "success" : "threat"} />
                <MetricCard label="Matches" value={result.matches} tone="cyber" />
              </div>
              {scoreSaved && (
                <div className="mt-3 flex items-center gap-1.5 text-xs text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Score saved to leaderboard
                </div>
              )}
            </Panel>
          )}
        </div>

        <div className="col-span-8 space-y-4">
          <div className="flex justify-end">
            <button onClick={handleRun} disabled={running} className="btn-cyber rounded-lg px-5 py-2 text-sm flex items-center gap-2">
              <Play className="h-4 w-4" /> {running ? "Running..." : "Execute Rule"}
            </button>
          </div>

          <Panel title="Sigma Rule Editor" icon={<GraduationCap className="h-4 w-4 text-cyan-400" />} className="h-[420px]">
            <div className="h-full -m-4 rounded-b-xl overflow-hidden">
              <Editor
                height="100%"
                defaultLanguage="yaml"
                theme="vs-dark"
                value={yaml}
                onChange={(v) => setYaml(v ?? "")}
                options={{ minimap: { enabled: false }, fontSize: 13, fontFamily: "JetBrains Mono, monospace", scrollBeyondLastLine: false }}
              />
            </div>
          </Panel>

          {(validation || error) && (
            <Panel title="Validation" icon={<Target className="h-4 w-4 text-cyan-400" />}>
              {error && <div className="flex items-center gap-2 text-sm text-red-300"><XCircle className="h-4 w-4" /> {error}</div>}
              {validation && (
                <div className="space-y-2">
                  <div className={`flex items-center gap-2 ${validation.valid ? "text-emerald-400" : "text-red-400"}`}>
                    {validation.valid ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                    {validation.valid ? "Valid Sigma rule" : "Errors found"}
                  </div>
                  {validation.errors.map((e, i) => <div key={i} className="text-xs text-red-300 bg-red-500/5 border border-red-500/20 rounded px-2 py-1">{e}</div>)}
                  {validation.warnings.map((w, i) => <div key={i} className="text-xs text-amber-300 bg-amber-500/5 border border-amber-500/20 rounded px-2 py-1">{w}</div>)}
                </div>
              )}
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
