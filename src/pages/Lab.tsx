import { useEffect, useState } from "react";
import Editor from "@monaco-editor/react";
import { Play, ShieldCheck, AlertTriangle, CheckCircle2, XCircle, Save, Download, Crosshair, Gauge } from "lucide-react";
import { validateRule, runRule } from "@/lib/sigma";
import { supabase } from "@/lib/supabase";
import { eventsForChallenge } from "@/data/datasets";
import { Panel, Badge, MetricCard } from "@/components/ui";
import { recommendedActions } from "@/lib/ai";
import { getMitre } from "@/data/mitre";
import type { SecurityEvent, ValidationResponse, RunRuleResponse } from "@/types";

const DATASET_OPTIONS = [
  { key: "T1059.001", label: "Process Creation (PowerShell)" },
  { key: "T1003", label: "Sysmon Process (LSASS)" },
  { key: "T1053", label: "Scheduled Tasks" },
  { key: "T1550", label: "Logon Events (PtH)" },
  { key: "T1190", label: "Web Access Logs" },
];

const DEFAULT_YAML = `title: Suspicious Encoded PowerShell Execution
id: a1b2c3d4-0000-0000-0000-000000000001
status: experimental
description: Detects PowerShell launched with an encoded command payload.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains:
      - powershell
    CommandLine|contains:
      - -EncodedCommand
      - -enc
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
`;

export default function LabPage() {
  const [yaml, setYaml] = useState(DEFAULT_YAML);
  const [datasetKey, setDatasetKey] = useState("T1059.001");
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [validation, setValidation] = useState<ValidationResponse | null>(null);
  const [runResult, setRunResult] = useState<RunRuleResponse | null>(null);
  const [validating, setValidating] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setEvents(eventsForChallenge(datasetKey));
    setRunResult(null);
  }, [datasetKey]);

  const handleValidate = async () => {
    setValidating(true);
    setError(null);
    try {
      const res = await validateRule(yaml);
      setValidation(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setValidating(false);
    }
  };

  const handleRun = async () => {
    setRunning(true);
    setError(null);
    try {
      const v = await validateRule(yaml);
      setValidation(v);
      if (!v.valid) {
        setError("Rule is not valid. Fix errors before running.");
        setRunning(false);
        return;
      }
      const res = await runRule(yaml, events);
      setRunResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const handleSave = async () => {
    setError(null);
    try {
      const titleMatch = yaml.match(/^title:\s*(.+)$/m);
      const title = titleMatch ? titleMatch[1].trim() : "Untitled Rule";
      const mitreMatch = yaml.match(/attack\.t(\d{4}(?:\.\d{3})?)/i);
      const mitre = mitreMatch ? `T${mitreMatch[1]}` : null;
      await supabase.from("sigma_rules").insert({
        title,
        yaml_content: yaml,
        mitre_technique: mitre,
        status: "tested",
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const downloadRule = () => {
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "sigma-rule.yml";
    a.click();
    URL.revokeObjectURL(url);
  };

  const mitre = runResult && validation?.rule ? (yaml.match(/attack\.t(\d{4}(?:\.\d{3})?)/i)?.[0]?.replace("attack.", "").toUpperCase()) : null;
  const mitreInfo = mitre ? getMitre(mitre) : null;

  return (
    <div className="space-y-4">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Sigma Detection Lab</h1>
          <p className="text-sm text-slate-400 mt-1">Author, validate, and execute Sigma rules against realistic security datasets</p>
        </div>
        <div className="flex gap-2">
          <button onClick={handleValidate} disabled={validating} className="btn-cyber rounded-lg px-4 py-2 text-sm flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" /> {validating ? "Validating..." : "Validate"}
          </button>
          <button onClick={handleRun} disabled={running} className="btn-cyber rounded-lg px-4 py-2 text-sm flex items-center gap-2">
            <Play className="h-4 w-4" /> {running ? "Running..." : "Run Detection"}
          </button>
          <button onClick={handleSave} className="rounded-lg px-4 py-2 text-sm flex items-center gap-2 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 transition-colors">
            <Save className="h-4 w-4" /> {saved ? "Saved!" : "Save"}
          </button>
          <button onClick={downloadRule} className="rounded-lg px-3 py-2 text-sm flex items-center gap-2 border border-slate-600 text-slate-300 hover:bg-slate-700/30 transition-colors">
            <Download className="h-4 w-4" />
          </button>
        </div>
      </header>

      {error && (
        <div className="glass rounded-lg p-3 border-red-500/40 flex items-center gap-2 text-sm text-red-300">
          <XCircle className="h-4 w-4" /> {error}
        </div>
      )}

      <div className="grid grid-cols-12 gap-4 h-[calc(100vh-220px)]">
        {/* Left: Monaco editor */}
        <div className="col-span-5 flex flex-col">
          <Panel title="Sigma YAML Editor" icon={<Crosshair className="h-4 w-4 text-cyan-400" />} className="flex-1">
            <div className="h-full -m-4 rounded-b-xl overflow-hidden">
              <Editor
                height="100%"
                defaultLanguage="yaml"
                theme="vs-dark"
                value={yaml}
                onChange={(v) => setYaml(v ?? "")}
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  fontFamily: "JetBrains Mono, Fira Code, monospace",
                  lineNumbers: "on",
                  scrollBeyondLastLine: false,
                  padding: { top: 12 },
                  smoothScrolling: true,
                }}
              />
            </div>
          </Panel>
        </div>

        {/* Center: dataset selection */}
        <div className="col-span-3 flex flex-col gap-4">
          <Panel title="Dataset Selection" icon={<Gauge className="h-4 w-4 text-cyan-400" />}>
            <div className="space-y-2">
              {DATASET_OPTIONS.map((d) => (
                <button
                  key={d.key}
                  onClick={() => setDatasetKey(d.key)}
                  className={`w-full text-left rounded-lg px-3 py-2 text-sm transition-all border ${
                    datasetKey === d.key
                      ? "bg-cyan-500/10 border-cyan-500/40 text-cyan-300"
                      : "border-slate-700/40 text-slate-300 hover:bg-slate-700/30"
                  }`}
                >
                  {d.label}
                </button>
              ))}
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-center">
              <div className="glass rounded-lg p-2">
                <div className="text-lg font-bold text-slate-200">{events.length}</div>
                <div className="text-[10px] text-slate-500 uppercase">Events</div>
              </div>
              <div className="glass rounded-lg p-2">
                <div className="text-lg font-bold text-red-400">{events.filter((e) => e.is_malicious).length}</div>
                <div className="text-[10px] text-slate-500 uppercase">Malicious</div>
              </div>
              <div className="glass rounded-lg p-2">
                <div className="text-lg font-bold text-emerald-400">{events.filter((e) => !e.is_malicious).length}</div>
                <div className="text-[10px] text-slate-500 uppercase">Benign</div>
              </div>
            </div>
          </Panel>

          <Panel title="Event Preview" className="flex-1">
            <div className="space-y-1.5 overflow-y-auto max-h-[calc(100%-0px)] pr-1">
              {events.map((e) => (
                <div key={e.id} className={`rounded-md px-2 py-1.5 text-[11px] font-mono border ${e.is_malicious ? "bg-red-500/5 border-red-500/20 text-red-200" : "bg-slate-700/20 border-slate-700/30 text-slate-300"}`}>
                  <div className="flex items-center justify-between">
                    <span>{e.id}</span>
                    <Badge tone={e.is_malicious ? "threat" : "success"}>{e.is_malicious ? "malicious" : "benign"}</Badge>
                  </div>
                  <div className="truncate text-slate-500">{String(e.Image ?? e.Uri ?? e.EventID ?? "")}</div>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        {/* Right: validation + results */}
        <div className="col-span-4 flex flex-col gap-4">
          <Panel title="Validation" icon={<ShieldCheck className="h-4 w-4 text-cyan-400" />}>
            {!validation ? (
              <div className="text-sm text-slate-500">Click Validate to check YAML structure, detection fields, and condition logic.</div>
            ) : (
              <div className="space-y-3">
                <div className={`flex items-center gap-2 ${validation.valid ? "text-emerald-400" : "text-red-400"}`}>
                  {validation.valid ? <CheckCircle2 className="h-5 w-5" /> : <XCircle className="h-5 w-5" />}
                  <span className="font-semibold">{validation.valid ? "Rule is valid" : "Rule has errors"}</span>
                </div>
                {validation.errors.length > 0 && (
                  <div className="space-y-1">
                    {validation.errors.map((e, i) => (
                      <div key={i} className="text-xs text-red-300 bg-red-500/5 border border-red-500/20 rounded px-2 py-1">{e}</div>
                    ))}
                  </div>
                )}
                {validation.warnings.length > 0 && (
                  <div className="space-y-1">
                    {validation.warnings.map((w, i) => (
                      <div key={i} className="text-xs text-amber-300 bg-amber-500/5 border border-amber-500/20 rounded px-2 py-1">{w}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </Panel>

          <Panel title="Detection Results" icon={<Crosshair className="h-4 w-4 text-cyan-400" />} className="flex-1">
            {!runResult ? (
              <div className="text-sm text-slate-500">Run detection to see matches and accuracy metrics.</div>
            ) : (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2">
                  <MetricCard label="Matches" value={runResult.matches} tone="cyber" />
                  <MetricCard label="Precision" value={`${(runResult.precision * 100).toFixed(1)}%`} tone={runResult.precision >= 0.8 ? "success" : "warning"} />
                  <MetricCard label="Recall" value={`${(runResult.recall * 100).toFixed(1)}%`} tone={runResult.recall >= 0.8 ? "success" : "warning"} />
                  <MetricCard label="False Positive Rate" value={`${(runResult.false_positive_rate * 100).toFixed(1)}%`} tone={runResult.false_positive_rate < 0.1 ? "success" : "threat"} />
                  <MetricCard label="F1 Score" value={`${(runResult.f1_score * 100).toFixed(1)}%`} tone="cyber" />
                  <MetricCard label="Accuracy" value={`${(runResult.accuracy * 100).toFixed(1)}%`} tone="success" />
                </div>
                <div className="glass rounded-lg p-3">
                  <div className="text-[10px] uppercase text-slate-500 mb-2">Confusion Matrix</div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="rounded border border-emerald-500/30 bg-emerald-500/10 p-2 text-center">
                      <div className="text-lg font-bold text-emerald-300">{runResult.confusion_matrix.true_positives}</div>
                      <div className="text-[10px] text-slate-500">True Positives</div>
                    </div>
                    <div className="rounded border border-amber-500/30 bg-amber-500/10 p-2 text-center">
                      <div className="text-lg font-bold text-amber-300">{runResult.confusion_matrix.false_positives}</div>
                      <div className="text-[10px] text-slate-500">False Positives</div>
                    </div>
                    <div className="rounded border border-red-500/30 bg-red-500/10 p-2 text-center">
                      <div className="text-lg font-bold text-red-300">{runResult.confusion_matrix.false_negatives}</div>
                      <div className="text-[10px] text-slate-500">False Negatives</div>
                    </div>
                    <div className="rounded border border-cyan-500/30 bg-cyan-500/10 p-2 text-center">
                      <div className="text-lg font-bold text-cyan-300">{runResult.confusion_matrix.true_negatives}</div>
                      <div className="text-[10px] text-slate-500">True Negatives</div>
                    </div>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-2 text-center">Executed in {runResult.execution_time_ms}ms</div>
                </div>
                {mitreInfo && (
                  <div className="glass rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-semibold text-cyan-300">{mitreInfo.id}</span>
                      <Badge tone={mitreInfo.severity === "critical" ? "threat" : "warning"}>{mitreInfo.severity}</Badge>
                    </div>
                    <div className="text-xs text-slate-300 mt-1">{mitreInfo.name}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">{mitreInfo.tactic}</div>
                  </div>
                )}
                <div>
                  <div className="text-[11px] uppercase text-slate-500 mb-1.5">Matched Events</div>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {runResult.matched_events.length === 0 && <div className="text-xs text-slate-500">No matches.</div>}
                    {runResult.matched_events.map((e) => (
                      <div key={e.id} className={`rounded px-2 py-1 text-[11px] font-mono border ${e.is_malicious ? "bg-red-500/5 border-red-500/20 text-red-200" : "bg-amber-500/5 border-amber-500/20 text-amber-200"}`}>
                        <span className="text-slate-400">{e.id}</span> {e.is_malicious ? "TRUE POS" : "FALSE POS"} — {String(e.Image ?? e.Uri ?? e.EventID ?? "")}
                      </div>
                    ))}
                  </div>
                </div>
                {mitre && (
                  <div>
                    <div className="text-[11px] uppercase text-slate-500 mb-1.5">Recommended Actions</div>
                    <ul className="space-y-1 text-xs text-slate-300">
                      {recommendedActions(mitre).map((a, i) => (
                        <li key={i} className="flex gap-1.5"><AlertTriangle className="h-3 w-3 text-amber-400 shrink-0 mt-0.5" />{a}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
