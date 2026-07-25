import { useEffect, useState } from "react";
import { BarChart3, Grid3x3, Target, TrendingUp, Activity, Gauge, RefreshCw, Download, Flame, Building2 } from "lucide-react";
import { runRule } from "@/lib/sigma";
import { eventsForChallenge } from "@/data/datasets";
import { CHALLENGES } from "@/data/challenges";
import { Panel, Badge, MetricCard } from "@/components/ui";
import type { RunRuleResponse } from "@/types";

interface ChallengeResult {
  challengeId: string;
  title: string;
  mitre: string;
  result: RunRuleResponse;
}

// Commercial SOC benchmark thresholds (industry standard for production detection)
const BENCHMARKS = {
  precision: { good: 0.85, acceptable: 0.70 },
  recall: { good: 0.85, acceptable: 0.70 },
  fpr: { good: 0.05, acceptable: 0.10 }, // commercial target: <5% FPR
  f1: { good: 0.85, acceptable: 0.75 },
};

export default function MetricsPage() {
  const [results, setResults] = useState<ChallengeResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const runAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const runs = await Promise.all(
        CHALLENGES.map(async (c) => {
          const events = eventsForChallenge(c.mitre);
          const result = await runRule(c.starterYaml, events);
          return { challengeId: c.id, title: c.title, mitre: c.mitre, result };
        }),
      );
      setResults(runs);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runAll();
  }, []);

  const totals = results.reduce(
    (acc, r) => {
      acc.tp += r.result.confusion_matrix.true_positives;
      acc.fp += r.result.confusion_matrix.false_positives;
      acc.tn += r.result.confusion_matrix.true_negatives;
      acc.fn += r.result.confusion_matrix.false_negatives;
      return acc;
    },
    { tp: 0, fp: 0, tn: 0, fn: 0 },
  );

  const totalEvents = totals.tp + totals.fp + totals.tn + totals.fn;
  const overallPrecision = totals.tp + totals.fp > 0 ? totals.tp / (totals.tp + totals.fp) : 0;
  const overallRecall = totals.tp + totals.fn > 0 ? totals.tp / (totals.tp + totals.fn) : 0;
  const overallFPR = totals.fp + totals.tn > 0 ? totals.fp / (totals.fp + totals.tn) : 0;
  const overallF1 = overallPrecision + overallRecall > 0 ? (2 * overallPrecision * overallRecall) / (overallPrecision + overallRecall) : 0;
  const overallAccuracy = totalEvents > 0 ? (totals.tp + totals.tn) / totalEvents : 0;

  const exportCsv = () => {
    const rows = [
      ["Challenge", "MITRE", "TP", "FP", "TN", "FN", "Precision", "Recall", "FPR", "F1", "Accuracy", "ExecMs"],
      ...results.map((r) => [
        r.title, r.mitre,
        String(r.result.confusion_matrix.true_positives),
        String(r.result.confusion_matrix.false_positives),
        String(r.result.confusion_matrix.true_negatives),
        String(r.result.confusion_matrix.false_negatives),
        (r.result.precision * 100).toFixed(1) + "%",
        (r.result.recall * 100).toFixed(1) + "%",
        (r.result.false_positive_rate * 100).toFixed(1) + "%",
        (r.result.f1_score * 100).toFixed(1) + "%",
        (r.result.accuracy * 100).toFixed(1) + "%",
        String(r.result.execution_time_ms),
      ]),
    ];
    const csv = rows.map((r) => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "detection-metrics.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  const matrixCells = [
    { label: "True Positives", value: totals.tp, color: "bg-emerald-500/20 border-emerald-500/40 text-emerald-300", desc: "Malicious events correctly detected" },
    { label: "False Positives", value: totals.fp, color: "bg-amber-500/20 border-amber-500/40 text-amber-300", desc: "Benign events incorrectly flagged" },
    { label: "False Negatives", value: totals.fn, color: "bg-red-500/20 border-red-500/40 text-red-300", desc: "Malicious events missed" },
    { label: "True Negatives", value: totals.tn, color: "bg-cyan-500/20 border-cyan-500/40 text-cyan-300", desc: "Benign events correctly ignored" },
  ];

  // Heatmap color: 0=red, 50=amber, 100=green
  const heatColor = (val: number, max: number) => {
    const ratio = max > 0 ? val / max : 0;
    if (ratio >= 0.8) return "bg-emerald-500/40 border-emerald-500/50 text-emerald-200";
    if (ratio >= 0.6) return "bg-emerald-500/25 border-emerald-500/30 text-emerald-300";
    if (ratio >= 0.4) return "bg-amber-500/25 border-amber-500/30 text-amber-300";
    if (ratio >= 0.2) return "bg-orange-500/25 border-orange-500/30 text-orange-300";
    return "bg-red-500/25 border-red-500/30 text-red-300";
  };

  const fprHeatColor = (fpr: number) => {
    if (fpr <= 0.02) return "bg-emerald-500/40 border-emerald-500/50 text-emerald-200";
    if (fpr <= 0.05) return "bg-emerald-500/25 border-emerald-500/30 text-emerald-300";
    if (fpr <= 0.10) return "bg-amber-500/25 border-amber-500/30 text-amber-300";
    if (fpr <= 0.20) return "bg-orange-500/25 border-orange-500/30 text-orange-300";
    return "bg-red-500/25 border-red-500/30 text-red-300";
  };

  const metricRating = (val: number, benchmark: { good: number; acceptable: number }, higherIsBetter = true) => {
    if (higherIsBetter) {
      if (val >= benchmark.good) return { tone: "success" as const, label: "Excellent" };
      if (val >= benchmark.acceptable) return { tone: "warning" as const, label: "Acceptable" };
      return { tone: "threat" as const, label: "Below target" };
    }
    if (val <= benchmark.good) return { tone: "success" as const, label: "Excellent" };
    if (val <= benchmark.acceptable) return { tone: "warning" as const, label: "Acceptable" };
    return { tone: "threat" as const, label: "Above target" };
  };

  const maxEvents = Math.max(...results.map((r) => r.result.matches), 1);

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <div className="flex items-center gap-2">
            <BarChart3 className="h-6 w-6 text-cyan-400" />
            <h1 className="text-2xl font-bold text-white tracking-tight">Detection Metrics & Confusion Matrix</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">Per-challenge precision, recall, FPR, F1, confusion matrix, and commercial-grade heatmap visualization</p>
        </div>
        <div className="flex gap-2">
          <button onClick={runAll} disabled={loading} className="btn-cyber rounded-lg px-4 py-2 text-sm flex items-center gap-2">
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> {loading ? "Running..." : "Re-run All"}
          </button>
          <button onClick={exportCsv} disabled={results.length === 0} className="rounded-lg px-4 py-2 text-sm flex items-center gap-2 border border-slate-600 text-slate-300 hover:bg-slate-700/30 disabled:opacity-40">
            <Download className="h-4 w-4" /> Export CSV
          </button>
        </div>
      </header>

      {error && (
        <div className="glass rounded-lg p-3 border-red-500/40 text-sm text-red-300">{error}</div>
      )}

      {loading ? (
        <div className="glass rounded-xl p-8 text-center text-slate-400">Running all reference rules against NIST-style datasets...</div>
      ) : (
        <>
          {/* Overall metrics */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <MetricCard label="Precision" value={`${(overallPrecision * 100).toFixed(1)}%`} tone={overallPrecision >= 0.85 ? "success" : overallPrecision >= 0.7 ? "warning" : "threat"} icon={<Target className="h-4 w-4" />} sub={`Target: ≥${(BENCHMARKS.precision.good * 100).toFixed(0)}%`} />
            <MetricCard label="Recall" value={`${(overallRecall * 100).toFixed(1)}%`} tone={overallRecall >= 0.85 ? "success" : overallRecall >= 0.7 ? "warning" : "threat"} icon={<TrendingUp className="h-4 w-4" />} sub={`Target: ≥${(BENCHMARKS.recall.good * 100).toFixed(0)}%`} />
            <MetricCard label="False Positive Rate" value={`${(overallFPR * 100).toFixed(1)}%`} tone={overallFPR <= 0.05 ? "success" : overallFPR <= 0.10 ? "warning" : "threat"} icon={<Activity className="h-4 w-4" />} sub={`Commercial: ≤${(BENCHMARKS.fpr.good * 100).toFixed(0)}%`} />
            <MetricCard label="F1 Score" value={`${(overallF1 * 100).toFixed(1)}%`} tone={overallF1 >= 0.85 ? "success" : overallF1 >= 0.75 ? "warning" : "threat"} icon={<Gauge className="h-4 w-4" />} sub={`Target: ≥${(BENCHMARKS.f1.good * 100).toFixed(0)}%`} />
            <MetricCard label="Accuracy" value={`${(overallAccuracy * 100).toFixed(1)}%`} tone="success" icon={<Target className="h-4 w-4" />} />
            <MetricCard label="Total Events" value={totalEvents} tone="cyber" icon={<Grid3x3 className="h-4 w-4" />} />
          </div>

          {/* Commercial benchmark banner */}
          <div className="glass rounded-xl p-4 flex items-center gap-3">
            <Building2 className="h-5 w-5 text-cyan-400 shrink-0" />
            <div className="text-sm text-slate-300">
              <span className="font-semibold text-cyan-300">Commercial SOC Benchmark:</span>{" "}
              Production-grade detection rules should achieve <span className="text-emerald-300">≥85% precision</span>,{" "}
              <span className="text-emerald-300">≥85% recall</span>, and{" "}
              <span className="text-emerald-300">≤5% FPR</span>. Rules below 70% precision or above 10% FPR need tuning before deployment.
            </div>
          </div>

          {/* Confusion Matrix */}
          <Panel title="Aggregate Confusion Matrix" icon={<Grid3x3 className="h-4 w-4 text-cyan-400" />}>
            <div className="grid grid-cols-2 gap-4 max-w-2xl mx-auto">
              <div className="text-center text-xs text-slate-500 uppercase pb-1">Predicted Malicious</div>
              <div className="text-center text-xs text-slate-500 uppercase pb-1">Predicted Benign</div>
              {matrixCells.map((cell, i) => (
                <div key={i} className={`rounded-xl border p-6 text-center ${cell.color}`}>
                  <div className="text-4xl font-bold">{cell.value}</div>
                  <div className="text-xs mt-1 font-medium">{cell.label}</div>
                  <div className="text-[10px] mt-0.5 opacity-70">{cell.desc}</div>
                </div>
              ))}
            </div>
            <div className="mt-4 flex justify-center gap-6 text-[11px] text-slate-500">
              <span><span className="text-emerald-400">●</span> Actual Malicious (top row)</span>
              <span><span className="text-cyan-400">●</span> Actual Benign (bottom row)</span>
            </div>
          </Panel>

          {/* Heatmap: Metrics per challenge */}
          <Panel title="Detection Performance Heatmap" icon={<Flame className="h-4 w-4 text-orange-400" />}>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[10px] uppercase text-slate-500">
                    <th className="text-left py-2 px-2">Challenge</th>
                    <th className="text-center py-2 px-1">Precision</th>
                    <th className="text-center py-2 px-1">Recall</th>
                    <th className="text-center py-2 px-1">FPR</th>
                    <th className="text-center py-2 px-1">F1</th>
                    <th className="text-center py-2 px-1">Accuracy</th>
                    <th className="text-center py-2 px-1">Specificity</th>
                    <th className="text-center py-2 px-1">Matches</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r) => {
                    const pRating = metricRating(r.result.precision, BENCHMARKS.precision);
                    const rRating = metricRating(r.result.recall, BENCHMARKS.recall);
                    const fRating = metricRating(r.result.false_positive_rate, BENCHMARKS.fpr, false);
                    const f1Rating = metricRating(r.result.f1_score, BENCHMARKS.f1);
                    return (
                      <tr key={r.challengeId} className="border-b border-slate-700/20">
                        <td className="py-2 px-2">
                          <div className="text-slate-200 text-xs font-medium">{r.title}</div>
                          <Badge tone="cyber">{r.mitre}</Badge>
                        </td>
                        <td className="py-2 px-1 text-center">
                          <div className={`inline-block rounded border px-2 py-1 text-xs font-bold ${heatColor(r.result.precision, 1)}`}>{(r.result.precision * 100).toFixed(0)}%</div>
                        </td>
                        <td className="py-2 px-1 text-center">
                          <div className={`inline-block rounded border px-2 py-1 text-xs font-bold ${heatColor(r.result.recall, 1)}`}>{(r.result.recall * 100).toFixed(0)}%</div>
                        </td>
                        <td className="py-2 px-1 text-center">
                          <div className={`inline-block rounded border px-2 py-1 text-xs font-bold ${fprHeatColor(r.result.false_positive_rate)}`}>{(r.result.false_positive_rate * 100).toFixed(0)}%</div>
                        </td>
                        <td className="py-2 px-1 text-center">
                          <div className={`inline-block rounded border px-2 py-1 text-xs font-bold ${heatColor(r.result.f1_score, 1)}`}>{(r.result.f1_score * 100).toFixed(0)}%</div>
                        </td>
                        <td className="py-2 px-1 text-center">
                          <div className={`inline-block rounded border px-2 py-1 text-xs font-bold ${heatColor(r.result.accuracy, 1)}`}>{(r.result.accuracy * 100).toFixed(0)}%</div>
                        </td>
                        <td className="py-2 px-1 text-center">
                          <div className={`inline-block rounded border px-2 py-1 text-xs font-bold ${heatColor(r.result.specificity, 1)}`}>{(r.result.specificity * 100).toFixed(0)}%</div>
                        </td>
                        <td className="py-2 px-1 text-center">
                          <div className={`inline-block rounded border px-2 py-1 text-xs font-bold ${heatColor(r.result.matches, maxEvents)}`}>{r.result.matches}</div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {/* Heatmap legend */}
            <div className="mt-4 flex items-center justify-center gap-4 text-[10px] text-slate-500">
              <span>Heat scale:</span>
              <span className="flex items-center gap-1"><span className="h-3 w-3 rounded bg-red-500/30 border border-red-500/30" /> Critical (&lt;40%)</span>
              <span className="flex items-center gap-1"><span className="h-3 w-3 rounded bg-orange-500/30 border border-orange-500/30" /> Poor (40-60%)</span>
              <span className="flex items-center gap-1"><span className="h-3 w-3 rounded bg-amber-500/30 border border-amber-500/30" /> Fair (60-80%)</span>
              <span className="flex items-center gap-1"><span className="h-3 w-3 rounded bg-emerald-500/30 border border-emerald-500/30" /> Good (≥80%)</span>
            </div>
          </Panel>

          {/* Per-challenge confusion matrices */}
          <Panel title="Per-Challenge Confusion Matrices" icon={<Grid3x3 className="h-4 w-4 text-cyan-400" />}>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {results.map((r) => {
                const cm = r.result.confusion_matrix;
                return (
                  <div key={r.challengeId} className="glass rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-sm font-medium text-slate-200">{r.title}</span>
                      <Badge tone="cyber">{r.mitre}</Badge>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-center">
                        <div className="text-2xl font-bold text-emerald-300">{cm.true_positives}</div>
                        <div className="text-[10px] text-slate-500">TP</div>
                      </div>
                      <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-center">
                        <div className="text-2xl font-bold text-amber-300">{cm.false_positives}</div>
                        <div className="text-[10px] text-slate-500">FP</div>
                      </div>
                      <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-center">
                        <div className="text-2xl font-bold text-red-300">{cm.false_negatives}</div>
                        <div className="text-[10px] text-slate-500">FN</div>
                      </div>
                      <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-3 text-center">
                        <div className="text-2xl font-bold text-cyan-300">{cm.true_negatives}</div>
                        <div className="text-[10px] text-slate-500">TN</div>
                      </div>
                    </div>
                    <div className="text-[10px] text-slate-500 mt-2 text-center">Executed in {r.result.execution_time_ms}ms</div>
                  </div>
                );
              })}
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
