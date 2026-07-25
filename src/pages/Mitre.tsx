import { Network, ShieldAlert, Crosshair } from "lucide-react";
import { MITRE_TECHNIQUES } from "@/data/mitre";
import { Panel, Badge, severityTone } from "@/components/ui";

export default function MitrePage() {
  const tactics = Array.from(new Set(MITRE_TECHNIQUES.map((t) => t.tactic.split(",")[0].trim())));

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-white tracking-tight">MITRE ATT&CK Intelligence</h1>
        <p className="text-sm text-slate-400 mt-1">Technique mapping, tactic coverage, and severity classification for every detection</p>
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

      <Panel title="Technique Coverage Matrix" icon={<Network className="h-4 w-4 text-cyan-400" />}>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {MITRE_TECHNIQUES.map((t) => (
            <div key={t.id} className="glass glass-hover rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-bold text-cyan-300">{t.id}</span>
                <Badge tone={severityTone(t.severity)}>{t.severity}</Badge>
              </div>
              <div className="text-sm font-medium text-slate-200">{t.name}</div>
              <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-1">
                <Crosshair className="h-3 w-3" /> {t.tactic}
              </div>
              <p className="text-xs text-slate-400 mt-2 leading-relaxed">{t.description}</p>
            </div>
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
    </div>
  );
}
