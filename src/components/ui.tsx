import { ShieldCheck, AlertTriangle, Activity, Target, Flame } from "lucide-react";
import type { ReactNode } from "react";

export function StatusDot({ status }: { status: "ok" | "warn" | "threat" | "idle" }) {
  const map = {
    ok: "bg-emerald-400",
    warn: "bg-amber-400",
    threat: "bg-red-500 pulse-ring",
    idle: "bg-slate-500",
  } as const;
  return <span className={`inline-block h-2.5 w-2.5 rounded-full ${map[status]}`} />;
}

export function MetricCard({
  label,
  value,
  sub,
  icon,
  tone = "cyber",
}: {
  label: string;
  value: ReactNode;
  sub?: string;
  icon?: ReactNode;
  tone?: "cyber" | "threat" | "success" | "warning";
}) {
  const tones = {
    cyber: "text-cyan-300",
    threat: "text-red-400",
    success: "text-emerald-400",
    warning: "text-amber-400",
  } as const;
  return (
    <div className="glass glass-hover rounded-xl p-4 flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-wider text-slate-400">{label}</span>
        <span className={tones[tone]}>{icon}</span>
      </div>
      <span className={`text-2xl font-semibold ${tones[tone]}`}>{value}</span>
      {sub && <span className="text-xs text-slate-500">{sub}</span>}
    </div>
  );
}

export function Panel({
  title,
  icon,
  actions,
  children,
  className = "",
}: {
  title: string;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`glass rounded-xl flex flex-col ${className}`}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700/40">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          {icon}
          {title}
        </div>
        {actions}
      </div>
      <div className="p-4 flex-1 min-h-0">{children}</div>
    </div>
  );
}

export function Badge({
  children,
  tone = "cyber",
}: {
  children: ReactNode;
  tone?: "cyber" | "threat" | "success" | "warning" | "neutral";
}) {
  const tones = {
    cyber: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
    threat: "bg-red-500/10 text-red-300 border-red-500/30",
    success: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
    warning: "bg-amber-500/10 text-amber-300 border-amber-500/30",
    neutral: "bg-slate-500/10 text-slate-300 border-slate-500/30",
  } as const;
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function severityTone(sev: string): "cyber" | "threat" | "success" | "warning" | "neutral" {
  switch (sev) {
    case "critical": return "threat";
    case "high": return "threat";
    case "medium": return "warning";
    case "low": return "cyber";
    default: return "neutral";
  }
}

export function ThreatLevelGauge({ level }: { level: number }) {
  const tone = level >= 75 ? "text-red-400" : level >= 40 ? "text-amber-400" : "text-emerald-400";
  const icon = level >= 75 ? <Flame className="h-5 w-5" /> : level >= 40 ? <AlertTriangle className="h-5 w-5" /> : <ShieldCheck className="h-5 w-5" />;
  return (
    <div className="flex items-center gap-3">
      {icon}
      <div className="flex-1">
        <div className="flex justify-between text-xs text-slate-400">
          <span>Threat Level</span>
          <span className={tone}>{level}/100</span>
        </div>
        <div className="mt-1 h-2 rounded-full bg-slate-700/50 overflow-hidden">
          <div
            className={`h-full rounded-full ${level >= 75 ? "bg-red-500" : level >= 40 ? "bg-amber-500" : "bg-emerald-500"} transition-all duration-500`}
            style={{ width: `${level}%` }}
          />
        </div>
      </div>
    </div>
  );
}

export { ShieldCheck, AlertTriangle, Activity, Target };
