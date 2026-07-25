import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  FlaskConical,
  Database,
  GraduationCap,
  Brain,
  Network,
  Bot,
  Archive,
  ShieldCheck,
  Radio,
  FileSearch,
  Cpu,
  Video,
  BarChart3,
} from "lucide-react";

const NAV = [
  { to: "/", label: "Command Dashboard", icon: LayoutDashboard, end: true },
  { to: "/lab", label: "Sigma Detection Lab", icon: FlaskConical },
  { to: "/datasets", label: "Dataset Library", icon: Database },
  { to: "/academy", label: "Detection Academy", icon: GraduationCap },
  { to: "/ai-assistant", label: "AI Sigma Assistant", icon: Brain },
  { to: "/explainability", label: "Explainable AI (SHAP)", icon: Cpu },
  { to: "/mitre", label: "MITRE ATT&CK", icon: Network },
  { to: "/copilot", label: "AI SOC Copilot", icon: Bot },
  { to: "/ai-soc-media", label: "AI Video & Audio", icon: Video },
  { to: "/evidence", label: "Evidence Vault", icon: Archive },
  { to: "/voxcrypt", label: "VoxCrypt Secure Comms", icon: Radio },
  { to: "/incidents", label: "Incident Investigation", icon: FileSearch },
  { to: "/metrics", label: "Detection Metrics", icon: BarChart3 },
];

export default function AppShell() {
  return (
    <div className="flex h-screen w-full overflow-hidden bg-[#060a14]">
      <aside className="w-64 shrink-0 glass border-r border-slate-700/40 flex flex-col">
        <div className="px-5 py-5 border-b border-slate-700/40">
          <div className="flex items-center gap-2.5">
            <div className="relative">
              <ShieldCheck className="h-8 w-8 text-cyan-400 cyber-glow rounded-lg" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-tight text-white leading-tight">
                ThreatZero
              </div>
              <div className="text-[10px] uppercase tracking-[0.2em] text-cyan-400 font-semibold">
                Sentinel X
              </div>
            </div>
          </div>
          <div className="mt-3 text-[10px] text-slate-500 leading-relaxed">
            AI-Powered Detection Engineering & SOC Intelligence Platform
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all ${
                  isActive
                    ? "bg-cyan-500/10 text-cyan-300 border border-cyan-500/30"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-700/30 border border-transparent"
                }`
              }
            >
              <item.icon className="h-4 w-4 shrink-0" />
              <span className="truncate">{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="px-4 py-3 border-t border-slate-700/40 text-[10px] text-slate-500">
          <div className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Engine online · XGBoost-Sentinel-v2
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto scanline">
        <div className="max-w-[1600px] mx-auto p-6 fade-in">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
