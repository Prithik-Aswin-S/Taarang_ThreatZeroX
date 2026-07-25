import { useEffect, useRef, useState } from "react";
import { Video, Volume2, Square, Play, Pause, Brain, Activity, Radio } from "lucide-react";
import { detectWithAI, explainDetection, recommendedActions } from "@/lib/ai";
import { eventsForChallenge } from "@/data/datasets";
import { getMitre } from "@/data/mitre";
import { Panel, Badge, MetricCard } from "@/components/ui";
import type { AiDetection } from "@/types";

type ExplanationState = "idle" | "playing" | "paused";

export default function AiSocMediaPage() {
  const detections = detectWithAI([
    ...eventsForChallenge("T1059.001"),
    ...eventsForChallenge("T1003"),
    ...eventsForChallenge("T1053"),
    ...eventsForChallenge("T1550"),
    ...eventsForChallenge("T1190"),
  ]);
  const [selected, setSelected] = useState<AiDetection>(detections[0]);
  const [state, setState] = useState<ExplanationState>("idle");
  const [progress, setProgress] = useState(0);
  const [audioSupported, setAudioSupported] = useState(true);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const utteranceRef = useRef<SpeechSynthesisUtterance | null>(null);
  const animRef = useRef<number>(0);

  useEffect(() => {
    if (typeof window === "undefined" || !("speechSynthesis" in window)) {
      setAudioSupported(false);
    }
  }, []);

  const mitreInfo = getMitre(selected.mitre_technique ?? "");

  const narrationScript = (d: AiDetection): string => {
    const m = getMitre(d.mitre_technique ?? "");
    const topFeatures = d.shap_features.slice(0, 3).map((f) => `${f.feature} at ${f.contribution} percent`).join(", ");
    return `Security alert. Threat detected: ${d.attack_type}. This event is mapped to MITRE technique ${d.mitre_technique}, ${m?.name ?? "an unknown technique"}, under the ${m?.tactic ?? "unknown"} tactic. The threat score is ${d.threat_score} out of 100, with a model confidence of ${Math.round(d.confidence * 100)} percent. The AI model's decision was primarily driven by the following contributing factors: ${topFeatures}. ${explainDetection(d)} Recommended response actions include: ${recommendedActions(d.mitre_technique ?? "").slice(0, 3).join(", ")}. Analysis complete.`;
  };

  const startNarration = () => {
    if (!audioSupported) return;
    window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(narrationScript(selected));
    u.rate = 0.95;
    u.pitch = 1;
    u.onend = () => {
      setState("idle");
      setProgress(100);
    };
    utteranceRef.current = u;
    window.speechSynthesis.speak(u);
    setState("playing");
    setProgress(0);
    const start = Date.now();
    const tick = () => {
      if (state === "playing") {
        setProgress(Math.min(100, ((Date.now() - start) / 30000) * 100));
      }
    };
    const interval = setInterval(tick, 200);
    return () => clearInterval(interval);
  };

  const pauseNarration = () => {
    if (!audioSupported) return;
    window.speechSynthesis.pause();
    setState("paused");
  };

  const resumeNarration = () => {
    if (!audioSupported) return;
    window.speechSynthesis.resume();
    setState("playing");
  };

  const stopNarration = () => {
    if (!audioSupported) return;
    window.speechSynthesis.cancel();
    setState("idle");
    setProgress(0);
  };

  // Animated "video" visualization on canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let frame = 0;
    const draw = () => {
      frame += 1;
      const w = canvas.width;
      const h = canvas.height;
      ctx.fillStyle = "#060a14";
      ctx.fillRect(0, 0, w, h);

      // Grid
      ctx.strokeStyle = "rgba(34, 211, 238, 0.06)";
      ctx.lineWidth = 1;
      for (let x = 0; x < w; x += 40) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      for (let y = 0; y < h; y += 40) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      const active = state === "playing";
      const cx = w / 2;
      const cy = h / 2;

      // Pulsing rings
      const rings = active ? 5 : 2;
      for (let i = 0; i < rings; i++) {
        const r = 30 + i * 28 + (active ? Math.sin(frame * 0.04 + i) * 8 : 0);
        ctx.strokeStyle = `rgba(34, 211, 238, ${active ? 0.4 - i * 0.06 : 0.15 - i * 0.05})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Center node
      ctx.fillStyle = active ? "#22d3ee" : "#0891b2";
      ctx.beginPath();
      ctx.arc(cx, cy, 12, 0, Math.PI * 2);
      ctx.fill();

      // Orbiting threat indicators
      const threatColor = selected.threat_score >= 75 ? "#ef4444" : "#f59e0b";
      for (let i = 0; i < 4; i++) {
        const angle = frame * 0.02 + (i * Math.PI) / 2;
        const r = 90 + (active ? Math.sin(frame * 0.05 + i) * 12 : 0);
        const x = cx + Math.cos(angle) * r;
        const y = cy + Math.sin(angle) * r;
        ctx.fillStyle = threatColor;
        ctx.globalAlpha = active ? 0.8 : 0.4;
        ctx.beginPath();
        ctx.arc(x, y, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // Scanning line
      if (active) {
        const scanY = (frame * 3) % h;
        const grad = ctx.createLinearGradient(0, scanY - 30, 0, scanY + 30);
        grad.addColorStop(0, "rgba(34, 211, 238, 0)");
        grad.addColorStop(0.5, "rgba(34, 211, 238, 0.15)");
        grad.addColorStop(1, "rgba(34, 211, 238, 0)");
        ctx.fillStyle = grad;
        ctx.fillRect(0, scanY - 30, w, 60);
      }

      // Text overlay
      ctx.fillStyle = "rgba(226, 232, 240, 0.7)";
      ctx.font = "11px JetBrains Mono, monospace";
      ctx.fillText(`THREAT: ${selected.attack_type.toUpperCase()}`, 16, 24);
      ctx.fillText(`MITRE: ${selected.mitre_technique}`, 16, 42);
      ctx.fillText(`SCORE: ${selected.threat_score}/100`, 16, 60);
      if (active) {
        ctx.fillStyle = "rgba(34, 211, 238, 0.8)";
        ctx.fillText("● LIVE ANALYSIS", w - 120, 24);
      }

      animRef.current = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [state, selected]);

  return (
    <div className="space-y-6">
      <header>
        <div className="flex items-center gap-2">
          <Video className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white tracking-tight">AI SOC Video & Audio Explanation</h1>
        </div>
        <p className="text-sm text-slate-400 mt-1">AI-narrated incident briefings with live threat visualization for SOC analysts</p>
      </header>

      {!audioSupported && (
        <div className="glass rounded-lg p-3 border-amber-500/30 text-sm text-amber-300 flex items-center gap-2">
          <Radio className="h-4 w-4" /> Audio narration is not supported in this browser. The video visualization will still play.
        </div>
      )}

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-4 space-y-2">
          <div className="text-[11px] uppercase text-slate-500 px-1">Detections ({detections.length})</div>
          <div className="space-y-2 max-h-[calc(100vh-280px)] overflow-y-auto">
            {detections.map((d) => (
              <button
                key={d.id}
                onClick={() => { setSelected(d); stopNarration(); }}
                className={`w-full text-left glass glass-hover rounded-lg p-3 border transition-all ${selected.id === d.id ? "border-cyan-500/40" : "border-slate-700/40"}`}
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
          <Panel title="AI Threat Briefing — Video Feed" icon={<Video className="h-4 w-4 text-cyan-400" />}
            actions={
              <div className="flex gap-1.5">
                {state === "idle" && (
                  <button onClick={startNarration} className="btn-cyber rounded-lg px-3 py-1.5 text-xs flex items-center gap-1.5">
                    <Play className="h-3.5 w-3.5" /> Play Briefing
                  </button>
                )}
                {state === "playing" && (
                  <button onClick={pauseNarration} className="rounded-lg px-3 py-1.5 text-xs flex items-center gap-1.5 border border-amber-500/30 text-amber-300 hover:bg-amber-500/10">
                    <Pause className="h-3.5 w-3.5" /> Pause
                  </button>
                )}
                {state === "paused" && (
                  <button onClick={resumeNarration} className="btn-cyber rounded-lg px-3 py-1.5 text-xs flex items-center gap-1.5">
                    <Play className="h-3.5 w-3.5" /> Resume
                  </button>
                )}
                {state !== "idle" && (
                  <button onClick={stopNarration} className="rounded-lg px-3 py-1.5 text-xs flex items-center gap-1.5 border border-red-500/30 text-red-300 hover:bg-red-500/10">
                    <Square className="h-3.5 w-3.5" /> Stop
                  </button>
                )}
              </div>
            }
          >
            <div className="relative rounded-lg overflow-hidden border border-slate-700/40">
              <canvas ref={canvasRef} width={760} height={320} className="w-full block" />
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-slate-700/50">
                <div className="h-full bg-cyan-400 transition-all duration-200" style={{ width: `${progress}%` }} />
              </div>
            </div>
          </Panel>

          <Panel title="Audio Narration Script" icon={<Volume2 className="h-4 w-4 text-cyan-400" />}>
            <div className="text-sm text-slate-300 leading-relaxed">{narrationScript(selected)}</div>
            <div className="mt-3 flex items-center gap-2 text-xs text-slate-500">
              <Volume2 className="h-3.5 w-3.5" />
              {audioSupported ? "Click Play Briefing to hear AI narration" : "Audio not supported — text briefing only"}
            </div>
          </Panel>

          <div className="grid grid-cols-3 gap-3">
            <MetricCard label="Threat Score" value={`${selected.threat_score}/100`} tone={selected.threat_score >= 75 ? "threat" : "warning"} icon={<Activity className="h-4 w-4" />} />
            <MetricCard label="Confidence" value={`${Math.round(selected.confidence * 100)}%`} tone="success" icon={<Brain className="h-4 w-4" />} />
            <MetricCard label="MITRE" value={selected.mitre_technique ?? "—"} tone="cyber" icon={<Radio className="h-4 w-4" />} />
          </div>

          {mitreInfo && (
            <Panel title="MITRE Context" icon={<Brain className="h-4 w-4 text-cyan-400" />}>
              <div className="text-sm text-slate-200 font-medium">{mitreInfo.name}</div>
              <div className="text-xs text-slate-500 mt-0.5">{mitreInfo.tactic}</div>
              <p className="text-sm text-slate-400 mt-2 leading-relaxed">{mitreInfo.description}</p>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
