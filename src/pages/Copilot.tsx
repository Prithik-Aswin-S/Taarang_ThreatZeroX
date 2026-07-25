import { useState } from "react";
import { Bot, Send, Sparkles } from "lucide-react";
import { Panel } from "@/components/ui";
import { detectWithAI, explainDetection, recommendedActions } from "@/lib/ai";
import { eventsForChallenge } from "@/data/datasets";
import { getMitre } from "@/data/mitre";

interface Message {
  role: "user" | "ai";
  text: string;
}

const SAMPLE_DETECTION = detectWithAI([...eventsForChallenge("T1059.001"), ...eventsForChallenge("T1190")])[0];

export default function CopilotPage() {
  const [messages, setMessages] = useState<Message[]>([
    { role: "ai", text: "Hello analyst. I'm your AI SOC Copilot. I can explain incidents, decode Sigma rules, suggest detection logic, recommend response actions, and summarise attacks. Ask me anything or pick a quick prompt below." },
  ]);
  const [input, setInput] = useState("");

  const respond = (q: string): string => {
    const lower = q.toLowerCase();
    if (lower.includes("why") && (lower.includes("rule") || lower.includes("detect"))) {
      if (SAMPLE_DETECTION) {
        const m = getMitre(SAMPLE_DETECTION.mitre_technique ?? "");
        return `This rule detected the attack because the event matched key indicators of ${SAMPLE_DETECTION.attack_type} (MITRE ${SAMPLE_DETECTION.mitre_technique}). ${m?.name} falls under the ${m?.tactic} tactic. The matched indicators — encoded command execution and an abnormal parent process — are consistent with ${SAMPLE_DETECTION.attack_type} behaviour.`;
      }
    }
    if (lower.includes("explain") && lower.includes("incident")) {
      if (SAMPLE_DETECTION) {
        return `Incident summary: ${SAMPLE_DETECTION.attack_type} (MITRE ${SAMPLE_DETECTION.mitre_technique}). Threat score ${SAMPLE_DETECTION.threat_score}/100 with ${(SAMPLE_DETECTION.confidence * 100).toFixed(0)}% confidence. ${explainDetection(SAMPLE_DETECTION)}`;
      }
    }
    if (lower.includes("suggest") && (lower.includes("sigma") || lower.includes("detection") || lower.includes("rule"))) {
      if (SAMPLE_DETECTION?.suggested_sigma) {
        return `I recommend a Sigma rule targeting ${SAMPLE_DETECTION.mitre_technique}. Here's a starting point:\n\n${SAMPLE_DETECTION.suggested_sigma.slice(0, 400)}...\n\nYou can load this into the Sigma Detection Lab to validate and test it.`;
      }
    }
    if (lower.includes("recommend") && lower.includes("response")) {
      if (SAMPLE_DETECTION) {
        return `Recommended response actions for ${SAMPLE_DETECTION.mitre_technique}:\n\n${recommendedActions(SAMPLE_DETECTION.mitre_technique ?? "").map((a, i) => `${i + 1}. ${a}`).join("\n")}`;
      }
    }
    if (lower.includes("summar") && lower.includes("attack")) {
      if (SAMPLE_DETECTION) {
        const m = getMitre(SAMPLE_DETECTION.mitre_technique ?? "");
        return `Attack summary: The adversary used ${SAMPLE_DETECTION.attack_type}, mapped to MITRE ${SAMPLE_DETECTION.mitre_technique} (${m?.tactic}). This technique allows the attacker to ${(m?.description ?? "execute malicious activity").toLowerCase()}. Threat score: ${SAMPLE_DETECTION.threat_score}/100.`;
      }
    }
    if (lower.includes("sigma") && (lower.includes("what") || lower.includes("explain"))) {
      return `Sigma is a generic and open signature format for log events. A Sigma rule is a YAML document with three required sections: title (name), logsource (which logs to search), and detection (the selection logic + condition). ThreatZero Sentinel X validates and executes these rules against security datasets server-side.`;
    }
    return `I can help with: explaining incidents, decoding Sigma rules, suggesting detection logic, recommending response actions, and summarising attacks. Try asking "Why did this rule detect the attack?" or "Recommend response actions."`;
  };

  const send = (text: string) => {
    if (!text.trim()) return;
    const reply = respond(text);
    setMessages((m) => [...m, { role: "user", text }, { role: "ai", text: reply }]);
    setInput("");
  };

  const prompts = [
    "Why did this rule detect the attack?",
    "Explain the incident",
    "Suggest a Sigma detection rule",
    "Recommend response actions",
    "Summarise the attack",
  ];

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <header>
        <h1 className="text-2xl font-bold text-white tracking-tight">AI SOC Copilot</h1>
        <p className="text-sm text-slate-400 mt-1">Your AI security assistant — explain, suggest, and respond</p>
      </header>

      <div className="flex flex-wrap gap-2">
        {prompts.map((p) => (
          <button key={p} onClick={() => send(p)} className="text-xs glass glass-hover rounded-full px-3 py-1.5 text-slate-300 flex items-center gap-1.5">
            <Sparkles className="h-3 w-3 text-cyan-400" /> {p}
          </button>
        ))}
      </div>

      <Panel title="Conversation" icon={<Bot className="h-4 w-4 text-cyan-400" />} className="min-h-[500px]">
        <div className="space-y-4 max-h-[500px] overflow-y-auto pr-1">
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div className={`max-w-[80%] rounded-xl px-4 py-3 text-sm whitespace-pre-wrap ${
                m.role === "user"
                  ? "bg-cyan-500/15 border border-cyan-500/30 text-cyan-100"
                  : "glass text-slate-200"
              }`}>
                {m.role === "ai" && <div className="flex items-center gap-1.5 mb-1 text-[10px] text-cyan-400 uppercase"><Bot className="h-3 w-3" /> AI Copilot</div>}
                {m.text}
              </div>
            </div>
          ))}
        </div>

        <form onSubmit={(e) => { e.preventDefault(); send(input); }} className="mt-4 flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about an incident, rule, or response..."
            className="flex-1 glass rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/40 border border-slate-700/40"
          />
          <button type="submit" className="btn-cyber rounded-lg px-4 py-2.5 flex items-center gap-2 text-sm">
            <Send className="h-4 w-4" />
          </button>
        </form>
      </Panel>
    </div>
  );
}
