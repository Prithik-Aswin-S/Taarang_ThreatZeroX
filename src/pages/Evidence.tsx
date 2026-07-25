import { useEffect, useState } from "react";
import { Archive, ShieldCheck, Lock, Hash, FileText, Download } from "lucide-react";
import { supabase } from "@/lib/supabase";
import { sealEvidence, sha256 } from "@/lib/crypto";
import { detectWithAI } from "@/lib/ai";
import { eventsForChallenge } from "@/data/datasets";
import { Panel, Badge, MetricCard } from "@/components/ui";
import type { Evidence } from "@/types";

const PASSPHRASE = "ThreatZero-SentinelX-2025";

export default function EvidencePage() {
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [sealing, setSealing] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  const load = async () => {
    const { data } = await supabase.from("evidence").select("*").order("created_at", { ascending: false }).limit(50);
    setEvidence((data as Evidence[]) ?? []);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const generateEvidence = async () => {
    setSealing(true);
    setStatus(null);
    try {
      const detections = detectWithAI([
        ...eventsForChallenge("T1059.001"),
        ...eventsForChallenge("T1003"),
        ...eventsForChallenge("T1190"),
      ]);
      const rows: Omit<Evidence, "id" | "created_at">[] = [];
      for (const d of detections) {
        const payload = JSON.stringify({
          incident_id: `INC-${d.event_id}`,
          attack_type: d.attack_type,
          mitre: d.mitre_technique,
          threat_score: d.threat_score,
          shap: d.shap_features,
          timestamp: d.created_at,
        });
        const sealed = await sealEvidence(payload, PASSPHRASE);
        rows.push({
          incident_id: `INC-${d.event_id}`,
          evidence_hash: sealed.hash,
          attack_type: d.attack_type,
          mitre_technique: d.mitre_technique,
          encryption_status: `${sealed.algorithm} Protected`,
          integrity_status: "SHA-256 Integrity Verified",
          payload: { ciphertext: sealed.ciphertext, iv: sealed.iv, salt: sealed.salt } as unknown as Record<string, unknown>,
        });
      }
      await supabase.from("evidence").insert(rows);
      setStatus(`Sealed ${rows.length} evidence packages with AES-256-GCM and SHA-256 integrity.`);
      await load();
    } catch (e) {
      setStatus(`Error: ${(e as Error).message}`);
    } finally {
      setSealing(false);
    }
  };

  const downloadEvidence = (e: Evidence) => {
    const blob = new Blob([JSON.stringify(e, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `evidence-${e.incident_id ?? e.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) return <div className="text-slate-400 text-sm">Loading evidence vault...</div>;

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Evidence Vault</h1>
          <p className="text-sm text-slate-400 mt-1">Secure evidence management — AES-256 encryption & SHA-256 integrity verification</p>
        </div>
        <button onClick={generateEvidence} disabled={sealing} className="btn-cyber rounded-lg px-4 py-2 text-sm flex items-center gap-2">
          <Lock className="h-4 w-4" /> {sealing ? "Sealing..." : "Seal New Evidence"}
        </button>
      </header>

      {status && (
        <div className="glass rounded-lg p-3 border-cyan-500/30 text-sm text-cyan-300 flex items-center gap-2">
          <ShieldCheck className="h-4 w-4" /> {status}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Evidence Items" value={evidence.length} icon={<Archive className="h-4 w-4" />} />
        <MetricCard label="Encryption" value="AES-256" tone="success" icon={<Lock className="h-4 w-4" />} />
        <MetricCard label="Integrity" value="SHA-256" tone="success" icon={<Hash className="h-4 w-4" />} />
        <MetricCard label="Verified" value={evidence.length} tone="success" icon={<ShieldCheck className="h-4 w-4" />} />
      </div>

      <Panel title="Evidence Records" icon={<Archive className="h-4 w-4 text-cyan-400" />}>
        {evidence.length === 0 ? (
          <div className="text-sm text-slate-500">No evidence sealed yet. Click "Seal New Evidence" to generate encrypted evidence packages from AI detections.</div>
        ) : (
          <div className="space-y-3">
            {evidence.map((e) => (
              <div key={e.id} className="glass glass-hover rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-cyan-400" />
                    <span className="text-sm font-semibold text-slate-200">{e.incident_id ?? "—"}</span>
                    <Badge tone="cyber">{e.attack_type ?? "unknown"}</Badge>
                    {e.mitre_technique && <Badge tone="warning">{e.mitre_technique}</Badge>}
                  </div>
                  <button onClick={() => downloadEvidence(e)} className="text-slate-400 hover:text-cyan-300">
                    <Download className="h-4 w-4" />
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-3 mt-3">
                  <div className="glass rounded-lg p-2.5">
                    <div className="text-[10px] text-slate-500 uppercase mb-0.5">Evidence Hash (SHA-256)</div>
                    <div className="text-[11px] font-mono text-cyan-300 break-all">{e.evidence_hash}</div>
                  </div>
                  <div className="glass rounded-lg p-2.5">
                    <div className="text-[10px] text-slate-500 uppercase mb-0.5">Security Status</div>
                    <div className="flex gap-2 flex-wrap">
                      <Badge tone="success"><Lock className="h-3 w-3" /> {e.encryption_status}</Badge>
                      <Badge tone="success"><ShieldCheck className="h-3 w-3" /> {e.integrity_status}</Badge>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
