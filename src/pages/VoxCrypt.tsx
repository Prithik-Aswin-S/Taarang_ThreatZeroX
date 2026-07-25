import { useState } from "react";
import { Radio, Lock, Unlock, ShieldCheck, ArrowRight, FileLock2, KeyRound, Send, Download, Upload } from "lucide-react";
import { sealEvidence, openEvidence, verifyIntegrity, type SealedEvidence, type CipherAlgorithm } from "@/lib/crypto";
import { supabase } from "@/lib/supabase";
import { Panel, Badge } from "@/components/ui";

const DEFAULT_REPORT = `INCIDENT REPORT
================
Incident ID: INC-2025-0725-001
Attack Type: Encoded PowerShell Execution
MITRE Technique: T1059.001
Severity: Critical
Threat Score: 94/100

Summary:
A service account launched PowerShell with an encoded command
payload establishing persistence via a rogue scheduled task.

Evidence:
- Process: powershell.exe (PID 4821)
- Parent: services.exe
- Command: powershell -EncodedCommand SQBFAFgA...
- Destination: 185.220.101.45:4444

Recommended Actions:
1. Isolate host
2. Reset svc-sql credentials
3. Remove scheduled task \\Microsoft\\Windows\\WindowsUpdate\\UpdateHelper
`;

export default function VoxCryptPage() {
  const [report, setReport] = useState(DEFAULT_REPORT);
  const [passphrase, setPassphrase] = useState("ThreatZero-SentinelX-2025");
  const [algorithm, setAlgorithm] = useState<CipherAlgorithm>("AES-256-GCM");
  const [sealed, setSealed] = useState<SealedEvidence | null>(null);
  const [decrypted, setDecrypted] = useState<string | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [transferred, setTransferred] = useState(false);

  const handleSeal = async () => {
    setBusy(true);
    setError(null);
    try {
      const s = await sealEvidence(report, passphrase, algorithm);
      setSealed(s);
      setDecrypted(null);
      setVerified(null);
      setTransferred(false);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleOpen = async () => {
    if (!sealed) return;
    setBusy(true);
    setError(null);
    try {
      const pt = await openEvidence(sealed, passphrase);
      setDecrypted(pt);
      const ok = await verifyIntegrity(pt, sealed.hash);
      setVerified(ok);
    } catch (e) {
      setError(`Decryption failed — wrong passphrase or tampered evidence: ${(e as Error).message}`);
      setVerified(false);
    } finally {
      setBusy(false);
    }
  };

  const handleTransfer = async () => {
    if (!sealed) return;
    setBusy(true);
    try {
      await supabase.from("evidence").insert({
        incident_id: `VOX-${Date.now()}`,
        evidence_hash: sealed.hash,
        attack_type: "VoxCrypt Secure Transfer",
        mitre_technique: null,
        encryption_status: sealed.algorithm,
        integrity_status: "SHA-256 Integrity Verified",
        payload: { ciphertext: sealed.ciphertext, iv: sealed.iv, salt: sealed.salt, algorithm: sealed.algorithm } as unknown as Record<string, unknown>,
      });
      setTransferred(true);
      setTimeout(() => setTransferred(false), 3000);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const downloadPackage = () => {
    if (!sealed) return;
    const pkg = { report_hash: sealed.hash, algorithm: sealed.algorithm, ciphertext: sealed.ciphertext, iv: sealed.iv, salt: sealed.salt };
    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `voxcrypt-package-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const importPackage = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const pkg = JSON.parse(reader.result as string) as SealedEvidence;
        setSealed({ ...pkg, algorithm: pkg.algorithm || "AES-256-GCM" });
        setDecrypted(null);
        setVerified(null);
      } catch {
        setError("Invalid package file.");
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-6">
      <header>
        <div className="flex items-center gap-2">
          <Radio className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white tracking-tight">VoxCrypt — Secure Cyber Evidence Communication</h1>
        </div>
        <p className="text-sm text-slate-400 mt-1">Advanced security extension for secure transmission of incident reports and forensic evidence</p>
      </header>

      <div className="glass rounded-xl p-4 flex items-center gap-3 text-sm flex-wrap">
        <span className="text-slate-400">Workflow:</span>
        <Badge tone="cyber">Incident Evidence</Badge>
        <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
        <Badge tone="cyber">{algorithm}</Badge>
        <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
        <Badge tone="cyber">Secure Packaging</Badge>
        <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
        <Badge tone="success">Authorized Transfer</Badge>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-6">
          <Panel title="Incident Report" icon={<FileLock2 className="h-4 w-4 text-cyan-400" />}
            actions={<button onClick={handleSeal} disabled={busy} className="btn-cyber rounded-lg px-3 py-1.5 text-xs flex items-center gap-1.5"><Lock className="h-3.5 w-3.5" /> {busy ? "Sealing..." : "Encrypt & Seal"}</button>}
          >
            <textarea
              value={report}
              onChange={(e) => setReport(e.target.value)}
              className="w-full h-64 bg-[#0a0f1a] text-slate-200 font-mono text-xs rounded-lg p-3 border border-slate-700/40 focus:outline-none focus:border-cyan-500/40 resize-none"
            />
            <div className="mt-3 grid grid-cols-2 gap-3">
              <div>
                <label className="text-[11px] text-slate-500 uppercase">Encryption Passphrase</label>
                <input
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  className="w-full mt-1 glass rounded-lg px-3 py-2 text-sm text-slate-200 border border-slate-700/40 focus:outline-none focus:border-cyan-500/40"
                />
              </div>
              <div>
                <label className="text-[11px] text-slate-500 uppercase">Algorithm</label>
                <div className="mt-1 flex gap-2">
                  <button
                    onClick={() => setAlgorithm("AES-256-GCM")}
                    className={`flex-1 rounded-lg px-3 py-2 text-xs flex items-center justify-center gap-1.5 border transition-all ${algorithm === "AES-256-GCM" ? "bg-cyan-500/15 border-cyan-500/40 text-cyan-300" : "border-slate-700/40 text-slate-400 hover:bg-slate-700/30"}`}
                  >
                    <KeyRound className="h-3.5 w-3.5" /> AES-256
                  </button>
                  <button
                    onClick={() => setAlgorithm("DES-3DES-CBC")}
                    className={`flex-1 rounded-lg px-3 py-2 text-xs flex items-center justify-center gap-1.5 border transition-all ${algorithm === "DES-3DES-CBC" ? "bg-amber-500/15 border-amber-500/40 text-amber-300" : "border-slate-700/40 text-slate-400 hover:bg-slate-700/30"}`}
                  >
                    <KeyRound className="h-3.5 w-3.5" /> 3DES
                  </button>
                </div>
              </div>
            </div>
          </Panel>
        </div>

        <div className="col-span-6 space-y-4">
          <Panel title="Sealed Evidence Package" icon={<ShieldCheck className="h-4 w-4 text-cyan-400" />}
            actions={
              <div className="flex gap-1.5">
                <label className="cursor-pointer text-slate-400 hover:text-cyan-300">
                  <Upload className="h-3.5 w-3.5" />
                  <input type="file" accept=".json" onChange={importPackage} className="hidden" />
                </label>
                {sealed && <button onClick={downloadPackage} className="text-slate-400 hover:text-cyan-300"><Download className="h-3.5 w-3.5" /></button>}
              </div>
            }
          >
            {!sealed ? (
              <div className="text-sm text-slate-500">No evidence sealed yet. Click "Encrypt & Seal" to package the report with your chosen cipher.</div>
            ) : (
              <div className="space-y-3">
                <div className="glass rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">Algorithm</div>
                  <Badge tone={sealed.algorithm === "AES-256-GCM" ? "success" : "warning"}>
                    <Lock className="h-3 w-3" /> {sealed.algorithm}
                  </Badge>
                </div>
                <div className="glass rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">SHA-256 Integrity Hash</div>
                  <div className="text-[11px] font-mono text-cyan-300 break-all">{sealed.hash}</div>
                </div>
                <div className="glass rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase mb-1">Ciphertext (base64)</div>
                  <div className="text-[11px] font-mono text-slate-300 break-all max-h-28 overflow-y-auto">{sealed.ciphertext}</div>
                </div>
                <div className="flex gap-2">
                  <button onClick={handleOpen} disabled={busy} className="flex-1 rounded-lg px-3 py-2 text-sm flex items-center justify-center gap-2 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 transition-colors">
                    <Unlock className="h-4 w-4" /> {busy ? "Decrypting..." : "Decrypt & Verify"}
                  </button>
                  <button onClick={handleTransfer} disabled={busy} className="flex-1 btn-cyber rounded-lg px-3 py-2 text-sm flex items-center justify-center gap-2">
                    <Send className="h-4 w-4" /> {transferred ? "Transferred!" : "Transfer"}
                  </button>
                </div>
              </div>
            )}
          </Panel>

          {(decrypted !== null || verified !== null || error) && (
            <Panel title="Decryption & Integrity Result" icon={<ShieldCheck className="h-4 w-4 text-cyan-400" />}>
              {error ? (
                <div className="text-sm text-red-300">{error}</div>
              ) : (
                <div className="space-y-3">
                  <div className={`flex items-center gap-2 ${verified ? "text-emerald-400" : "text-red-400"}`}>
                    <ShieldCheck className="h-5 w-5" />
                    {verified ? "SHA-256 Integrity Verified — evidence is authentic" : "Integrity check failed — evidence may have been tampered with"}
                  </div>
                  {decrypted && (
                    <div className="glass rounded-lg p-3">
                      <div className="text-[10px] text-slate-500 uppercase mb-1">Decrypted Report</div>
                      <pre className="text-[11px] font-mono text-slate-200 whitespace-pre-wrap max-h-40 overflow-y-auto">{decrypted}</pre>
                    </div>
                  )}
                </div>
              )}
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
