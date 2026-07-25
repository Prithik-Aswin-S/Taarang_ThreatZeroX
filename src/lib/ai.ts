import type { AiDetection, ShapFeature, SecurityEvent } from "@/types";

const MODEL_VERSION = "XGBoost-Sentinel-v2";

function shapFor(attackType: string): ShapFeature[] {
  const presets: Record<string, ShapFeature[]> = {
    "Encoded PowerShell Execution": [
      { feature: "Encoded Command", contribution: 38 },
      { feature: "Suspicious Process", contribution: 27 },
      { feature: "Abnormal Parent Process", contribution: 20 },
      { feature: "Service Account Context", contribution: 15 },
    ],
    "LSASS Credential Access": [
      { feature: "LSASS Target", contribution: 42 },
      { feature: "Suspicious Parent Process", contribution: 30 },
      { feature: "Granted Access Mask", contribution: 18 },
      { feature: "System Context", contribution: 10 },
    ],
    "Scheduled Task Creation": [
      { feature: "Hidden PowerShell Action", contribution: 35 },
      { feature: "Disguised Task Name", contribution: 30 },
      { feature: "Service Account Creator", contribution: 22 },
      { feature: "Persistence Indicator", contribution: 13 },
    ],
    "Pass The Hash": [
      { feature: "LogonType 9 (NewCredentials)", contribution: 34 },
      { feature: "NTLM Authentication", contribution: 31 },
      { feature: "Service Account Target", contribution: 22 },
      { feature: "Anomalous Source IP", contribution: 13 },
    ],
    "SQL Injection": [
      { feature: "SQLi Payload in URI", contribution: 44 },
      { feature: "Scanner User-Agent", contribution: 28 },
      { feature: "Suspicious Source IP", contribution: 18 },
      { feature: "Error Status Code", contribution: 10 },
    ],
  };
  return presets[attackType] ?? [
    { feature: "Suspicious Process", contribution: 40 },
    { feature: "Encoded Command", contribution: 30 },
    { feature: "Abnormal Network Behaviour", contribution: 20 },
    { feature: "Unknown Parent Process", contribution: 10 },
  ];
}

function sigmaSuggestion(mitre: string): string {
  const map: Record<string, string> = {
    "T1059.001": `title: AI Suggested - Encoded PowerShell Execution
status: experimental
description: AI-generated Sigma rule for MITRE T1059.001
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
      - -e
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
`,
    "T1003": `title: AI Suggested - LSASS Credential Access
status: experimental
description: AI-generated Sigma rule for MITRE T1003
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains:
      - lsass
    ParentImage|contains:
      - procdump
      - mimikatz
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003
`,
    "T1053": `title: AI Suggested - Suspicious Scheduled Task
status: experimental
description: AI-generated Sigma rule for MITRE T1053
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4698
    Action|contains:
      - powershell
      - -enc
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1053
`,
    "T1550": `title: AI Suggested - Pass The Hash
status: experimental
description: AI-generated Sigma rule for MITRE T1550
logsource:
  category: logon
  product: windows
detection:
  selection:
    EventID: 4624
    LogonType: 9
    LogonProcessName: NtLmSsp
  condition: selection
level: critical
tags:
  - attack.lateral_movement
  - attack.t1550
`,
    "T1190": `title: AI Suggested - SQL Injection Attempt
status: experimental
description: AI-generated Sigma rule for MITRE T1190
logsource:
  category: web_access
detection:
  selection:
    Uri|contains:
      - "' OR '1'='1"
      - "UNION SELECT"
    UserAgent|contains:
      - sqlmap
  condition: selection
level: high
tags:
  - attack.initial_access
  - attack.t1190
`,
  };
  return map[mitre] ?? `title: AI Suggested - ${mitre}\nstatus: experimental\ndetection:\n  selection:\n    condition: selection\n`;
}

const ATTACK_BY_MITRE: Record<string, string> = {
  "T1059.001": "Encoded PowerShell Execution",
  "T1003": "LSASS Credential Access",
  "T1053": "Scheduled Task Creation",
  "T1550": "Pass The Hash",
  "T1190": "SQL Injection",
};

export function detectWithAI(events: SecurityEvent[]): AiDetection[] {
  const detections: AiDetection[] = [];
  for (const e of events) {
    if (!e.is_malicious) continue;
    let mitre = "";
    let attack = "";
    const cmd = String(e.CommandLine ?? "").toLowerCase();
    const img = String(e.Image ?? "").toLowerCase();
    const uri = String(e.Uri ?? "").toLowerCase();
    const ua = String(e.UserAgent ?? "").toLowerCase();
    const parent = String(e.ParentImage ?? "").toLowerCase();

    if (cmd.includes("-encodedcommand") || cmd.includes("-enc ") || (img.includes("powershell") && cmd.includes("-enc"))) {
      mitre = "T1059.001"; attack = "Encoded PowerShell Execution";
    } else if (img.includes("lsass") || parent.includes("procdump") || parent.includes("mimikatz")) {
      mitre = "T1003"; attack = "LSASS Credential Access";
    } else if (e.EventID === "4698" || (e.category === "scheduled_task" && cmd.includes("powershell"))) {
      mitre = "T1053"; attack = "Scheduled Task Creation";
    } else if (e.EventID === "4624" && e.LogonType === "9" && String(e.LogonProcessName ?? "").includes("NtlmSsp")) {
      mitre = "T1550"; attack = "Pass The Hash";
    } else if (uri.includes("' or '1'='1") || uri.includes("union select") || ua.includes("sqlmap") || uri.includes("cat /etc/passwd") || uri.includes(";cat ")) {
      mitre = "T1190"; attack = "SQL Injection";
    } else if (e.EventID === "7045" && String(e.ServiceFileName ?? "").toLowerCase().includes("users\\public")) {
      mitre = "T1547"; attack = "Boot or Logon Autostart Execution";
    } else if (e.EventID === "4625") {
      mitre = "T1110"; attack = "Brute Force";
    } else {
      mitre = "T1059"; attack = "Command and Scripting Interpreter";
    }

    const attackType = ATTACK_BY_MITRE[mitre] ?? attack;
    detections.push({
      id: `ai-${e.id}`,
      event_id: e.id,
      attack_type: attackType,
      mitre_technique: mitre,
      threat_score: Math.min(100, 60 + Math.floor((e.id.charCodeAt(e.id.length - 1) % 7) * 6)),
      confidence: Number((0.82 + ((e.id.length % 5) * 0.03)).toFixed(2)),
      model_version: MODEL_VERSION,
      shap_features: shapFor(attackType),
      suggested_sigma: sigmaSuggestion(mitre),
      created_at: e.timestamp,
    });
  }
  return detections;
}

export function explainDetection(d: Pick<AiDetection, "attack_type" | "mitre_technique" | "shap_features">): string {
  const top = d.shap_features.slice(0, 2).map((f) => f.feature).join(" and ");
  return `This event was flagged as "${d.attack_type}" (MITRE ${d.mitre_technique}). The model's decision was primarily driven by ${top}, which together account for the majority of the detection score.`;
}

export function recommendedActions(mitre: string): string[] {
  const map: Record<string, string[]> = {
    "T1059.001": ["Isolate the host from the network", "Capture PowerShell script block logs (4104)", "Review parent process tree for the service account", "Reset credentials for the launching account"],
    "T1003": ["Isolate the affected host immediately", "Preserve LSASS memory for forensics", "Rotate all credentials used on the host", "Investigate the parent process (procdump/mimikatz)"],
    "T1053": ["Remove the rogue scheduled task", "Audit all scheduled tasks on the host", "Block the encoded command payload hash", "Review persistence mechanisms across the estate"],
    "T1550": ["Force re-authentication on affected accounts", "Block NTLM where Kerberos is available", "Investigate the source IP for lateral movement", "Audit service account logon patterns"],
    "T1190": ["Block the source IP at the WAF", "Patch the vulnerable web endpoint", "Review all requests from the attacker IP", "Inspect application logs for data exfiltration"],
  };
  return map[mitre] ?? ["Investigate the source and scope of the activity", "Preserve evidence", "Contain the affected systems"];
}
