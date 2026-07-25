export interface ChallengeDef {
  id: string;
  title: string;
  mitre: string;
  tactic: string;
  difficulty: "Easy" | "Medium" | "Hard" | "Expert";
  briefing: string;
  starterYaml: string;
  targetPrecision: number;
  targetRecall: number;
}

export const CHALLENGES: ChallengeDef[] = [
  {
    id: "ch1-powershell",
    title: "Encoded PowerShell Execution",
    mitre: "T1059.001",
    tactic: "Execution",
    difficulty: "Medium",
    briefing:
      "A service account has launched PowerShell with an encoded command payload. Analysts have flagged suspicious child processes spawned by services.exe. Build a Sigma rule that detects encoded PowerShell execution without alerting on benign PowerShell use (e.g. Get-Process).",
    starterYaml: `title: Suspicious Encoded PowerShell Execution
id: 00000000-0000-0000-0000-000000000001
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
`,
    targetPrecision: 0.8,
    targetRecall: 0.8,
  },
  {
    id: "ch2-lsass",
    title: "LSASS Credential Access",
    mitre: "T1003",
    tactic: "Credential Access",
    difficulty: "Hard",
    briefing:
      "An attacker is attempting to dump credentials from LSASS memory using procdump or similar tools. Build a Sigma rule that detects suspicious access to lsass.exe by non-standard parent processes.",
    starterYaml: `title: Suspicious LSASS Memory Access
id: 00000000-0000-0000-0000-000000000002
status: experimental
description: Detects potential credential dumping via LSASS access.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains:
      - lsass
    ParentImage|contains:
      - procdump
  condition: selection
level: critical
`,
    targetPrecision: 0.7,
    targetRecall: 0.7,
  },
  {
    id: "ch3-schtasks",
    title: "Scheduled Task Creation",
    mitre: "T1053",
    tactic: "Execution",
    difficulty: "Medium",
    briefing:
      "Persistence has been established via a rogue scheduled task disguised as a Windows Update helper. The task launches a hidden, encoded PowerShell command. Build a Sigma rule that flags suspicious scheduled task creation.",
    starterYaml: `title: Suspicious Scheduled Task Creation
id: 00000000-0000-0000-0000-000000000003
status: experimental
description: Detects creation of suspicious scheduled tasks.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 4698
    Action|contains:
      - powershell
  condition: selection
level: high
`,
    targetPrecision: 0.8,
    targetRecall: 0.8,
  },
  {
    id: "ch4-pth",
    title: "Pass The Hash Detection",
    mitre: "T1550",
    tactic: "Defense Evasion, Lateral Movement",
    difficulty: "Expert",
    briefing:
      "An attacker is using Pass-the-Hash to authenticate as a service account across the domain. Suspicious logons show LogonType 9 (NewCredentials) and NTLM authentication where Kerberos is expected. Build a Sigma rule to detect this lateral movement pattern.",
    starterYaml: `title: Potential Pass The Hash Activity
id: 00000000-0000-0000-0000-000000000004
status: experimental
description: Detects possible Pass-the-Hash authentication events.
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
`,
    targetPrecision: 0.7,
    targetRecall: 0.7,
  },
  {
    id: "ch5-sqli",
    title: "SQL Injection Detection",
    mitre: "T1190",
    tactic: "Initial Access",
    difficulty: "Medium",
    briefing:
      "A web application is being probed for SQL injection. Requests contain classic SQLi payloads such as OR '1'='1' and sqlmap user agents. Build a Sigma rule that detects SQL injection attempts in web access logs.",
    starterYaml: `title: Web SQL Injection Attempt
id: 00000000-0000-0000-0000-000000000005
status: experimental
description: Detects SQL injection attempts in web access logs.
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
`,
    targetPrecision: 0.8,
    targetRecall: 0.8,
  },
];
