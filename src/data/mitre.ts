import type { MitreTechnique } from "@/types";

export const MITRE_TECHNIQUES: MitreTechnique[] = [
  { id: "T1059.001", name: "PowerShell", tactic: "Execution", description: "Adversaries may abuse PowerShell commands and scripts for execution. Encoded PowerShell is a common defense-evasion technique.", severity: "high" },
  { id: "T1003", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access", description: "Adversaries may attempt to access credential material stored in the LSASS process memory.", severity: "critical" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Execution", description: "Adversaries may abuse task scheduling functionality to execute malicious code for persistence.", severity: "high" },
  { id: "T1550", name: "Use Alternate Authentication Material", tactic: "Defense Evasion, Lateral Movement", description: "Adversaries may use alternate authentication material, such as Pass-the-Hash, to move laterally.", severity: "critical" },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", description: "Adversaries may attempt to exploit a weakness in a public-facing web application, e.g. SQL injection.", severity: "high" },
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", description: "Adversaries may abuse command and script interpreters for execution of arbitrary code.", severity: "medium" },
  { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion, Persistence, Privilege Escalation, Initial Access", description: "Adversaries may compromise accounts with legitimate access to systems.", severity: "medium" },
  { id: "T1110", name: "Brute Force", tactic: "Credential Access", description: "Adversaries may attempt to brute-force or guess passwords to obtain account credentials.", severity: "medium" },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence, Privilege Escalation", description: "Adversaries may configure system settings to automatically execute programs during boot or logon.", severity: "high" },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", description: "Adversaries may attempt to make an executable or file difficult to discover or analyze.", severity: "medium" },
  { id: "T1047", name: "Windows Management Instrumentation", tactic: "Execution", description: "Adversaries may abuse WMI for execution of arbitrary commands.", severity: "medium" },
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", description: "Adversaries may encrypt data on target systems to interrupt availability.", severity: "critical" },
];

export function getMitre(id: string): MitreTechnique | undefined {
  return MITRE_TECHNIQUES.find((t) => t.id === id);
}
