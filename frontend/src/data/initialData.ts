export interface Process {
    PID: number;
    ImageFileName: string;
    ThreatScore: number;
    IsBrowser: boolean;
    CreateTime: string;
}

export interface NetworkConnection {
    Proto: string;
    LocalAddr: string;
    ForeignAddr: string;
    State: string;
}

export interface ScanResult {
    tool: string;
    pid: number;
    findings: Array<string | Record<string, unknown>>;
    severity?: string;
}

export const initialProcesses: Process[] = [
    // ─── Core Windows Services ──────────────────────────────────────
    { PID: 4, ImageFileName: "System", ThreatScore: 0.1, IsBrowser: false, CreateTime: "2026-04-28T06:32:08Z" },
    { PID: 108, ImageFileName: "Registry", ThreatScore: 0.0, IsBrowser: false, CreateTime: "2026-04-28T06:32:08Z" },
    { PID: 312, ImageFileName: "smss.exe", ThreatScore: 0.3, IsBrowser: false, CreateTime: "2026-04-28T06:32:10Z" },
    { PID: 416, ImageFileName: "csrss.exe", ThreatScore: 0.5, IsBrowser: false, CreateTime: "2026-04-28T06:32:12Z" },
    { PID: 504, ImageFileName: "wininit.exe", ThreatScore: 0.2, IsBrowser: false, CreateTime: "2026-04-28T06:32:14Z" },
    { PID: 548, ImageFileName: "csrss.exe", ThreatScore: 0.4, IsBrowser: false, CreateTime: "2026-04-28T06:32:14Z" },
    { PID: 620, ImageFileName: "winlogon.exe", ThreatScore: 0.3, IsBrowser: false, CreateTime: "2026-04-28T06:32:16Z" },
    { PID: 672, ImageFileName: "services.exe", ThreatScore: 0.2, IsBrowser: false, CreateTime: "2026-04-28T06:32:18Z" },
    { PID: 688, ImageFileName: "lsass.exe", ThreatScore: 1.8, IsBrowser: false, CreateTime: "2026-04-28T06:32:18Z" },
    { PID: 780, ImageFileName: "svchost.exe", ThreatScore: 0.6, IsBrowser: false, CreateTime: "2026-04-28T06:32:20Z" },
    { PID: 848, ImageFileName: "svchost.exe", ThreatScore: 0.4, IsBrowser: false, CreateTime: "2026-04-28T06:32:22Z" },
    { PID: 956, ImageFileName: "svchost.exe", ThreatScore: 0.5, IsBrowser: false, CreateTime: "2026-04-28T06:32:24Z" },
    { PID: 1064, ImageFileName: "svchost.exe", ThreatScore: 0.3, IsBrowser: false, CreateTime: "2026-04-28T06:32:26Z" },

    // ─── User Session ───────────────────────────────────────────────
    { PID: 1220, ImageFileName: "dwm.exe", ThreatScore: 0.1, IsBrowser: false, CreateTime: "2026-04-28T06:33:02Z" },
    { PID: 1388, ImageFileName: "explorer.exe", ThreatScore: 0.7, IsBrowser: false, CreateTime: "2026-04-28T06:33:10Z" },
    { PID: 1520, ImageFileName: "SearchHost.exe", ThreatScore: 0.2, IsBrowser: false, CreateTime: "2026-04-28T06:33:18Z" },
    { PID: 1672, ImageFileName: "RuntimeBroker.exe", ThreatScore: 0.3, IsBrowser: false, CreateTime: "2026-04-28T06:33:22Z" },
    { PID: 1804, ImageFileName: "ShellExperienceHost.exe", ThreatScore: 0.1, IsBrowser: false, CreateTime: "2026-04-28T06:33:28Z" },
    { PID: 1940, ImageFileName: "taskhostw.exe", ThreatScore: 0.4, IsBrowser: false, CreateTime: "2026-04-28T06:33:32Z" },
    { PID: 2080, ImageFileName: "sihost.exe", ThreatScore: 0.2, IsBrowser: false, CreateTime: "2026-04-28T06:33:40Z" },

    // ─── Corporate / Productivity Software ──────────────────────────
    { PID: 2256, ImageFileName: "OUTLOOK.EXE", ThreatScore: 1.2, IsBrowser: false, CreateTime: "2026-04-28T07:01:05Z" },
    { PID: 2412, ImageFileName: "EXCEL.EXE", ThreatScore: 2.4, IsBrowser: false, CreateTime: "2026-04-28T07:15:22Z" },
    { PID: 2580, ImageFileName: "Teams.exe", ThreatScore: 0.9, IsBrowser: false, CreateTime: "2026-04-28T07:02:10Z" },
    { PID: 2744, ImageFileName: "OneDrive.exe", ThreatScore: 1.1, IsBrowser: false, CreateTime: "2026-04-28T06:34:05Z" },

    // ─── Browsers (legitimate + suspicious sessions) ────────────────
    { PID: 3024, ImageFileName: "msedge.exe", ThreatScore: 1.3, IsBrowser: true, CreateTime: "2026-04-28T07:05:30Z" },
    { PID: 3168, ImageFileName: "msedge.exe", ThreatScore: 1.0, IsBrowser: true, CreateTime: "2026-04-28T07:05:32Z" },
    { PID: 3340, ImageFileName: "chrome.exe", ThreatScore: 3.6, IsBrowser: true, CreateTime: "2026-04-28T09:18:44Z" },
    { PID: 3488, ImageFileName: "chrome.exe", ThreatScore: 4.2, IsBrowser: true, CreateTime: "2026-04-28T09:18:46Z" },
    { PID: 3620, ImageFileName: "firefox.exe", ThreatScore: 2.1, IsBrowser: true, CreateTime: "2026-04-28T10:30:15Z" },

    // ─── Security / IT Tools ────────────────────────────────────────
    { PID: 3780, ImageFileName: "MsMpEng.exe", ThreatScore: 0.2, IsBrowser: false, CreateTime: "2026-04-28T06:32:30Z" },
    { PID: 3920, ImageFileName: "SecurityHealthSystray.exe", ThreatScore: 0.1, IsBrowser: false, CreateTime: "2026-04-28T06:33:50Z" },

    // ─── ⚠️ SUSPICIOUS / MALICIOUS PROCESSES ────────────────────────
    { PID: 4100, ImageFileName: "powershell.exe", ThreatScore: 7.8, IsBrowser: false, CreateTime: "2026-04-28T11:42:18Z" },
    { PID: 4264, ImageFileName: "certutil.exe", ThreatScore: 6.2, IsBrowser: false, CreateTime: "2026-04-28T11:43:05Z" },
    { PID: 4388, ImageFileName: "cmd.exe", ThreatScore: 5.1, IsBrowser: false, CreateTime: "2026-04-28T11:44:30Z" },
    { PID: 4520, ImageFileName: "rundll32.exe", ThreatScore: 8.4, IsBrowser: false, CreateTime: "2026-04-28T11:45:12Z" },
    { PID: 4680, ImageFileName: "mshta.exe", ThreatScore: 9.1, IsBrowser: false, CreateTime: "2026-04-28T11:46:55Z" },
    { PID: 4812, ImageFileName: "wscript.exe", ThreatScore: 7.3, IsBrowser: false, CreateTime: "2026-04-28T11:48:20Z" },
    { PID: 4960, ImageFileName: "regsvr32.exe", ThreatScore: 6.8, IsBrowser: false, CreateTime: "2026-04-28T11:49:40Z" },
    { PID: 5104, ImageFileName: "schtasks.exe", ThreatScore: 5.5, IsBrowser: false, CreateTime: "2026-04-28T11:50:30Z" },
    { PID: 5248, ImageFileName: "bitsadmin.exe", ThreatScore: 6.0, IsBrowser: false, CreateTime: "2026-04-28T11:51:15Z" },

    // ─── Remote Access / Suspicious Utilities ───────────────────────
    { PID: 5400, ImageFileName: "AnyDesk.exe", ThreatScore: 4.8, IsBrowser: false, CreateTime: "2026-04-28T12:05:10Z" },
    { PID: 5560, ImageFileName: "ncat.exe", ThreatScore: 9.5, IsBrowser: false, CreateTime: "2026-04-28T12:10:22Z" },
    { PID: 5720, ImageFileName: "rclone.exe", ThreatScore: 8.7, IsBrowser: false, CreateTime: "2026-04-28T12:15:48Z" },
];

export const initialNetworkConnections: Record<number, NetworkConnection[]> = {
    // ─── Legitimate Traffic ─────────────────────────────────────────
    780: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:49668", ForeignAddr: "20.190.159.71:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:49670", ForeignAddr: "13.107.42.14:443", State: "ESTABLISHED" },
    ],
    2256: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:50112", ForeignAddr: "52.96.166.130:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:50113", ForeignAddr: "40.99.150.18:443", State: "ESTABLISHED" },
    ],
    2580: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:50200", ForeignAddr: "52.113.194.132:443", State: "ESTABLISHED" },
    ],
    2744: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:50320", ForeignAddr: "13.107.42.12:443", State: "ESTABLISHED" },
    ],
    3024: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:51024", ForeignAddr: "204.79.197.200:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:51025", ForeignAddr: "13.107.21.200:443", State: "ESTABLISHED" },
        { Proto: "UDP", LocalAddr: "10.0.15.42:5353", ForeignAddr: "*:*", State: "LISTENING" },
    ],
    3340: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:51340", ForeignAddr: "142.250.80.46:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:51341", ForeignAddr: "142.250.189.206:443", State: "ESTABLISHED" },
    ],
    3488: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:51490", ForeignAddr: "185.199.108.133:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:51491", ForeignAddr: "104.18.32.68:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:51492", ForeignAddr: "91.108.56.100:443", State: "ESTABLISHED" },
    ],
    3620: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:51620", ForeignAddr: "34.117.65.55:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:51621", ForeignAddr: "151.101.1.69:443", State: "ESTABLISHED" },
    ],

    // ─── ⚠️ Suspicious C2 / Exfiltration Traffic ────────────────────
    4100: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:52100", ForeignAddr: "198.51.100.14:4443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:52101", ForeignAddr: "203.0.113.88:8080", State: "ESTABLISHED" },
    ],
    4264: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:52264", ForeignAddr: "198.51.100.14:443", State: "ESTABLISHED" },
    ],
    4520: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:52520", ForeignAddr: "45.33.32.156:4444", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:52521", ForeignAddr: "192.0.2.100:8443", State: "ESTABLISHED" },
    ],
    4680: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:52680", ForeignAddr: "203.0.113.22:443", State: "ESTABLISHED" },
    ],
    5400: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:53400", ForeignAddr: "185.204.1.235:7070", State: "ESTABLISHED" },
    ],
    5560: [
        { Proto: "TCP", LocalAddr: "0.0.0.0:4444", ForeignAddr: "0.0.0.0:0", State: "LISTENING" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:4444", ForeignAddr: "198.51.100.14:48210", State: "ESTABLISHED" },
    ],
    5720: [
        { Proto: "TCP", LocalAddr: "10.0.15.42:55720", ForeignAddr: "162.159.135.232:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:55721", ForeignAddr: "162.159.136.232:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "10.0.15.42:55722", ForeignAddr: "162.159.137.232:443", State: "ESTABLISHED" },
    ],
};

export const initialScanResults: Record<string, ScanResult> = {
    // ─── PowerShell — heavy code injection ──────────────────────────
    "4100-malfind": {
        tool: "malfind",
        pid: 4100,
        severity: "CRITICAL",
        findings: [
            "Suspicious memory region at 0x7FFE0300 with PAGE_EXECUTE_READWRITE (rwx)",
            "Injected shellcode detected: NOP sled pattern (0x90 x 512) at offset 0x7FFE0300",
            "PE header detected in non-image region at 0x00BC0000 — possible reflective DLL load",
            "Process hollowing indicators: original entry point modified in PEB",
            "Detoured API: ntdll.dll!NtCreateThreadEx redirected to 0x00BC1A40",
        ],
    },
    "4100-yara": {
        tool: "yara",
        pid: 4100,
        severity: "CRITICAL",
        findings: [
            "Rule matched: CobaltStrike_Beacon_x64",
            "Match at 0x00BC0100: MZ header with embedded config block",
            "Rule matched: PowerShell_EncodedCommand",
            "Match at 0x7FFE0400: 'powershell.exe -nop -w hidden -enc JABTA...'",
            "Rule matched: Mimikatz_Strings",
            "Match at 0x00BC2200: 'sekurlsa::logonpasswords'",
        ],
    },

    // ─── rundll32.exe — proxy execution ─────────────────────────────
    "4520-malfind": {
        tool: "malfind",
        pid: 4520,
        severity: "CRITICAL",
        findings: [
            "Code injection detected at 0x00400000 — 28KB executable region",
            "Modified IAT entries: kernel32.dll!CreateRemoteThread hooked → 0x004012B0",
            "Packed executable region with entropy 7.92 (threshold: 6.5)",
            "Reflective DLL injection artifacts: RtlUserThreadStart detour detected",
            "Suspicious thread context: start address outside all loaded modules",
            "Memory region at 0x004A0000 has PAGE_EXECUTE_READWRITE with no backing file",
        ],
    },
    "4520-yara": {
        tool: "yara",
        pid: 4520,
        severity: "HIGH",
        findings: [
            "Rule matched: SuspiciousShellcode_Generic",
            "Match at 0x004001C0: syscall stub for NtAllocateVirtualMemory",
            "Rule matched: ReflectiveDLLInjection",
            "Match at 0x00401000: 'ReflectiveLoader' export name",
        ],
    },

    // ─── mshta.exe — LOLBin abuse ───────────────────────────────────
    "4680-malfind": {
        tool: "malfind",
        pid: 4680,
        severity: "CRITICAL",
        findings: [
            "VBScript engine loaded with suspicious ActiveX controls",
            "Shellcode blob detected at 0x0A1E0000 — matches known Cobalt Strike stager",
            "WScript.Shell object created with hidden window style",
            "PowerShell child process spawned via COM object instantiation",
        ],
    },

    // ─── certutil.exe — download cradle ─────────────────────────────
    "4264-malfind": {
        tool: "malfind",
        pid: 4264,
        severity: "HIGH",
        findings: [
            "URL download cache contains entries for hxxps://198.51.100.14/payload.b64",
            "Base64 decoded content matches PE executable signature (MZ header)",
            "Certutil -urlcache -split -f command pattern detected in command line",
        ],
    },

    // ─── ncat.exe — reverse shell ───────────────────────────────────
    "5560-malfind": {
        tool: "malfind",
        pid: 5560,
        severity: "CRITICAL",
        findings: [
            "Listening socket bound to 0.0.0.0:4444 (all interfaces)",
            "Active connection from 198.51.100.14:48210 — known C2 IP",
            "STDIN/STDOUT redirected to socket (cmd.exe pipe pattern)",
            "Process created with CREATE_NO_WINDOW flag — hidden execution",
        ],
    },

    // ─── Browser forensics (chrome incognito) ───────────────────────
    "3488-chracer": {
        tool: "chracer",
        pid: 3488,
        severity: "HIGH",
        findings: [
            "Visited: hxxps://anonfiles.com/upload (2026-04-28 12:18:00 UTC)",
            "Visited: hxxps://privnote.com/xR7k29#enc_data (2026-04-28 12:20:15 UTC)",
            "Visited: hxxps://onion.ly/gateway (2026-04-28 12:25:00 UTC)",
            "Download initiated: confidential_q1_financials.7z from hxxps://mega.nz",
            "Visited: hxxps://temp-mail.org/en/ — disposable email service (2026-04-28 12:32:44 UTC)",
            "Visited: hxxps://protonmail.com/compose — secure email composer (2026-04-28 12:35:10 UTC)",
        ],
    },
    "3340-chracer": {
        tool: "chracer",
        pid: 3340,
        severity: "MEDIUM",
        findings: [
            "Visited: hxxps://pastebin.com/raw/Xt7z9kLm (2026-04-28 09:22:10 UTC)",
            "Visited: hxxps://github.com/swisskyrepo/PayloadsAllTheThings (2026-04-28 09:30:05 UTC)",
            "Searched: 'windows credential dumping tools 2026' (2026-04-28 09:45:00 UTC)",
            "Searched: 'how to exfiltrate data without detection' (2026-04-28 10:02:30 UTC)",
        ],
    },

    // ─── rclone.exe — data exfiltration ─────────────────────────────
    "5720-malfind": {
        tool: "malfind",
        pid: 5720,
        severity: "CRITICAL",
        findings: [
            "Rclone config loaded: remote type 'mega' with encrypted credentials",
            "Active transfer to MEGA cloud storage — 2.4GB data transferred",
            "Source path: C:\\Users\\jthompson\\Documents\\Finance\\Confidential\\",
            "Bandwidth throttle disabled — maximum upload speed detected",
            "Transfer log shows 847 files synced in 14 minutes",
        ],
    },

    // ─── wscript.exe — script-based attack ──────────────────────────
    "4812-malfind": {
        tool: "malfind",
        pid: 4812,
        severity: "HIGH",
        findings: [
            "VBScript dropper detected: creates .ps1 file in %TEMP%",
            "Anti-analysis check: WMI query for sandbox indicators (Win32_ComputerSystem)",
            "Registry persistence key written: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Downloaded secondary payload from hxxps://203.0.113.22/stage2.vbs",
        ],
    },

    // ─── AnyDesk — unauthorized remote access ───────────────────────
    "5400-malfind": {
        tool: "malfind",
        pid: 5400,
        severity: "MEDIUM",
        findings: [
            "AnyDesk configured with unattended access password",
            "Connection log shows 3 inbound sessions from external IP 185.204.1.235",
            "Session timestamps: 12:05, 12:18, 12:35 UTC — correlates with exfiltration window",
            "File transfer feature used: 12 files transferred during session",
        ],
    },
};
