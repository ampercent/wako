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
    { PID: 4, ImageFileName: "System", ThreatScore: 0.2, IsBrowser: false, CreateTime: "2025-02-09T01:00:12Z" },
    { PID: 312, ImageFileName: "smss.exe", ThreatScore: 0.5, IsBrowser: false, CreateTime: "2025-02-09T01:00:14Z" },
    { PID: 456, ImageFileName: "csrss.exe", ThreatScore: 1.0, IsBrowser: false, CreateTime: "2025-02-09T01:00:16Z" },
    { PID: 612, ImageFileName: "wininit.exe", ThreatScore: 0.3, IsBrowser: false, CreateTime: "2025-02-09T01:00:18Z" },
    { PID: 768, ImageFileName: "Discord.exe", ThreatScore: 0.8, IsBrowser: false, CreateTime: "2025-02-09T01:00:20Z" },
    { PID: 892, ImageFileName: "Slack.exe", ThreatScore: 2.1, IsBrowser: false, CreateTime: "2025-02-09T01:00:22Z" },
    { PID: 1024, ImageFileName: "chrome.exe", ThreatScore: 1.5, IsBrowser: true, CreateTime: "2025-02-09T02:15:30Z" },
    { PID: 1156, ImageFileName: "chrome.exe", ThreatScore: 3.8, IsBrowser: true, CreateTime: "2025-02-09T02:15:32Z" },

    { PID: 2780, ImageFileName: "BitTorrent.exe", ThreatScore: 8.9, IsBrowser: false, CreateTime: "2025-02-09T01:00:24Z" },
    { PID: 3010, ImageFileName: "AnyDesk.exe", ThreatScore: 6.4, IsBrowser: false, CreateTime: "2025-02-09T06:15:30Z" },
    { PID: 3200, ImageFileName: "Zoom.exe", ThreatScore: 1.8, IsBrowser: false, CreateTime: "2025-02-09T01:00:28Z" },
    { PID: 3456, ImageFileName: "Notion.exe", ThreatScore: 3.2, IsBrowser: false, CreateTime: "2025-02-09T04:12:05Z" },
    { PID: 3700, ImageFileName: "Docker.exe", ThreatScore: 4.0, IsBrowser: false, CreateTime: "2025-02-09T07:00:00Z" },
];

export const initialNetworkConnections: Record<number, NetworkConnection[]> = {
    1024: [
        { Proto: "TCP", LocalAddr: "192.168.1.10:52341", ForeignAddr: "142.250.80.46:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "192.168.1.10:52342", ForeignAddr: "142.250.80.46:443", State: "ESTABLISHED" },
        { Proto: "UDP", LocalAddr: "192.168.1.10:5353", ForeignAddr: "*:*", State: "LISTENING" },
    ],
    1156: [
        { Proto: "TCP", LocalAddr: "192.168.1.10:52500", ForeignAddr: "185.70.41.35:443", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "192.168.1.10:52501", ForeignAddr: "91.108.56.100:443", State: "ESTABLISHED" },
    ],
    1900: [
        { Proto: "TCP", LocalAddr: "192.168.1.10:49200", ForeignAddr: "45.33.32.156:4444", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "192.168.1.10:49201", ForeignAddr: "104.21.234.77:80", State: "ESTABLISHED" },
    ],
    2780: [
        { Proto: "TCP", LocalAddr: "192.168.1.10:50100", ForeignAddr: "198.51.100.1:8080", State: "ESTABLISHED" },
        { Proto: "TCP", LocalAddr: "0.0.0.0:135", ForeignAddr: "0.0.0.0:0", State: "LISTENING" },
    ],
    3010: [
        { Proto: "TCP", LocalAddr: "192.168.1.10:51300", ForeignAddr: "203.0.113.50:443", State: "ESTABLISHED" },
    ],
};

export const initialScanResults: Record<string, ScanResult> = {
    "1900-malfind": {
        tool: "malfind",
        pid: 1900,
        severity: "HIGH",
        findings: [
            "Suspicious memory region at 0x7FFE0000 with PAGE_EXECUTE_READWRITE",
            "Injected shellcode detected: NOP sled pattern (0x90 x 256)",
            "Process hollowing indicators found in PEB",
        ],
    },
    "2780-malfind": {
        tool: "malfind",
        pid: 2780,
        severity: "CRITICAL",
        findings: [
            "Code injection detected at 0x00400000",
            "Modified IAT entries: kernel32.dll!CreateRemoteThread hooked",
            "Packed executable region detected with high entropy (7.8)",
            "Reflective DLL injection artifacts found",
        ],
    },
    "1156-chracer": {
        tool: "chracer",
        pid: 1156,
        severity: "MEDIUM",
        findings: [
            "Visited: hxxps://anonfiles.com/upload (2025-02-09 14:18:00)",
            "Visited: hxxps://privnote.com/xAc123#password (2025-02-09 14:20:15)",
            "Visited: hxxps://onion.ly/ (2025-02-09 14:25:00)",
            "Download: secret_archive.7z from untrusted source",
        ],
    },
    "1900-yara": {
        tool: "yara",
        pid: 1900,
        severity: "HIGH",
        findings: [
            "Rule matched: SuspiciousString",
            "Match at 0x00007FFEF00D: 'powershell -enc'",
        ],
    },
};
