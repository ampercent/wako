export interface BrowserArtifact {
    SessionID: string;
    Tab: number;
    Time: string;
    Title: string;
    URL: string;
}

export interface UnifiedHistoryEntry {
    Time: string;
    URL: string;
    Title: string;
    Source: "Disk" | "Memory (RAM)";
    Type: "Standard" | "Incognito";
}

export const initialBrowserArtifacts: BrowserArtifact[] = [
    // ─── PID 3024 — msedge.exe (Corporate Activity — legitimate) ────
    { SessionID: "PID-3024", Tab: 1, Time: "2026-04-28T07:08:15Z", Title: "Outlook Web App - Inbox (12)", URL: "https://outlook.office365.com/mail/inbox" },
    { SessionID: "PID-3024", Tab: 2, Time: "2026-04-28T07:12:30Z", Title: "SharePoint - Q1 Financial Review", URL: "https://contoso.sharepoint.com/sites/Finance/Q1-Review" },
    { SessionID: "PID-3024", Tab: 3, Time: "2026-04-28T07:25:00Z", Title: "Power BI - Revenue Dashboard", URL: "https://app.powerbi.com/groups/me/reports/a1b2c3d4" },
    { SessionID: "PID-3024", Tab: 4, Time: "2026-04-28T07:40:10Z", Title: "Azure DevOps - Sprint Board", URL: "https://dev.azure.com/contoso/platform/_boards" },
    { SessionID: "PID-3024", Tab: 5, Time: "2026-04-28T08:05:00Z", Title: "Confluence - Infrastructure Runbook", URL: "https://contoso.atlassian.net/wiki/spaces/INFRA/pages/1234567890" },

    // ─── PID 3168 — msedge.exe (Additional corporate tabs) ──────────
    { SessionID: "PID-3168", Tab: 1, Time: "2026-04-28T07:10:22Z", Title: "Microsoft Teams - Chat", URL: "https://teams.microsoft.com/_#/conversations" },
    { SessionID: "PID-3168", Tab: 2, Time: "2026-04-28T08:30:00Z", Title: "ServiceNow - Incident INC0084291", URL: "https://contoso.service-now.com/nav_to.do?uri=incident.do?sys_id=abc123" },
    { SessionID: "PID-3168", Tab: 3, Time: "2026-04-28T09:00:15Z", Title: "LinkedIn - Feed", URL: "https://www.linkedin.com/feed/" },

    // ─── PID 3340 — chrome.exe (Research → Suspicious) ──────────────
    { SessionID: "PID-3340", Tab: 1, Time: "2026-04-28T09:20:10Z", Title: "Stack Overflow - PowerShell base64 encode", URL: "https://stackoverflow.com/questions/15414678/powershell-base64-encode" },
    { SessionID: "PID-3340", Tab: 2, Time: "2026-04-28T09:22:10Z", Title: "Pastebin - Raw Dump", URL: "https://pastebin.com/raw/Xt7z9kLm" },
    { SessionID: "PID-3340", Tab: 3, Time: "2026-04-28T09:30:05Z", Title: "GitHub - PayloadsAllTheThings", URL: "https://github.com/swisskyrepo/PayloadsAllTheThings" },
    { SessionID: "PID-3340", Tab: 4, Time: "2026-04-28T09:45:00Z", Title: "Google Search: credential dumping tools 2026", URL: "https://www.google.com/search?q=windows+credential+dumping+tools+2026" },
    { SessionID: "PID-3340", Tab: 5, Time: "2026-04-28T10:02:30Z", Title: "Google Search: exfiltrate data without detection", URL: "https://www.google.com/search?q=how+to+exfiltrate+data+without+detection" },
    { SessionID: "PID-3340", Tab: 6, Time: "2026-04-28T10:10:00Z", Title: "Rclone Documentation - Mega Backend", URL: "https://rclone.org/mega/" },

    // ─── PID 3488 — chrome.exe (Incognito — Exfiltration / Dark) ────
    { SessionID: "PID-3488", Tab: 1, Time: "2026-04-28T12:18:00Z", Title: "AnonFiles - Upload Complete", URL: "https://anonfiles.com/upload" },
    { SessionID: "PID-3488", Tab: 2, Time: "2026-04-28T12:20:15Z", Title: "PrivNote - Destructing Note", URL: "https://privnote.com/xR7k29#enc_data" },
    { SessionID: "PID-3488", Tab: 3, Time: "2026-04-28T12:25:00Z", Title: "Dark Web Gateway - Tor2Web Proxy", URL: "https://onion.ly/gateway" },
    { SessionID: "PID-3488", Tab: 4, Time: "2026-04-28T12:28:30Z", Title: "MEGA - Encrypted Cloud Storage", URL: "https://mega.nz/folder/Xt7z9kLm#SECRET_KEY" },
    { SessionID: "PID-3488", Tab: 5, Time: "2026-04-28T12:32:44Z", Title: "Temp Mail - Disposable Email", URL: "https://temp-mail.org/en/" },
    { SessionID: "PID-3488", Tab: 6, Time: "2026-04-28T12:35:10Z", Title: "ProtonMail - Compose Secure Email", URL: "https://protonmail.com/compose" },
    { SessionID: "PID-3488", Tab: 7, Time: "2026-04-28T12:40:20Z", Title: "Bitcoin Mixer - CoinJoin Service", URL: "https://wasabiwallet.io/coinjoin" },
    { SessionID: "PID-3488", Tab: 8, Time: "2026-04-28T12:45:00Z", Title: "Signal Downloads - Encrypted Messenger", URL: "https://signal.org/download/" },

    // ─── PID 3620 — firefox.exe (Personal / Mixed Use) ──────────────
    { SessionID: "PID-3620", Tab: 1, Time: "2026-04-28T10:32:00Z", Title: "Reddit - r/sysadmin", URL: "https://www.reddit.com/r/sysadmin/" },
    { SessionID: "PID-3620", Tab: 2, Time: "2026-04-28T10:45:10Z", Title: "YouTube - Active Directory Security", URL: "https://www.youtube.com/watch?v=dQw4w9WgXcQ" },
    { SessionID: "PID-3620", Tab: 3, Time: "2026-04-28T11:05:30Z", Title: "Wikipedia - Advanced Persistent Threat", URL: "https://en.wikipedia.org/wiki/Advanced_persistent_threat" },
    { SessionID: "PID-3620", Tab: 4, Time: "2026-04-28T11:20:00Z", Title: "Hacker News - Front Page", URL: "https://news.ycombinator.com/" },
    { SessionID: "PID-3620", Tab: 5, Time: "2026-04-28T11:35:45Z", Title: "Amazon - Flipper Zero Kit", URL: "https://www.amazon.com/Flipper-Zero-Portable-Multi-tool/dp/B0BXYZ1234" },
];

export const initialUnifiedHistory: UnifiedHistoryEntry[] = [
    // ─── Morning Boot & Login (Disk — Standard) ────────────────────
    { Time: "2026-04-28T06:55:00Z", URL: "https://login.microsoftonline.com/", Title: "Microsoft 365 SSO Login", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T07:00:10Z", URL: "https://outlook.office365.com/mail/inbox", Title: "Outlook Web App - Inbox", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T07:05:00Z", URL: "https://contoso.sharepoint.com/sites/Finance", Title: "SharePoint - Finance Portal", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T07:12:00Z", URL: "https://contoso.sharepoint.com/sites/Finance/Q1-Review", Title: "SharePoint - Q1 Financial Review", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T07:25:00Z", URL: "https://app.powerbi.com/groups/me/reports/a1b2c3d4", Title: "Power BI - Revenue Dashboard", Source: "Disk", Type: "Standard" },

    // ─── Mid-Morning Work (Disk — Standard) ────────────────────────
    { Time: "2026-04-28T07:40:00Z", URL: "https://dev.azure.com/contoso/platform/_boards", Title: "Azure DevOps - Sprint Board", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T08:05:00Z", URL: "https://contoso.atlassian.net/wiki/spaces/INFRA/pages/1234567890", Title: "Confluence - Infrastructure Runbook", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T08:30:00Z", URL: "https://contoso.service-now.com/incident.do?sys_id=abc123", Title: "ServiceNow - INC0084291", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T08:50:00Z", URL: "https://www.cnn.com/business", Title: "CNN Business - Markets", Source: "Disk", Type: "Standard" },

    // ─── ⚠️ Research Phase — Escalating Suspicion (RAM — Incognito) ──
    { Time: "2026-04-28T09:18:00Z", URL: "https://stackoverflow.com/questions/15414678/powershell-base64-encode", Title: "Stack Overflow - PowerShell Base64", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T09:22:10Z", URL: "https://pastebin.com/raw/Xt7z9kLm", Title: "Pastebin - Raw Paste (obfuscated script)", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T09:30:05Z", URL: "https://github.com/swisskyrepo/PayloadsAllTheThings", Title: "GitHub - Offensive Security Payloads", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T09:45:00Z", URL: "https://www.google.com/search?q=windows+credential+dumping+tools+2026", Title: "Google Search - Credential Dumping Tools", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T10:02:30Z", URL: "https://www.google.com/search?q=how+to+exfiltrate+data+without+detection", Title: "Google Search - Data Exfiltration Methods", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T10:10:00Z", URL: "https://rclone.org/mega/", Title: "Rclone Documentation - MEGA Backend", Source: "Memory (RAM)", Type: "Incognito" },

    // ─── Normal Browsing Interlude (Disk — Standard) ────────────────
    { Time: "2026-04-28T10:30:00Z", URL: "https://www.reddit.com/r/sysadmin/", Title: "Reddit - r/sysadmin", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T10:45:10Z", URL: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", Title: "YouTube - AD Security Hardening", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T11:05:30Z", URL: "https://en.wikipedia.org/wiki/Advanced_persistent_threat", Title: "Wikipedia - Advanced Persistent Threat", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T11:20:00Z", URL: "https://news.ycombinator.com/", Title: "Hacker News", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T11:35:45Z", URL: "https://www.amazon.com/Flipper-Zero-Portable-Multi-tool/dp/B0BXYZ1234", Title: "Amazon - Flipper Zero Kit", Source: "Disk", Type: "Standard" },

    // ─── ⚠️ Attack Execution Window (RAM — Incognito) ────────────────
    { Time: "2026-04-28T11:42:00Z", URL: "https://raw.githubusercontent.com/n1nj4/rootkit-demo/main/loader.ps1", Title: "GitHub Raw - Rootkit Loader Script", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T11:55:00Z", URL: "https://github.com/gentilkiwi/mimikatz/releases", Title: "Mimikatz Releases - Credential Tool", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T12:08:00Z", URL: "https://darkweb-market.onion.ly/login", Title: "Dark Web Marketplace - Login Portal", Source: "Memory (RAM)", Type: "Incognito" },

    // ─── ⚠️ Exfiltration Phase (RAM — Incognito) ────────────────────
    { Time: "2026-04-28T12:18:00Z", URL: "https://anonfiles.com/upload", Title: "AnonFiles - File Upload Service", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T12:20:15Z", URL: "https://privnote.com/xR7k29#enc_data", Title: "PrivNote - Self-Destructing Note", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T12:25:00Z", URL: "https://onion.ly/gateway", Title: "Tor2Web - Dark Web Gateway", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T12:28:30Z", URL: "https://mega.nz/folder/Xt7z9kLm#SECRET_KEY", Title: "MEGA - Encrypted Cloud Folder", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T12:32:44Z", URL: "https://temp-mail.org/en/", Title: "Temp Mail - Disposable Email", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T12:35:10Z", URL: "https://protonmail.com/compose", Title: "ProtonMail - Secure Email Compose", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T12:40:20Z", URL: "https://wasabiwallet.io/coinjoin", Title: "Wasabi Wallet - Bitcoin CoinJoin Mixer", Source: "Memory (RAM)", Type: "Incognito" },

    // ─── Afternoon Cleanup / Normal (Disk — Standard) ───────────────
    { Time: "2026-04-28T12:50:00Z", URL: "https://drive.google.com/", Title: "Google Drive", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T13:10:00Z", URL: "https://www.linkedin.com/", Title: "LinkedIn - Profile", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T13:30:00Z", URL: "https://twitter.com/", Title: "Twitter / X", Source: "Disk", Type: "Standard" },
    { Time: "2026-04-28T13:45:00Z", URL: "https://www.google.com/maps", Title: "Google Maps", Source: "Disk", Type: "Standard" },

    // ─── ⚠️ Late Activity (RAM — Incognito) ─────────────────────────
    { Time: "2026-04-28T14:00:00Z", URL: "https://web.telegram.org/k/", Title: "Telegram Web - Encrypted Chat", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T14:15:00Z", URL: "https://signal.org/download/", Title: "Signal - Encrypted Messenger Download", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2026-04-28T14:30:00Z", URL: "https://www.dropbox.com/request/Xt7z9kLm", Title: "Dropbox - File Request Upload", Source: "Memory (RAM)", Type: "Incognito" },
];

export function extractDomain(url: string): string {
    try {
        return new URL(url).hostname.replace("www.", "");
    } catch {
        return url;
    }
}
