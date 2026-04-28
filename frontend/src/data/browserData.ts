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
    // PID 1024 - chrome.exe (Corporate Activity)
    { SessionID: "PID-1024", Tab: 1, Time: "2025-02-09T09:15:30Z", Title: "Outlook Web App - Inbox (3)", URL: "https://outlook.office365.com/mail/inbox" },
    { SessionID: "PID-1024", Tab: 2, Time: "2025-02-09T09:20:10Z", Title: "Salesforce - Dashboard", URL: "https://na1.salesforce.com/home/home.jsp" },
    { SessionID: "PID-1024", Tab: 3, Time: "2025-02-09T09:45:00Z", Title: "Jira - ANT-1023: Fix Security Vulnerability", URL: "https://company.atlassian.net/browse/ANT-1023" },
    { SessionID: "PID-1024", Tab: 4, Time: "2025-02-09T10:05:00Z", Title: "Slack - #dev-ops", URL: "https://app.slack.com/client/T012345/C012345" },

    // PID 1156 - chrome.exe (Suspicious/Malicious)
    { SessionID: "PID-1156", Tab: 1, Time: "2025-02-09T14:18:00Z", Title: "AnonFiles - Upload Complete", URL: "https://anonfiles.com/upload" },
    { SessionID: "PID-1156", Tab: 2, Time: "2025-02-09T14:20:15Z", Title: "PrivNote - Destructing Note", URL: "https://privnote.com/xAc123#password" },
    { SessionID: "PID-1156", Tab: 3, Time: "2025-02-09T14:22:30Z", Title: "Temp Mail - Disposable Email", URL: "https://temp-mail.org/en/" },
    { SessionID: "PID-1156", Tab: 4, Time: "2025-02-09T14:25:00Z", Title: "Dark Web Gateway - Tor2Web", URL: "https://onion.ly/" },

    // PID 1340 - firefox.exe (Research/Exfiltration)
    { SessionID: "PID-1340", Tab: 1, Time: "2025-02-09T11:22:10Z", Title: "GitHub - torvalds/linux", URL: "https://github.com/torvalds/linux" },
    { SessionID: "PID-1340", Tab: 2, Time: "2025-02-09T11:25:00Z", Title: "Stack Overflow - 'How to bypass firewall python'", URL: "https://stackoverflow.com/questions/search?q=bypass+firewall" },
    { SessionID: "PID-1340", Tab: 3, Time: "2025-02-09T11:30:00Z", Title: "Google Cloud Storage - Bucket Browser", URL: "https://console.cloud.google.com/storage/browser/confidential-backups" },
    { SessionID: "PID-1340", Tab: 4, Time: "2025-02-09T11:35:00Z", Title: "WeTransfer - Transfer Files", URL: "https://wetransfer.com/" },

    // PID 2500 - msedge.exe (Personal/Distraction)
    { SessionID: "PID-2500", Tab: 1, Time: "2025-02-09T12:10:00Z", Title: "Netflix - Black Mirror", URL: "https://www.netflix.com/watch/8012345" },
    { SessionID: "PID-2500", Tab: 2, Time: "2025-02-09T12:15:00Z", Title: "Spotify - Deep Focus Playlist", URL: "https://open.spotify.com/playlist/37i9dQZF1DWZeKCadgRd5" },
    { SessionID: "PID-2500", Tab: 3, Time: "2025-02-09T12:20:00Z", Title: "Twitter - Trending Now", URL: "https://twitter.com/explore/tabs/trending" },
    { SessionID: "PID-2500", Tab: 4, Time: "2025-02-09T12:25:00Z", Title: "Amazon - Flipper Zero WiFi Devboard", URL: "https://www.amazon.com/Flipper-Zero-WiFi-Devboard/dp/B09X..." },
];

export const initialUnifiedHistory: UnifiedHistoryEntry[] = [
    { Time: "2025-02-09T08:55:00Z", URL: "https://login.microsoftonline.com/", Title: "Microsoft 365 Login", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T09:00:00Z", URL: "https://outlook.office.com/mail/", Title: "Outlook", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T09:15:00Z", URL: "https://company.sharepoint.com/sites/Finance", Title: "SharePoint - Finance Docs", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T09:30:00Z", URL: "https://www.cnn.com/", Title: "CNN - Breaking News", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T10:15:30Z", URL: "https://www.google.com/search?q=how+to+hide+processes", Title: "Google Search - Hide Processes", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T10:18:00Z", URL: "https://github.com/n1nj4/rootkit-demo", Title: "GitHub - Rootkit Demo", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T10:30:00Z", URL: "https://stackoverflow.com/", Title: "Stack Overflow", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T11:00:00Z", URL: "https://www.youtube.com/", Title: "YouTube", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T11:22:10Z", URL: "https://darkweb-market.onion/login", Title: "DarkWeb Market - Login", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T12:00:00Z", URL: "https://www.google.com/search?q=bitcoin+mixer", Title: "Google Search - Bitcoin Mixer", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T12:05:30Z", URL: "https://protonmail.com/login", Title: "ProtonMail Login", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T12:30:00Z", URL: "https://www.amazon.com/", Title: "Amazon", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T13:00:00Z", URL: "https://drive.google.com/", Title: "Google Drive", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T13:10:00Z", URL: "https://www.dropbox.com/upload", Title: "Dropbox - Uploading...", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T13:30:00Z", URL: "https://github.com/", Title: "GitHub", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T14:00:00Z", URL: "https://mega.nz/folder/SECRET_KEY", Title: "MEGA - Encrypted Folder", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T14:15:00Z", URL: "https://en.wikipedia.org/wiki/Computer_forensics", Title: "Wikipedia - Computer Forensics", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T14:30:00Z", URL: "https://twitter.com/", Title: "Twitter/X", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T15:00:00Z", URL: "https://web.telegram.org/", Title: "Telegram Web", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T15:10:00Z", URL: "https://signal.org/download/", Title: "Signal Downloads", Source: "Memory (RAM)", Type: "Incognito" },
    { Time: "2025-02-09T15:30:00Z", URL: "https://news.ycombinator.com/", Title: "Hacker News", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T16:00:00Z", URL: "https://www.linkedin.com/", Title: "LinkedIn", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T16:30:00Z", URL: "https://outlook.live.com/", Title: "Outlook", Source: "Disk", Type: "Standard" },
    { Time: "2025-02-09T17:00:00Z", URL: "https://www.google.com/maps", Title: "Google Maps", Source: "Disk", Type: "Standard" },
];

export function extractDomain(url: string): string {
    try {
        return new URL(url).hostname.replace("www.", "");
    } catch {
        return url;
    }
}
