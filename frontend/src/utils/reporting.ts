import type { Process } from "@/data/initialData";

export interface CriticalFinding {
  PID: number;
  ImageFileName: string;
  ThreatScore: number;
  Level: "CRITICAL" | "HIGH";
  Created: string;
  CreatedLabel: string;
}

function formatDate(value: string) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function buildCriticalFindings(processes: Process[]): CriticalFinding[] {
  return processes
    .filter((p) => p.ThreatScore > 3)
    .sort((a, b) => b.ThreatScore - a.ThreatScore)
    .map((p) => ({
      PID: p.PID,
      ImageFileName: p.ImageFileName,
      ThreatScore: p.ThreatScore,
      Level: p.ThreatScore >= 7 ? "CRITICAL" : "HIGH",
      Created: p.CreateTime,
      CreatedLabel: formatDate(p.CreateTime),
    }));
}

export function exportProcessReport(params: {
  processes: Process[];
  findings: CriticalFinding[];
  title?: string;
}) {
  const { processes, findings, title } = params;
  const reportWindow = window.open("", "_blank", "width=1024,height=720");
  if (!reportWindow) return false;

  const generatedAt = new Date().toLocaleString();
  const reportTitle = title || "Forensics Process Report";

  const processRows = processes
    .map((p) => {
      const created = formatDate(p.CreateTime);
      return `
        <tr>
          <td>${escapeHtml(String(p.PID))}</td>
          <td>${escapeHtml(p.ImageFileName)}</td>
          <td>${escapeHtml(p.IsBrowser ? "Browser" : "System")}</td>
          <td>${escapeHtml(p.ThreatScore.toFixed(1))}</td>
          <td>${escapeHtml(created)}</td>
        </tr>
      `;
    })
    .join("");

  const findingsRows =
    findings.length === 0
      ? `<tr><td colspan="4" class="empty">No critical findings detected.</td></tr>`
      : findings
        .map((f) => {
          return `
              <tr>
                <td>${escapeHtml(String(f.PID))}</td>
                <td>${escapeHtml(f.ImageFileName)}</td>
                <td>${escapeHtml(f.Level)}</td>
                <td>${escapeHtml(f.ThreatScore.toFixed(1))}</td>
              </tr>
            `;
        })
        .join("");

  reportWindow.document.write(`
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>${escapeHtml(reportTitle)}</title>
        <style>
          * { box-sizing: border-box; }
          body { font-family: "Segoe UI", Arial, sans-serif; margin: 32px; color: #111827; }
          h1 { font-size: 22px; margin: 0 0 6px; }
          h2 { font-size: 14px; margin: 24px 0 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #374151; }
          .meta { font-size: 12px; color: #6b7280; margin-bottom: 18px; }
          table { width: 100%; border-collapse: collapse; font-size: 12px; }
          th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
          th { background: #f3f4f6; text-transform: uppercase; font-size: 11px; letter-spacing: 0.06em; }
          .section { margin-bottom: 22px; }
          .empty { color: #6b7280; font-style: italic; }
          @media print {
            body { margin: 16px; }
            h2 { color: #111827; }
          }
        </style>
      </head>
      <body>
        <h1>${escapeHtml(reportTitle)}</h1>
        <div class="meta">Generated ${escapeHtml(generatedAt)}</div>

        <div class="section">
          <h2>Process List</h2>
          <table>
            <thead>
              <tr>
                <th>PID</th>
                <th>Process</th>
                <th>Type</th>
                <th>Threat Score</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              ${processRows}
            </tbody>
          </table>
        </div>

        <div class="section">
          <h2>Critical Findings</h2>
          <table>
            <thead>
              <tr>
                <th>PID</th>
                <th>Process</th>
                <th>Severity</th>
                <th>Threat Score</th>
              </tr>
            </thead>
            <tbody>
              ${findingsRows}
            </tbody>
          </table>
        </div>
      </body>
    </html>
  `);

  reportWindow.document.close();
  reportWindow.focus();
  reportWindow.onload = () => {
    reportWindow.print();
  };

  return true;
}
