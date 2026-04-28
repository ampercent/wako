import json
from fpdf import FPDF
from datetime import datetime
import pandas as pd
from typing import Dict, Any

class ReportGenerator:
    def __init__(self, output_dir: str = "C:/Major_Project/Layer1_Output_Edge/reports"):
        self.output_dir = output_dir
        import os
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_json_report(self, case_id: int, case_data: Dict[str, Any], alerts: list, timeline: list) -> str:
        report = {
            "case_id": case_id,
            "generated_at": datetime.now().isoformat(),
            "case_info": {
                "name": case_data.get("name"),
                "description": case_data.get("description"),
                "status": case_data.get("status")
            },
            "alerts": alerts,
            "timeline": timeline,
            "notes": case_data.get("notes", [])
        }
        
        filename = f"{self.output_dir}/report_case_{case_id}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        return filename

    def generate_pdf_report(self, case_id: int, case_data: Dict[str, Any], alerts: list, timeline: list) -> str:
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, "Antigravity Forensics Report", ln=True, align='C')
        pdf.ln(5)
        
        # Case Info
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 8, "Case Information", ln=True)
        pdf.set_font("Arial", '', 11)
        pdf.cell(0, 6, f"Case ID: {case_id}", ln=True)
        pdf.cell(0, 6, f"Name: {case_data.get('name', 'N/A')}", ln=True)
        pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(5)

        # Alerts / High-Risk Processes
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 8, "High-Risk Findings", ln=True)
        pdf.set_font("Arial", '', 10)
        
        if not alerts:
             pdf.cell(0, 6, "No high-risk findings detected.", ln=True)
        else:
            for alert in alerts:
                # Sanitize to avoid PDF encoding issues
                desc = str(alert.get('explanation', 'No explanation')).encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 6, f"- {desc}")
        pdf.ln(5)

        # Timeline Snippet
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 8, "Attack Timeline (Suspicious Events)", ln=True)
        pdf.set_font("Arial", '', 10)
        
        suspicious_timeline = [t for t in (timeline or []) if t.get('is_suspicious')]
        if not suspicious_timeline:
             pdf.cell(0, 6, "No suspicious timeline events recorded.", ln=True)
        else:
            for ev in suspicious_timeline[:20]: # Limit to 20
                ts = ev.get('timestamp', 'Unknown Time')
                desc = str(ev.get('description', '')).encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 6, f"[{ts}] {desc}")
                
        # Save
        filename = f"{self.output_dir}/report_case_{case_id}.pdf"
        pdf.output(filename)
        return filename
