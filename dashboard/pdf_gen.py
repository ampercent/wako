from fpdf import FPDF
import pandas as pd
from pathlib import Path

class ReportGenerator(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Antigravity Forensics - Investigation Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 5, body)
        self.ln()

    def add_process_table(self, df):
        self.set_font('Arial', 'B', 10)
        # Header
        cols = ['PID', 'Process Name', 'Threat Score']
        for col in cols:
            self.cell(40, 7, col, 1)
        self.ln()
        # Data
        self.set_font('Arial', '', 10)
        for _, row in df.iterrows():
            self.cell(40, 7, str(row['PID']), 1)
            self.cell(40, 7, str(row['ImageFileName'])[:20], 1)
            self.cell(40, 7, str(row['Threat Score']), 1)
            self.ln()

def generate_pdf_report(process_df, artifacts_summary, output_path):
    pdf = ReportGenerator()
    pdf.add_page()
    
    pdf.chapter_title("1. High Risk Processes")
    # Filter high risk
    if 'Threat Score' in process_df.columns:
        high_risk = process_df[process_df['Threat Score'] >= 3].head(10)
        pdf.add_process_table(high_risk)
    else:
        pdf.chapter_body("No threat scoring data available.")

    pdf.ln(10)
    pdf.chapter_title("2. Artifact Summary")
    pdf.chapter_body(artifacts_summary)

    pdf.output(output_path)
