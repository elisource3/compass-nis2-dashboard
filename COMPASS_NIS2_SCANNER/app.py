import json
import html
import os
import io
import urllib.parse
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Import per la generazione del PDF formale
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

MAX_FILE_SIZE_MB = 5  # <--- LIMITE SICUREZZA PER PREVENIRE DoS

# EUR-Lex Article 21 NIS2 Directive URL
EURLEX_ART21_BASE = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555#d1e3090-80-1"

# FIXED REPORT FILE NAME
REPORT_FILE = "compass_nis2_report.json"

# --- LOGO CYBER COMPASS SVG EMBEDDED ---
CYBER_COMPASS_SVG_HEADER = """
<svg width="110" height="110" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" style="filter: drop-shadow(0px 0px 10px rgba(0,255,170,0.5));">
  <path d="M50 5 L85 20 V45 C85 68 70 88 50 95 C30 88 15 68 15 45 V20 L50 5 Z" fill="#101826" stroke="#00ffaa" stroke-width="2.5" stroke-linejoin="round"/>
  <circle cx="50" cy="50" r="30" stroke="#00bfff" stroke-width="1.5" stroke-dasharray="4 2"/>
  <circle cx="50" cy="50" r="34" stroke="#223654" stroke-width="1"/>
  <line x1="50" y1="16" x2="50" y2="20" stroke="#00ffaa" stroke-width="2"/>
  <line x1="50" y1="80" x2="50" y2="84" stroke="#00ffaa" stroke-width="2"/>
  <line x1="16" y1="50" x2="20" y2="50" stroke="#00ffaa" stroke-width="2"/>
  <line x1="80" y1="50" x2="84" y2="50" stroke="#00ffaa" stroke-width="2"/>
  <polygon points="50,22 43,50 50,45" fill="#00ffaa"/>
  <polygon points="50,22 57,50 50,45" fill="#00bfff"/>
  <polygon points="50,78 43,50 50,55" fill="#223654"/>
  <polygon points="50,78 57,50 50,55" fill="#445b7c"/>
  <circle cx="50" cy="50" r="4" fill="#101826" stroke="#00ffaa" stroke-width="2"/>
  <circle cx="50" cy="50" r="1.5" fill="#00ffaa"/>
</svg>
"""

CYBER_COMPASS_SVG_SIDEBAR = """
<svg width="24" height="24" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" style="vertical-align: middle; margin-right: 8px;">
  <path d="M50 5 L85 20 V45 C85 68 70 88 50 95 C30 88 15 68 15 45 V20 L50 5 Z" fill="#101826" stroke="#00ffaa" stroke-width="3"/>
  <circle cx="50" cy="50" r="30" stroke="#00bfff" stroke-width="2" stroke-dasharray="4 2"/>
  <polygon points="50,22 43,50 50,45" fill="#00ffaa"/>
  <polygon points="50,22 57,50 50,45" fill="#00bfff"/>
  <polygon points="50,78 43,50 50,55" fill="#223654"/>
  <polygon points="50,78 57,50 50,55" fill="#445b7c"/>
  <circle cx="50" cy="50" r="4" fill="#101826" stroke="#00ffaa" stroke-width="2"/>
</svg>
"""

# --- SEVERITY LEVEL MAPPING & STYLING ---
SEVERITY_CONFIG = {
    "CRITICAL": {"label": "CRITICAL", "color": "#ff2a2a", "badge": "CRITICAL"},
    "HIGH": {"label": "HIGH", "color": "#ff7700", "badge": "HIGH"},
    "MEDIUM": {"label": "MEDIUM", "color": "#ffcc00", "badge": "MEDIUM"},
    "LOW": {"label": "LOW", "color": "#00bfff", "badge": "LOW"}
}

# --- NIS2 TECHNICAL EXPLANATIONS ---
NIS2_EXPLANATIONS = {
    "NIS2-Art21-2g-01": {
        "title": "CYBER HYGIENE (FIREWALL & NETWORK PROTECTION)",
        "law": "Article 21, Paragraph 2, Point g",
        "severity": "HIGH",
        "compliant_reason": "Local firewall is active and correctly configured.",
        "non_compliant_reason": "System firewall is disabled or unconfigured.",
        "remediation": "Enable local firewalls across all network profiles.",
        "windows_remediation": """1. Open Windows Defender Firewall.
2. Ensure Domain, Private and Public profiles are enabled.
3. Verify inbound rules.
4. Block unnecessary ports.

PowerShell:
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True""",
        "linux_remediation": """Ubuntu/Debian:
sudo ufw enable
sudo ufw status

RHEL/Rocky:
sudo systemctl enable firewalld
sudo systemctl start firewalld""",
        "macos_remediation": """Enable Application Firewall:
System Settings -> Network -> Firewall

Or via CLI:
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on""",
        "law_full_text": "Directive (EU) 2022/2555 — Article 21, Paragraph 2, Point g"
    },
    "NIS2-Art21-2h-01": {
        "title": "CRYPTOGRAPHY (DATA AT REST ENCRYPTION)",
        "law": "Article 21, Paragraph 2, Point h",
        "severity": "CRITICAL",
        "compliant_reason": "Disk encryption (BitLocker/LUKS) is active.",
        "non_compliant_reason": "Disk encryption is disabled.",
        "remediation": "Enable full-disk encryption (BitLocker / LUKS / FileVault).",
        "windows_remediation": """Enable BitLocker:
Control Panel -> BitLocker Drive Encryption

PowerShell:
Enable-BitLocker -MountPoint C:""",
        "linux_remediation": """Encrypt disks using LUKS:
sudo cryptsetup luksFormat /dev/sdX""",
        "macos_remediation": """Enable FileVault:
System Settings -> Privacy & Security -> FileVault

Or CLI:
sudo fdesetup enable""",
        "law_full_text": "Directive (EU) 2022/2555 — Article 21, Paragraph 2, Point h"
    },
    "NIS2-SB-01": {
        "title": "HARDENING & SECURE CONFIGURATION",
        "law": "Article 21, Paragraph 2, Point e",
        "severity": "MEDIUM",
        "compliant_reason": "Critical system parameters align with standard security benchmarks.",
        "non_compliant_reason": "System configuration vulnerabilities detected.",
        "remediation": "Enforce UAC, disable obsolete protocols (SMBv1, Telnet).",
        "windows_remediation": """Enable UAC. Disable SMBv1:
PowerShell:
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol""",
        "linux_remediation": """Disable unnecessary services:
sudo systemctl list-unit-files
Apply CIS Benchmark recommendations.""",
        "macos_remediation": """Enable Gatekeeper:
sudo spctl --master-enable""",
        "law_full_text": "Directive (EU) 2022/2555 — Article 21, Paragraph 2, Point e"
    },
    "NIS2-Art21-2e-01": {
        "title": "PATCH MANAGEMENT",
        "law": "Article 21, Paragraph 2, Point e",
        "severity": "HIGH",
        "compliant_reason": "Operating system is updated within established timeframes.",
        "non_compliant_reason": "System reboot pending or security updates missing.",
        "remediation": "Apply latest security patches and reboot host.",
        "windows_remediation": """PowerShell:
UsoClient StartScan
UsoClient StartInstall
Restart-Computer""",
        "linux_remediation": """Ubuntu/Debian:
sudo apt update && sudo apt upgrade -y && sudo reboot

RHEL/Rocky:
sudo dnf update -y && sudo reboot""",
        "macos_remediation": """softwareupdate -l
sudo softwareupdate -ia""",
        "law_full_text": "Directive (EU) 2022/2555 — Article 21, Paragraph 2, Point e"
    },
    "NIS2-Art21-2i-01": {
        "title": "ACCESS CONTROL & PRIVILEGES",
        "law": "Article 21, Paragraph 2, Point i",
        "severity": "CRITICAL",
        "compliant_reason": "User account follows least privilege policy.",
        "non_compliant_reason": "Session running with unnecessary administrative privileges.",
        "remediation": "Demote user to standard account; use LAPS / PAM for elevated tasks.",
        "windows_remediation": """Remove permanent admin access:
PowerShell:
Get-LocalGroupMember Administrators""",
        "linux_remediation": """Review sudo privileges:
sudo visudo""",
        "macos_remediation": """Review local administrators:
System Settings -> Users & Groups""",
        "law_full_text": "Directive (EU) 2022/2555 — Article 21, Paragraph 2, Point i"
    },
    "NIS2-Art21-2c-01": {
        "title": "OPERATIONAL RESILIENCE & BACKUP",
        "law": "Article 21, Paragraph 2, Point c",
        "severity": "CRITICAL",
        "compliant_reason": "Business continuity and backup mechanisms are operational.",
        "non_compliant_reason": "Lack of business continuity planning or missing backups.",
        "remediation": "Implement automated immutable backups (3-2-1-1-0 Rule).",
        "windows_remediation": """Enable automated backups via Windows Backup or Veeam.""",
        "linux_remediation": """Automate backups with rsync, borgbackup or restic.""",
        "macos_remediation": """Enable Time Machine with external or offsite storage.""",
        "law_full_text": "Directive (EU) 2022/2555 — Article 21, Paragraph 2, Point c"
    },
    "NIS2-Art21-2d-01": {
        "title": "ATTACK SURFACE REDUCTION",
        "law": "Article 21, Paragraph 2, Points d & e",
        "severity": "MEDIUM",
        "compliant_reason": "No unnecessary open ports or exposed services found.",
        "non_compliant_reason": "Unnecessary services or exposed ports identified.",
        "remediation": "Disable unused background network services.",
        "windows_remediation": """Review open ports:
netstat -ano""",
        "linux_remediation": """Check exposed services:
ss -tulpn""",
        "macos_remediation": """Review active services:
lsof -i""",
        "law_full_text": "Directive (EU) 2022/2555 — Article 21, Paragraph 2, Points d & e"
    }
}

# --- NIS2 HUMAN & GOVERNANCE CONTROLS TEMPLATE ---
HUMAN_CONTROLS_DEFINITIONS = [
    {
        "id": "GOV-HUM-01",
        "category": "PASSWORD & AUTHENTICATION POLICY",
        "law": "Art. 21.2(i)",
        "label": "Regular password rotation, complexity requirements, and mandatory Multi-Factor Authentication (MFA) policy enforced."
    },
    {
        "id": "GOV-HUM-02",
        "category": "CYBERSECURITY AWARENESS TRAINING",
        "law": "Art. 21.2(g)",
        "label": "Periodic phishing simulations and staff cybersecurity awareness training completed within last 12 months."
    },
    {
        "id": "GOV-HUM-03",
        "category": "INCIDENT RESPONSE PLAN",
        "law": "Art. 21.2(a)",
        "label": "Documented Incident Response Plan (IRP) with defined roles, communication channels, and 24h CSIRT reporting flow."
    },
    {
        "id": "GOV-HUM-04",
        "category": "SUPPLY CHAIN & VENDOR RISK",
        "law": "Art. 21.2(d)",
        "label": "Third-party vendor cybersecurity risk assessments and contractual security clauses conducted."
    },
    {
        "id": "GOV-HUM-05",
        "category": "OFFBOARDING & ASSET MANAGEMENT",
        "law": "Art. 21.2(i)",
        "label": "Formal employee offboarding checklist active (immediate account revocation, hardware collection)."
    }
]

# --- GENERAZIONE PDF AUDIT FORMALE ---
def generate_pdf_report(metadata, tech_controls, human_controls, score, global_risk):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=18, leading=22,
                                 textColor=colors.HexColor('#0b1220'), alignment=0)
    subtitle_style = ParagraphStyle('DocSubTitle', parent=styles['Normal'], fontSize=10, leading=12,
                                    textColor=colors.HexColor('#555555'))
    h2_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=12, leading=15,
                              textColor=colors.HexColor('#0b1220'), spaceBefore=10, spaceAfter=5)
    body_style = ParagraphStyle('TableBody', parent=styles['Normal'], fontSize=8, leading=10)
    body_bold = ParagraphStyle('TableBodyBold', parent=styles['Normal'], fontSize=8, leading=10,
                               fontName='Helvetica-Bold')

    elements = []

    # Intestazione Documento
    elements.append(Paragraph("COMPASS — OFFICIAL NIS2 COMPLIANCE AUDIT REPORT", title_style))
    elements.append(Paragraph("CONFIDENTIAL — FORMAL COMPLIANCE EVALUATION REPORT", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0b1220'), spaceBefore=8, spaceAfter=12))

    # Tabella Metadati System & Score
    meta_data = [
        [Paragraph("<b>Host Name:</b>", body_style), Paragraph(str(metadata.get('hostname', 'N/A')), body_style),
         Paragraph("<b>Compliance Score:</b>", body_style), Paragraph(f"<b>{score}%</b>", body_style)],
        [Paragraph("<b>Operating System:</b>", body_style),
         Paragraph(f"{metadata.get('os', '')} {metadata.get('os_release', '')}", body_style),
         Paragraph("<b>Global Risk Level:</b>", body_style), Paragraph(f"<b>{global_risk}</b>", body_style)],
        [Paragraph("<b>Audit Date:</b>", body_style), Paragraph(str(metadata.get('scan_time', 'N/A'))[:10], body_style),
         Paragraph("<b>Framework:</b>", body_style), Paragraph("EU NIS2 Directive (2022/2555)", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[1.3 * inch, 2.2 * inch, 1.4 * inch, 2.3 * inch])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f4f6f9')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e5e5')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(t_meta)
    elements.append(Spacer(1, 10))

    # Sezione 1: Controlli Tecnici
    elements.append(Paragraph("1. TECHNICAL ENDPOINT SECURITY CONTROLS", h2_style))
    tech_table_data = [
        [Paragraph("Control ID", body_bold), Paragraph("Category", body_bold), Paragraph("Ref.", body_bold),
         Paragraph("Status", body_bold), Paragraph("Details", body_bold)]]

    for c in tech_controls:
        status_color = colors.HexColor('#28a745') if c['status'] == 'COMPLIANT' else colors.HexColor('#dc3545')
        tech_table_data.append([
            Paragraph(c.get('nis2_control_id', ''), body_style),
            Paragraph(c.get('category', ''), body_style),
            Paragraph(c.get('requirement_reference', ''), body_style),
            Paragraph(f"<font color='{status_color.hexval()}'><b>{c['status']}</b></font>", body_style),
            Paragraph(c.get('details', '')[:120] + '...', body_style)
        ])

    t_tech = Table(tech_table_data, colWidths=[1.1 * inch, 1.8 * inch, 0.9 * inch, 1.1 * inch, 2.3 * inch])
    t_tech.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0b1220')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t_tech)
    elements.append(Spacer(1, 12))

    # Sezione 2: Controlli Governance/Umani
    elements.append(Paragraph("2. GOVERNANCE & HUMAN CONTROLS (ASSESSED)", h2_style))
    hum_table_data = [
        [Paragraph("Control ID", body_bold), Paragraph("Category", body_bold), Paragraph("Ref.", body_bold),
         Paragraph("Status", body_bold), Paragraph("Assessment Requirement", body_bold)]]

    for h in human_controls:
        status_str = "COMPLIANT" if h['checked'] else "NON-COMPLIANT"
        status_color = colors.HexColor('#28a745') if h['checked'] else colors.HexColor('#dc3545')
        hum_table_data.append([
            Paragraph(h['id'], body_style),
            Paragraph(h['category'], body_style),
            Paragraph(h['law'], body_style),
            Paragraph(f"<font color='{status_color.hexval()}'><b>{status_str}</b></font>", body_style),
            Paragraph(h['label'], body_style)
        ])

    t_hum = Table(hum_table_data, colWidths=[1.1 * inch, 1.8 * inch, 0.9 * inch, 1.1 * inch, 2.3 * inch])
    t_hum.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0b1220')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(t_hum)
    elements.append(Spacer(1, 25))

    # Sezione Firma Formale
    elements.append(Paragraph("3. AUDIT FORMAL SIGN-OFF & APPROVAL", h2_style))
    elements.append(Paragraph(
        "I hereby certify that the security technical scan and procedural governance assessments recorded in this document accurately represent the endpoint posture at the date of evaluation.",
        body_style))
    elements.append(Spacer(1, 20))

    sig_data = [
        [Paragraph("<b>Chief Information Security Officer (CISO) / Auditor</b>", body_style),
         Paragraph("<b>IT System Administrator / Manager</b>", body_style)],
        [Paragraph("Signature: ___________________________", body_style),
         Paragraph("Signature: ___________________________", body_style)],
        [Paragraph("Date: ________________________", body_style),
         Paragraph("Date: ________________________", body_style)]
    ]
    t_sig = Table(sig_data, colWidths=[3.6 * inch, 3.6 * inch])
    t_sig.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#aaaaaa')),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fafafa')),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t_sig)

    doc.build(elements)
    buffer.seek(0)
    return buffer


# Favicon Data URI
encoded_svg = urllib.parse.quote(CYBER_COMPASS_SVG_SIDEBAR)
favicon_data_url = f"data:image/svg+xml;utf8,{encoded_svg}"

st.set_page_config(
    page_title="COMPASS — NIS2 SECURITY DASHBOARD",
    page_icon=favicon_data_url,
    layout="wide"
)

# --- CUSTOM CSS ---
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&display=swap');

/* Applicazione estesa del font Orbitron a TUTTI gli header e titoli */
.header-title, 
.cyber-title, 
[data-testid="stMetricValue"], 
h1, h2, h3, h4,
.stSubheader, 
[data-testid="stMarkdownContainer"] h2,
[data-testid="stMarkdownContainer"] h3 {
    font-family: 'Orbitron', sans-serif !important;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}

/* Eccezione: Mantieni il testo leggibile dentro i box expander */
[data-testid="stExpander"] h1, 
[data-testid="stExpander"] h2, 
[data-testid="stExpander"] h3,
[data-testid="stExpander"] h4,
[data-testid="stExpander"] p {
    font-family: inherit !important;
    letter-spacing: normal !important;
    text-transform: none !important;
}

.stApp {
    background-color: #0b1220;
}

.header-container {
    display: flex;
    align-items: center;
    gap: 30px;
    background: #101826;
    padding: 25px;
    border-radius: 14px;
    border: 1px solid #223654;
    margin-bottom: 25px;
}

.header-title {
    font-size: 2.4rem;
    color: #ffffff;
    font-weight: 900;
}

.header-subtitle {
    color: #00ffaa;
    font-size: 1.1rem;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
}

[data-testid="stMetric"] {
    background-color: #101826;
    border: 1px solid #00ffaa;
    padding: 15px;
    border-radius: 12px;
}

section[data-testid="stSidebar"] {
    background-color: #08111f;
}

.severity-pill {
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 0.70rem;
    font-family: 'Orbitron', sans-serif;
    display: inline-block;
    line-height: 1.2;
    letter-spacing: 1px;
    text-transform: uppercase;
}

.ok-pill {
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 0.70rem;
    font-family: 'Orbitron', sans-serif;
    display: inline-block;
    background-color: #00ffaa;
    color: #000000;
    line-height: 1.2;
    letter-spacing: 1px;
    text-transform: uppercase;
}

div[data-baseweb="radio"] label {
    background:#101826 !important;
    border:1px solid #223654 !important;
    border-radius:8px !important;
    padding:6px 12px !important;
    margin-right:6px !important;
    transition:all .2s ease;
}

div[data-baseweb="radio"] label:hover {
    border:1px solid #00ffaa !important;
}
</style>
""", unsafe_allow_html=True)

# --- HEADER SECTION ---
st.markdown(
    f"""
    <div class="header-container">
        <div>{CYBER_COMPASS_SVG_HEADER}</div>
        <div>
            <div class="header-title">COMPASS</div>
            <div class="header-subtitle">NIS2 RISK & CRITICALITY ASSESSMENT</div>
            <div style="color: #8ea6c9; margin-top: 5px; text-transform: uppercase;">Compliance Evaluation & Risk-Based Severity Matrix</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# --- SIDEBAR NAV & FILE LOADING LOGIC ---
sb_col1, sb_col2 = st.sidebar.columns([1, 4])
with sb_col1:
    st.markdown(CYBER_COMPASS_SVG_SIDEBAR, unsafe_allow_html=True)
with sb_col2:
    st.markdown("### **COMPASS NAV**")

uploaded_file = st.sidebar.file_uploader("📂 LOAD JSON REPORT", type=["json"])

# Opzione facoltativa per forzare l'uso del file locale solo se spuntata
use_local_file = st.sidebar.checkbox("Use local 'compass_nis2_report.json'", value=False)

data = None

if uploaded_file is not None:
    # 1. Controllo dimensione del file (Protezione DoS - Max 5 MB)
    if uploaded_file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
        st.error(f"❌ File troppo grande. Il limite massimo consentito è {MAX_FILE_SIZE_MB} MB.")
        st.stop()

    try:
        # 2. Caricamento e parsing sicuro
        data = json.load(uploaded_file)

        # Validazione della struttura minima attesa
        if "nis2_compliance_results" not in data and not isinstance(data, list):
            st.error("❌ Struttura del file JSON non riconosciuta o incompatibile con COMPASS.")
            st.stop()

        st.sidebar.success("File manually uploaded successfully!")

    except json.JSONDecodeError:
        st.error("❌ Il file caricato non è un JSON valido o risulta corrotto.")
        st.stop()

elif use_local_file and os.path.exists(REPORT_FILE):
    # Se l'utente attiva la spunta, carica il file locale in modo sicuro
    st.sidebar.info(f"Loaded local file: `{REPORT_FILE}`")
    try:
        with open(REPORT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        st.error("❌ Il file locale non è un JSON valido.")
        st.stop()
else:
    # Se non c'è né upload né spunta locale, la sessione viene pulita e l'app si ferma
    st.session_state.clear()
    st.warning("⚠️ No audit report loaded. Please upload a valid JSON scan report from the sidebar.")
    st.stop()



metadata = data["scanner_metadata"]
controls = data["nis2_compliance_results"]

# Enrich controls with severity
for c in controls:
    ctrl_id = c.get("nis2_control_id", "")
    info = NIS2_EXPLANATIONS.get(ctrl_id, {})
    c["severity"] = info.get("severity", "MEDIUM") if c["status"] != "COMPLIANT" else "-"

scan_date_str = metadata.get("scan_time", "N/A")[:10]

historical_reports = [
    f for f in os.listdir(".")
    if f.startswith("compass_nis2_report")
    and f.endswith(".json")
]

# --- HISTORICAL REPORTS PARSING ---
history = []
for report_file in historical_reports:
    try:
        with open(report_file, "r", encoding="utf-8") as f:
            report = json.load(f)
        controls_hist = report["nis2_compliance_results"]
        total_hist = len(controls_hist)
        compliant_hist = sum(1 for c in controls_hist if c["status"] == "COMPLIANT")
        score_hist = round((compliant_hist / total_hist) * 100, 1) if total_hist > 0 else 0.0
        findings_hist = total_hist - compliant_hist

        history.append({
            "Date": report["scanner_metadata"]["scan_time"][0:10],
            "Score": score_hist,
            "Findings": findings_hist
        })
    except Exception:
        pass

# --- SIDEBAR INFO ---
st.sidebar.markdown("---")
st.sidebar.markdown("### 🖥️ ASSET")
st.sidebar.write(f"**Host**  \n`{metadata.get('hostname','N/A')}`")
st.sidebar.write(f"**OS**  \n`{metadata.get('os','N/A')} {metadata.get('os_release','')}`")
st.sidebar.write(f"**Last Audit**  \n`{scan_date_str}`")

st.sidebar.markdown("---")
st.sidebar.markdown("### 📈 AUDIT INTELLIGENCE")
st.sidebar.metric("Stored Audits", len(historical_reports))
show_history = st.sidebar.toggle("Historical Tracking", value=False)

# --- HUMAN & GOVERNANCE CONTROLS ---
st.subheader("👤 HUMAN & GOVERNANCE NIS2 CONTROLS (MANUAL ASSESSMENT)")
st.write("Tick the non-technical governance practices verified in your organizational policies:")

evaluated_human_controls = []
h_col1, h_col2 = st.columns(2)

for idx, h_def in enumerate(HUMAN_CONTROLS_DEFINITIONS):
    target_col = h_col1 if idx % 2 == 0 else h_col2
    with target_col:
        is_checked = st.checkbox(
            f"**[{h_def['id']}] {h_def['category']}** ({h_def['law']})\n\n{h_def['label']}",
            value=False,
            key=f"chk_{h_def['id']}"
        )
        evaluated_human_controls.append({
            "id": h_def['id'],
            "category": h_def['category'],
            "law": h_def['law'],
            "label": h_def['label'],
            "checked": is_checked
        })

# --- METRIC CALCULATION ---
total_tech = len(controls)
compliant_tech = sum(1 for c in controls if c["status"] == "COMPLIANT")

total_human = len(evaluated_human_controls)
compliant_human = sum(1 for h in evaluated_human_controls if h["checked"])

total_combined = total_tech + total_human
compliant_combined = compliant_tech + compliant_human
score = round((compliant_combined / total_combined) * 100, 1) if total_combined > 0 else 0.0

# Count severities for NON-COMPLIANT technical controls
crit_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for c in controls:
    if c["status"] != "COMPLIANT":
        ctrl_id = c.get("nis2_control_id", "")
        sev = NIS2_EXPLANATIONS.get(ctrl_id, {}).get("severity", "MEDIUM")
        crit_counts[sev] = crit_counts.get(sev, 0) + 1

# Add unchecked human controls as HIGH severity risks
for h in evaluated_human_controls:
    if not h["checked"]:
        crit_counts["HIGH"] += 1

# Global Risk Level Evaluation
if crit_counts["CRITICAL"] > 0:
    global_risk = "CRITICAL RISK"
    risk_color = "#ff2a2a"
elif crit_counts["HIGH"] > 0:
    global_risk = "HIGH RISK"
    risk_color = "#ff7700"
elif crit_counts["MEDIUM"] > 0:
    global_risk = "MEDIUM RISK"
    risk_color = "#ffcc00"
elif crit_counts["LOW"] > 0:
    global_risk = "LOW RISK"
    risk_color = "#00bfff"
else:
    global_risk = "NO RISK (FULL COMPLIANT)"
    risk_color = "#00ffaa"

# --- SIDEBAR OVERVIEW ---
st.sidebar.markdown("---")
st.sidebar.markdown("### 🚨 RISK OVERVIEW")
st.sidebar.metric("Security Score", f"{score}%")
st.sidebar.markdown(
    f"""
    <div style="background:#101826; border-left:5px solid {risk_color}; padding:10px; border-radius:8px; font-weight:bold;">
    {global_risk}
    </div>
    """,
    unsafe_allow_html=True
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔥 QUICK STATS")
st.sidebar.metric("Critical Findings", crit_counts["CRITICAL"])
st.sidebar.metric("High Findings", crit_counts["HIGH"])

st.sidebar.markdown("---")
if score >= 90:
    st.sidebar.success("✅ AUDIT READY")
elif score >= 70:
    st.sidebar.warning("⚠ NEEDS IMPROVEMENT")
else:
    st.sidebar.error("🚨 IMMEDIATE REMEDIATION REQUIRED")

# --- PDF GENERATION DOWNLOAD SIDEBAR ---
st.sidebar.markdown("---")
st.sidebar.markdown("### 📄 AUDIT REPORT")
pdf_buffer = generate_pdf_report(metadata, controls, evaluated_human_controls, score, global_risk)
st.sidebar.download_button(
    label="📥 DOWNLOAD OFFICIAL PDF REPORT",
    data=pdf_buffer,
    file_name=f"NIS2_Audit_Report_{metadata.get('hostname', 'host')}.pdf",
    mime="application/pdf",
    use_container_width=True
)

st.divider()

# --- TOP METRIC CARDS ---
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("COMBINED SECURITY SCORE", f"{score}%")
with col2:
    st.metric("COMPLIANT CONTROLS", f"{compliant_combined} / {total_combined}")
with col3:
    st.metric("HUMAN CONTROLS OK", f"{compliant_human} / {total_human}")
with col4:
    # Sanitizzazione del livello di rischio globale
    safe_global_risk = html.escape(str(global_risk))

    st.markdown(
        f"""
        <div style="font-family: 'Orbitron', sans-serif; text-transform: uppercase;">
            <span style="color: #8ea6c9; font-size: 13px;">GLOBAL RISK LEVEL</span><br>
            <span style='color:{risk_color}; font-size:20px; font-weight:bold;'>{global_risk}</span>
        </div>
        """,
        unsafe_allow_html=True
    )

st.divider()

# --- CHARTS SECTION ---
col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("CRITICALITY DISTRIBUTION OF NON-COMPLIANCES")

    df_severity = pd.DataFrame([
        {"Criticality": "CRITICAL", "Count": crit_counts["CRITICAL"]},
        {"Criticality": "HIGH", "Count": crit_counts["HIGH"]},
        {"Criticality": "MEDIUM", "Count": crit_counts["MEDIUM"]},
        {"Criticality": "LOW", "Count": crit_counts["LOW"]}
    ])

    fig_sev = px.bar(
        df_severity,
        x="Criticality",
        y="Count",
        color="Criticality",
        color_discrete_map={
            "CRITICAL": "#ff2a2a",
            "HIGH": "#ff7700",
            "MEDIUM": "#ffcc00",
            "LOW": "#00bfff"
        }
    )
    fig_sev.update_layout(paper_bgcolor="#0b1220", plot_bgcolor="#0b1220", font_color="white")
    st.plotly_chart(fig_sev, use_container_width=True)

with col_right:
    st.subheader("NIS2 SECURITY POSTURE RADAR")

    radar_labels = [c["category"].upper().replace("&AMP;", "&").replace("&", "&") for c in controls]
    radar_scores = [100 if c["status"] == "COMPLIANT" else 0 for c in controls]

    for h in evaluated_human_controls:
        radar_labels.append(h["category"].upper().replace("&AMP;", "&").replace("&", "&"))
        radar_scores.append(100 if h["checked"] else 0)

    fig_radar = go.Figure(go.Scatterpolar(
        r=radar_scores,
        theta=radar_labels,
        fill="toself",
        line=dict(color="#00ffaa", width=2),
        fillcolor="rgba(0,255,170,0.2)"
    ))

    fig_radar.update_layout(
        paper_bgcolor="#0b1220",
        plot_bgcolor="#0b1220",
        font_color="white",
        height=380,
        polar=dict(
            bgcolor="#0b1220",
            radialaxis=dict(visible=True, range=[0, 100])
        )
    )

    st.plotly_chart(fig_radar, use_container_width=True)


# --- HISTORICAL AUDITS TRACKING ---
if show_history and len(history) > 1:
    st.divider()
    st.subheader("HISTORICAL AUDITS TRACKING")

    history_df = pd.DataFrame(history)
    history_df["Date"] = pd.to_datetime(history_df["Date"])
    history_df = history_df.sort_values(by="Date")

    trend_col1, trend_col2 = st.columns(2)

    with trend_col1:
        fig_score = px.line(history_df, x="Date", y="Score", markers=True)
        fig_score.update_traces(line_color="#00ffaa", line_width=4, marker_size=10)
        fig_score.update_layout(
            title="Compliance Score Evolution",
            paper_bgcolor="#0b1220",
            plot_bgcolor="#0b1220",
            font_color="white",
            height=420
        )
        st.plotly_chart(fig_score, use_container_width=True)

    with trend_col2:
        fig_findings = px.line(history_df, x="Date", y="Findings", markers=True)
        fig_findings.update_traces(line_color="#ff2a2a", line_width=4, marker_size=10)
        fig_findings.update_layout(
            title="Open Findings Evolution",
            paper_bgcolor="#0b1220",
            plot_bgcolor="#0b1220",
            font_color="white",
            height=420
        )
        st.plotly_chart(fig_findings, use_container_width=True)

    latest_score = history_df["Score"].iloc[-1]
    first_score = history_df["Score"].iloc[0]
    delta_score = latest_score - first_score

    if delta_score > 0:
        trend_message = f"Compliance improved by {delta_score:.1f}% during the audit period."
        trend_color = "#00ffaa"
    elif delta_score < 0:
        trend_message = f"Compliance decreased by {abs(delta_score):.1f}% during the audit period."
        trend_color = "#ff2a2a"
    else:
        trend_message = "Compliance remained stable."
        trend_color = "#00bfff"

    # 🛡️ SANITIZZAZIONE DEL MESSAGGIO DINAMICO
    safe_trend_message = html.escape(trend_message)
    safe_history_len = html.escape(str(len(history_df)))
    safe_latest_score = html.escape(str(latest_score))

    st.markdown(
        f"""
        <div style="background:#101826; border:1px solid #223654; border-left:6px solid {trend_color}; border-radius:12px; padding:20px; margin-top:15px;">
            <h4 style="margin:0; color:white; font-family:'Orbitron', sans-serif;">📊 AUDIT EVOLUTION SUMMARY</h4>
            <p style="color:#8ea6c9; margin-top:10px;">
                Historical Audits Analysed: <b>{safe_history_len}</b><br><br>
                Current Compliance Score: <b>{safe_latest_score}%</b><br><br>
                {safe_trend_message}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

# ==============================================================================
# --- SUMMARY TABLE & EXPORT SECTION ---
# ==============================================================================
st.divider()
st.subheader("NIS2 AUDIT SUMMARY TABLE & EXPORT")

# Costruzione DataFrame unificato (Technical + Human)
summary_list = []

for c in controls:
    ctrl_id = c.get("nis2_control_id", "")
    info = NIS2_EXPLANATIONS.get(ctrl_id, {})
    summary_list.append({
        "Type": "Technical",
        "Control ID": ctrl_id,
        "Category": c.get("category", "N/A"),
        "Legal Reference": c.get("requirement_reference", "Art. 21 NIS2"),
        "Status": c.get("status", "UNKNOWN"),
        "Severity": info.get("severity", "MEDIUM") if c.get("status") != "COMPLIANT" else "NONE",
        "Evidence / Requirement": c.get("details", "")
    })

for h in evaluated_human_controls:
    summary_list.append({
        "Type": "Governance",
        "Control ID": h["id"],
        "Category": h["category"],
        "Legal Reference": h["law"],
        "Status": "COMPLIANT" if h["checked"] else "NON-COMPLIANT",
        "Severity": "HIGH" if not h["checked"] else "NONE",
        "Evidence / Requirement": h["label"]
    })

df_summary = pd.DataFrame(summary_list)

# Filtri per la tabella
filter_col1, filter_col2 = st.columns([1, 1])
with filter_col1:
    status_filter = st.multiselect(
        "Filter by Status",
        options=["COMPLIANT", "NON-COMPLIANT"],
        default=["COMPLIANT", "NON-COMPLIANT"]
    )
with filter_col2:
    type_filter = st.multiselect(
        "Filter by Type",
        options=["Technical", "Governance"],
        default=["Technical", "Governance"]
    )

df_filtered = df_summary[
    (df_summary["Status"].isin(status_filter)) &
    (df_summary["Type"].isin(type_filter))
]

st.dataframe(
    df_filtered,
    use_container_width=True,
    column_config={
        "Status": st.column_config.TextColumn(
            "Status",
            help="Compliance Status"
        ),
        "Severity": st.column_config.TextColumn(
            "Severity",
            help="Criticality level if non-compliant"
        )
    },
    hide_index=True
)

# Export Buttons Row (CSV & PDF)
export_col1, export_col2 = st.columns(2)

with export_col1:
    csv_data = df_filtered.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 EXPORT SUMMARY TABLE AS CSV",
        data=csv_data,
        file_name=f"NIS2_Summary_{metadata.get('hostname', 'host')}.csv",
        mime="text/csv",
        use_container_width=True
    )

with export_col2:
    st.download_button(
        label="📄 EXPORT OFFICIAL COMPLIANCE REPORT (PDF)",
        data=pdf_buffer,
        file_name=f"NIS2_Audit_Report_{metadata.get('hostname', 'host')}.pdf",
        mime="application/pdf",
        use_container_width=True
    )

# --- DETAILED TECHNICAL CONTROL ANALYSIS ---
st.divider()
st.subheader("DETAILED TECHNICAL CONTROL ANALYSIS")

os_choice = st.radio(
    "Select your current Operating System",
    options=["Microsoft Windows", "Linux", "macOS"],
    horizontal=True,
    key="global_os_selector"
)


# Loop controlli tecnici
for control in controls:
    is_compliant = (control["status"] == "COMPLIANT")
    icon = "✅" if is_compliant else "❌"
    ctrl_id = control.get("nis2_control_id", "")

    info = NIS2_EXPLANATIONS.get(ctrl_id, {
        "title": control.get('category', ctrl_id).upper(),
        "law": f"Req: {control.get('requirement_reference', 'Art. 21 NIS2')}",
        "severity": "MEDIUM",
        "compliant_reason": "Compliant with security requirements.",
        "non_compliant_reason": "Compliance anomaly detected.",
        "remediation": "Apply relevant company security policies.",
        "windows_remediation": "Refer to official Windows security baseline.",
        "linux_remediation": "Refer to CIS Benchmarks for Linux.",
        "macos_remediation": "Refer to Apple Security Configuration Guide.",
        "law_full_text": "«Article 21, EU Directive 2022/2555»"
    })

    sev_key = info.get("severity", "MEDIUM")
    sev_cfg = SEVERITY_CONFIG.get(sev_key, SEVERITY_CONFIG["MEDIUM"])

    if is_compliant:
        expander_title = f"{icon} {ctrl_id} — {info['title']}"
    else:
        expander_title = f"{icon} [{sev_cfg['label']}] {ctrl_id} — {info['title']}"

    with st.expander(expander_title):
        col_a, col_b = st.columns([3, 1])

        with col_a:
            st.write(f"**Regulatory Reference:** `{info['law']}`")
        with col_b:
            if not is_compliant:
                st.markdown(
                    f"""<div style="text-align:right;">
                        <span style="font-size: 0.75rem; color: #8ea6c9; text-transform: uppercase;">Criticality Level:</span><br>
                        <span class="severity-pill" style="background-color:{sev_cfg['color']}; color:black;">
                            {sev_cfg['badge']}
                        </span>
                    </div>""",
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    """<div style="text-align:right;">
                        <span style="font-size: 0.75rem; color: #8ea6c9; text-transform: uppercase;">STATUS:</span><br>
                        <span class="ok-pill">
                            COMPLIANT
                        </span>
                    </div>""",
                    unsafe_allow_html=True
                )

        # Sanitizzazione del dettaglio tecnico proveniente dal JSON
        safe_details = html.escape(str(control.get('details', 'No additional evidence recorded.')))

        st.markdown(
            f"""
            <div style="background-color:#101826; border:1px solid #223654; border-radius:8px; padding:15px; margin-top:10px;">
                <p style="color:#00ffaa; font-weight:bold; margin-bottom:5px;">TECHNICAL EVIDENCE:</p>
                <div style="color:#e0e0e0;">{safe_details}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        if not is_compliant:
            if "Windows" in os_choice:
                guide_title = "WINDOWS REMEDIATION GUIDE"
                rem_text = info.get("windows_remediation", info.get("remediation", ""))
            elif "Linux" in os_choice:
                guide_title = "LINUX REMEDIATION GUIDE"
                rem_text = info.get("linux_remediation", info.get("remediation", ""))
            else:
                guide_title = "MACOS REMEDIATION GUIDE"
                rem_text = info.get("macos_remediation", info.get("remediation", ""))

            safe_rem_text = html.escape(str(rem_text))

            st.markdown(
                f"""
                <div style="background:#0d1523; border:1px solid #223654; border-radius:8px; margin-top:15px; overflow:hidden;">
                    <div style="background:#101826; padding:10px 14px; border-bottom:1px solid #223654; color:#00ffaa; font-weight:700; font-size:12px; letter-spacing:1px; text-transform:uppercase;">
                        {guide_title}
                    </div>
                    <div style="padding:12px 14px; max-height:160px; overflow-y:auto; color:#d5dceb; font-size:13px; line-height:1.6; white-space:pre-wrap; font-family:monospace;">{safe_rem_text}</div>
                </div>
                """,
                unsafe_allow_html=True
            )


# --- COLLEGAMENTO NORMATIVA NIS2 (POST-CONTROLLI TECNICI) ---
# Sanitizziamo l'URL per sicurezza prima di inserirlo nell'attributo href
safe_url = html.escape(str(EURLEX_ART21_BASE))

st.markdown(
    f"""
    <div style="margin-top: 25px; padding: 15px 20px; background: #101826; border: 1px solid #223654; border-radius: 10px; display: flex; justify-content: space-between; align-items: center;">
        <div>
            <span style="font-size: 0.9rem; color: #ffffff; font-weight: bold; display: block; font-family: 'Orbitron', sans-serif;">
                📜 OFFICIAL LEGAL FRAMEWORK REFERENCE
            </span>
            <span style="font-size: 0.8rem; color: #8ea6c9;">
                All technical security controls are directly mapped to Directive (EU) 2022/2555 — Article 21.
            </span>
        </div>
        <a href="{safe_url}" target="_blank" style="font-size: 0.8rem; color: #00ffaa; text-decoration: none; font-weight: bold; background: #0b1220; padding: 8px 16px; border: 1px solid #00ffaa; border-radius: 6px; white-space: nowrap;">
            🔗 VIEW OFFICIAL EUR-LEX TEXT ↗
        </a>
    </div>
    """,
    unsafe_allow_html=True
)

# --- FOOTER DI CHIUSURA DASHBOARD ---
st.divider()

st.markdown(
    """
    <div style="text-align: center; color: #8ea6c9; padding: 20px 0px; font-size: 0.85rem;">
        <p style="margin: 0;"><b>COMPASS NIS2 Compliance Engine</b> | Enterprise Risk & Criticality Assessment Platform</p>
        <p style="margin: 5px 0 0 0; font-size: 0.75rem; color: #556b8e;">
            Aligned with EU Directive 2022/2555 (NIS2) — Article 21 Security Requirements
        </p>
    </div>
    """,
    unsafe_allow_html=True
)
