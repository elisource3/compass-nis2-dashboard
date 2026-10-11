import os
import sys
import json
import html
import socket
import platform
import subprocess
from datetime import datetime

       
        
# Nome del file JSON di output (fisso, senza data nel nome)
OUTPUT_FILENAME = "compass_nis2_report.json"


def clean_data(data):
    """
    Sanitizza ricorsivamente tutte le stringhe nel dizionario 
    per prevenire injection nel JSON.
    """
    if isinstance(data, dict):
        return {key: clean_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [clean_data(element) for element in data]
    elif isinstance(data, str):
        # Rimuove caratteri di controllo non stampabili e applica escaping HTML
        clean_str = "".join(ch for ch in data if ch.isprintable())
        return html.escape(clean_str.strip())
    return data


def save_scan_results(data, output_filepath=OUTPUT_FILENAME):
    # 1. Sanitizzazione prima del salvataggio
    sanitized_data = clean_data(data)

    # 2. Scrittura sicura su file con encoding UTF-8 esplicito
    with open(output_filepath, "w", encoding="utf-8") as f:
        json.dump(sanitized_data, f, indent=4, ensure_ascii=False)

def get_system_metadata():
    """Raccoglie informazioni di base sul sistema ospitante."""
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "scan_time": datetime.now().isoformat()
    }

def run_cmd(cmd):
    """Esegue un comando shell e restituisce l'output, gestendo eventuali errori."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception as e:
        return f"Error executing command: {str(e)}"

# --- CONTROLLI NIS2 PER WINDOWS ---
def check_windows_firewall():
    cmd = "PowerShell -Command \"Get-NetFirewallProfile | Select-Object Name, Enabled\""
    out = run_cmd(cmd)
    if "True" in out and "False" not in out:
        return "COMPLIANT", f"Tutti i profili Firewall risultano attivi.\n{out}"
    elif "True" in out:
        return "NON-COMPLIANT", f"Alcuni profili Firewall sono disattivati.\n{out}"
    else:
        return "NON-COMPLIANT", f"Firewall disattivato su tutti i profili.\n{out}"

def check_windows_bitlocker():
    cmd = "PowerShell -Command \"Get-BitLockerVolume -MountPoint 'C:' | Select-Object -ExpandProperty ProtectionStatus\""
    out = run_cmd(cmd)
    if out == "1" or "On" in out:
        return "COMPLIANT", "Cifratura BitLocker attiva sull'unità principale (C:)."
    else:
        return "NON-COMPLIANT", "BitLocker disattivato sull'unità principale (C:)."

def check_windows_uac():
    cmd = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA'
    out = run_cmd(cmd)
    if "0x1" in out:
        return "COMPLIANT", "User Account Control (UAC) abilitato correttamente."
    else:
        return "NON-COMPLIANT", "User Account Control (UAC) disabilitato."

def check_windows_updates():
    cmd = "PowerShell -Command \"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 InstalledOn\""
    out = run_cmd(cmd)
    return "COMPLIANT", f"Ultimo aggiornamento installato identificato: {out}"

def check_windows_privileges():
    cmd = "whoami /groups"
    out = run_cmd(cmd)
    if "S-1-5-32-544" in out or "Administrators" in out or "Amministratori" in out:
        return "NON-COMPLIANT", "La sessione corrente è eseguita con privilegi di Amministratore."
    return "COMPLIANT", "La sessione corrente è eseguita con un account standard privo di privilegi elevati."

def check_windows_backup():
    cmd = "PowerShell -Command \"Get-Service -Name 'wbengine' | Select-Object -ExpandProperty Status\""
    out = run_cmd(cmd)
    if "Running" in out:
        return "COMPLIANT", "Servizio Windows Backup in esecuzione."
    return "NON-COMPLIANT", "Servizio Windows Backup non in esecuzione o non configurato."

def check_windows_attack_surface():
    cmd = "netstat -ano"
    out = run_cmd(cmd)
    listening_count = out.count("LISTENING")
    if listening_count > 15:
        return "NON-COMPLIANT", f"Rilevate numerose porte in ascolto ({listening_count} servizi in ascolto)."
    return "COMPLIANT", f"Superficie di attacco contenuta ({listening_count} porte in ascolto)."

# --- CONTROLLI NIS2 PER LINUX ---
def check_linux_firewall():
    out = run_cmd("sudo ufw status || systemctl status firewalld")
    if "active" in out.lower():
        return "COMPLIANT", f"Firewall attivo.\n{out[:200]}"
    return "NON-COMPLIANT", "Firewall non attivo o non configurato."

def check_linux_encryption():
    out = run_cmd("lsblk -o NAME,FSTYPE,MOUNTPOINT")
    if "crypto_LUKS" in out:
        return "COMPLIANT", "Partizione con cifratura LUKS rilevata."
    return "NON-COMPLIANT", "Nessuna partizione cifrata con LUKS rilevata."

def check_linux_hardening():
    out = run_cmd("grep '^PermitRootLogin' /etc/ssh/sshd_config")
    if "no" in out.lower():
        return "COMPLIANT", "SSH hardening ok: PermitRootLogin è impostato su 'no'."
    return "NON-COMPLIANT", "SSH root login abilitato o non esplicitamente disabilitato."

def check_linux_updates():
    out = run_cmd("uptime")
    return "COMPLIANT", f"Uptime sistema e stato sistema: {out}"

def check_linux_privileges():
    uid = os.getuid() if hasattr(os, 'getuid') else -1
    if uid == 0:
        return "NON-COMPLIANT", "Esecuzione dello scanner avviata direttamente come utente root."
    return "COMPLIANT", f"Esecuzione avviata come utente non-root (UID: {uid})."

def check_linux_backup():
    out = run_cmd("crontab -l || systemctl list-timers")
    if "backup" in out.lower() or "duplicity" in out.lower() or "rsync" in out.lower():
        return "COMPLIANT", "Job di backup schedulato identificato."
    return "NON-COMPLIANT", "Nessun job di backup automatico evidente in cron/systemctl."

def check_linux_attack_surface():
    out = run_cmd("ss -tuln")
    lines = out.strip().split('\n')
    if len(lines) > 10:
        return "NON-COMPLIANT", f"In ascolto {len(lines)-1} porte o servizi di rete."
    return "COMPLIANT", f"Superficie di attacco ridotta: {len(lines)-1} porte in ascolto."


def run_nis2_assessment():
    os_type = platform.system()
    results = []

    # Definiamo i controlli in base all'OS
    if os_type == "Windows":
        checks = [
            ("NIS2-Art21-2g-01", "Igiene Informatica (Firewall)", "Art. 21.2(g)", check_windows_firewall),
            ("NIS2-Art21-2h-01", "Crittografia (Cifratura Dati)", "Art. 21.2(h)", check_windows_bitlocker),
            ("NIS2-SB-01", "Hardening & Security Baseline", "Art. 21.2(e)", check_windows_uac),
            ("NIS2-Art21-2e-01", "Patch Management", "Art. 21.2(e)", check_windows_updates),
            ("NIS2-Art21-2i-01", "Controllo Accessi & Privilegi", "Art. 21.2(i)", check_windows_privileges),
            ("NIS2-Art21-2c-01", "Continuità Operativa & Backup", "Art. 21.2(c)", check_windows_backup),
            ("NIS2-Art21-2d-01", "Riduzione Superficie di Attacco", "Art. 21.2(d)", check_windows_attack_surface),
        ]
    else:  # Linux / Unix fallback
        checks = [
            ("NIS2-Art21-2g-01", "Igiene Informatica (Firewall)", "Art. 21.2(g)", check_linux_firewall),
            ("NIS2-Art21-2h-01", "Crittografia (Cifratura Dati)", "Art. 21.2(h)", check_linux_encryption),
            ("NIS2-SB-01", "Hardening & Security Baseline", "Art. 21.2(e)", check_linux_hardening),
            ("NIS2-Art21-2e-01", "Patch Management", "Art. 21.2(e)", check_linux_updates),
            ("NIS2-Art21-2i-01", "Controllo Accessi & Privilegi", "Art. 21.2(i)", check_linux_privileges),
            ("NIS2-Art21-2c-01", "Continuità Operativa & Backup", "Art. 21.2(c)", check_linux_backup),
            ("NIS2-Art21-2d-01", "Riduzione Superficie di Attacco", "Art. 21.2(d)", check_linux_attack_surface),
        ]

    for ctrl_id, category, req_ref, func in checks:
        print(f"[*] Verifico {ctrl_id} ({category})...")
        status, details = func()
        results.append({
            "nis2_control_id": ctrl_id,
            "category": category,
            "requirement_reference": req_ref,
            "status": status,
            "details": details
        })

    return results

def main():
    print("===========================================")
    print(" COMPASS — NIS2 Endpoint Security Scanner")
    print("===========================================\n")

    metadata = get_system_metadata()
    print(f"[+] Host: {metadata['hostname']} ({metadata['os']} {metadata['os_release']})")
    print("[+] Inizio scansione controlli NIS2...\n")

    compliance_results = run_nis2_assessment()

    report_payload = {
        "scanner_metadata": metadata,
        "nis2_compliance_results": compliance_results
    }

    # Salvataggio nel file con nome fisso SENZA DATA
    save_scan_results(report_payload, OUTPUT_FILENAME)

    print("\n===========================================")
    print(f"[✔] Scansione completata con successo!")
    print(f"[✔] Report salvato in: {os.path.abspath(OUTPUT_FILENAME)}")
    print("===========================================")

if __name__ == "__main__":
    main()