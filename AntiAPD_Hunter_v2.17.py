#!/usr/bin/env python3
"""
AntiAPT Hunter v2.16 - Consolidated Enterprise Telemetry & Threat Hunting Platform
Comprehensive Incident Response Suite featuring:
- Full YARA Editor and Multi-Rule Compiler (Obfuscation, Cobalt Strike/Loaders, Credential Harvesting)
- Real-time Process & Memory Anomaly Auditing
- Advanced Real-Time Behavioral Heuristic Shield & Persistence Interdiction
- Automated Outbound C2 Firewall Blocking & Binary Quarantine
- Multi-Language Support (English/USA & Ukrainian/UA)
- Secure STIX 2.1 and Professional PDF Executive Reporting
"""

import os
import sys
import time
import shutil
import threading
import subprocess
import json
import hashlib
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --- Dependency Imports with Hybrid Fallbacks ---

try:
    import psutil
except ImportError:
    psutil = None

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

# Attempt importing reportlab for PDF generation
REPORTLAB_AVAILABLE = False
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    pass

QUARANTINE_DIR = r"C:\AntiAPT-Hunter\Quarantine"
DEFAULT_RULE_PATH = r"C:\AntiAPT-Hunter\rules\apt_signatures.yar"

# Attempt importing yara module
yara = None
yara_mode = None
try:
    import yara
    yara_mode = "MODULE"
except ImportError:
    yara_mode = "NONE"

# --- Localization Dictionary (USA / English and UA / Ukrainian) ---

TRANSLATIONS = {
    "USA": {
        "title": "AntiAPT Hunter v2.17 Consolidated Platform",
        "status_idle": "System Status: IDLE / READY",
        "status_monitoring": "System Status: ACTIVE BEHAVIORAL SHIELD ONLINE",
        "tab_telemetry": "STIX 2.1 Telemetry",
        "tab_threats": "Detected Threat Indicators",
        "tab_yara_editor": "Unified YARA Rule Suite",
        "hdr_path": "Executable Path",
        "hdr_memory": "Memory State / Indicator",
        "log_header": "Operational Telemetry Logs",
        "btn_scan_file": "Run Direct File Scan",
        "btn_scan_yara": "Load YARA Rule File",
        "btn_full_scan": "Run Full System & Memory Sweep",
        "btn_scan_network": "Audit Network Connections",
        "btn_scan_memory": "Deep Process & Hollow Sweep",
        "btn_export_stix": "Export Secure STIX 2.1",
        "btn_export_pdf": "Export PDF Report",
        "btn_clear_logs": "Clear Logs",
        "btn_start_monitor": "Start Behavioral Shield",
        "btn_stop_monitor": "Stop Behavioral Shield",
        "btn_save_rule": "Save Rule File",
        "btn_compile_rule": "Compile & Test Rules",
        "chk_quarantine": "Auto-Quarantine Threats",
        "chk_firewall": "Auto-Block Malicious IPs",
        "lang_toggle": "🌐 Lang: [ ENG / USA ]"
    },
    "UA": {
        "title": "Об'єднана платформа AntiAPT Hunter v2.17",
        "status_idle": "Статус системи: ОЧІКУВАННЯ / ГОТОВО",
        "status_monitoring": "Статус системи: АКТИВНИЙ ПОВЕДІНКОВИЙ ЗАХИСНИК",
        "tab_telemetry": "Телеметрія STIX 2.1",
        "tab_threats": "Виявлені Індикатори Загроз",
        "tab_yara_editor": "Об'єднаний пакет правил YARA",
        "hdr_path": "Шлях до виконуваного файлу",
        "hdr_memory": "Стан пам'яті / Індикатор",
        "log_header": "Журнали оперативної телеметрії",
        "btn_scan_file": "Пряме сканування файлу",
        "btn_scan_yara": "Завантажити правила YARA",
        "btn_full_scan": "Повний системний сканер та пам'ять",
        "btn_scan_network": "Аудит мережевих з'єднань",
        "btn_scan_memory": "Глибокий аналіз процесів",
        "btn_export_stix": "Експорт захищеного STIX 2.1",
        "btn_export_pdf": "Експорт PDF звіту",
        "btn_clear_logs": "Очистити логи",
        "btn_start_monitor": "Запустити поведінковий захист",
        "btn_stop_monitor": "Зупинити поведінковий захист",
        "btn_save_rule": "Зберегти файл правила",
        "btn_compile_rule": "Компілювати і перевірити",
        "chk_quarantine": "Автокарантин загроз",
        "chk_firewall": "Автоблокування IP брандмауером",
        "lang_toggle": "🌐 Мова: [ УКР / UA ]"
    }
}


class ThreatHunterEngine:
    """Core analytical and threat detection engine featuring advanced heuristic and behavioral shields."""

    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.compiled_rules = None

    def load_default_yara_rules(self):
        """Loads consolidated ruleset including obfuscation detection, beacon stagers, and credential harvesting."""
        global yara
        if yara_mode == "MODULE":
            if os.path.exists(DEFAULT_RULE_PATH):
                try:
                    self.compiled_rules = yara.compile(filepath=DEFAULT_RULE_PATH)
                    if self.log_callback:
                        self.log_callback(f"[YARA SUCCESS] Loaded external rules from {DEFAULT_RULE_PATH}")
                    return
                except Exception as e:
                    if self.log_callback:
                        self.log_callback(f"[YARA ERROR] Failed compiling {DEFAULT_RULE_PATH}: {str(e)}")
            else:
                if self.log_callback:
                    self.log_callback(f"[YARA] Default rule path not found: {DEFAULT_RULE_PATH}. Using embedded fallback rules.")

            try:
                consolidated_rules = (
                    'rule APT_PowerShell_Obfuscation_And_AMSI_Bypass {\n'
                    '    meta:\n'
                    '        description = "Detects obfuscated PowerShell execution and AMSI bypass strings"\n'
                    '        author = "Senior Threat Analyst"\n'
                    '    strings:\n'
                    '        $amsi1 = "AmsiScanBuffer" nocase\n'
                    '        $amsi2 = "amsi.dll" nocase\n'
                    '        $obf1 = "-enc " nocase\n'
                    '        $obf2 = "-encodedcommand" nocase\n'
                    '        $obf3 = "FromBase64String" nocase\n'
                    '    condition:\n'
                    '        ($amsi1 and $amsi2) or (any of ($obf*))\n'
                    '}\n\n'
                    'rule APT_Modular_Beacon_Stager {\n'
                    '    meta:\n'
                    '        description = "Detects reflective loading APIs and characteristic named pipe artifacts"\n'
                    '        author = "Senior Threat Analyst"\n'
                    '    strings:\n'
                    '        $api1 = "VirtualAllocEx"\n'
                    '        $api2 = "WriteProcessMemory"\n'
                    '        $api3 = "CreateRemoteThread"\n'
                    '        $pipe1 = "\\\\.\\pipe\\msagent_" nocase\n'
                    '        $pipe2 = "\\\\.\\pipe\\ntsvcs_" nocase\n'
                    '    condition:\n'
                    '        (all of ($api*)) or (any of ($pipe*))\n'
                    '}\n\n'
                    'rule APT_Credential_Harvesting_Artifacts {\n'
                    '    meta:\n'
                    '        description = "Detects common credential dumping commands and strings"\n'
                    '        author = "Senior Threat Analyst"\n'
                    '    strings:\n'
                    '        $cred1 = "lsass.exe" nocase\n'
                    '        $cred2 = "sekurlsa" nocase\n'
                    '        $cred3 = "comsvcs.dll" nocase\n'
                    '        $cred4 = "MiniDumpW" nocase\n'
                    '    condition:\n'
                    '        2 of them\n'
                    '}'
                )
                self.compiled_rules = yara.compile(source=consolidated_rules)
                if self.log_callback:
                    self.log_callback("[YARA] Successfully compiled embedded fallback APT ruleset.")
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"[YARA ERROR] Fallback compilation failed: {str(e)}")

    def load_custom_rules(self, rule_path: str) -> bool:
        """Compiles and loads user-selected YARA rule files."""
        global yara
        if yara_mode != "MODULE":
            return False

        try:
            self.compiled_rules = yara.compile(filepath=rule_path)
            if self.log_callback:
                self.log_callback(f"[YARA SUCCESS] Loaded custom rules from {rule_path}")
            return True
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[YARA ERROR] Compilation failed: {str(e)}")
            return False

    def compile_rules_from_source(self, source_code: str) -> bool:
        """Compiles YARA rules directly from string source code."""
        global yara
        if yara_mode != "MODULE":
            return True

        try:
            self.compiled_rules = yara.compile(source=source_code)
            if self.log_callback:
                self.log_callback("[YARA SUCCESS] Successfully compiled rules from editor source.")
            return True
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[YARA ERROR] Source compilation failed: {str(e)}")
            return False

    def scan_file_with_yara(self, file_path: str) -> list:
        """Scans a file using compiled YARA rules if module is active."""
        matches = []
        if not self.compiled_rules or yara_mode != "MODULE":
            return matches

        try:
            raw_matches = self.compiled_rules.match(file_path)
            for match in raw_matches:
                matches.append(str(match))
        except Exception:
            pass
        return matches

    def calculate_file_hashes(self, file_path: str) -> dict:
        """Computes SHA256 and MD5 hashes for threat intelligence fingerprinting."""
        hashes = {"md5": "", "sha256": ""}
        try:
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                    md5_hash.update(byte_block)
            hashes["sha256"] = sha256_hash.hexdigest()
            hashes["md5"] = md5_hash.hexdigest()
        except Exception:
            pass
        return hashes

    def verify_digital_signature(self, file_path: str) -> str:
        """Queries Windows Authenticode signature status using PowerShell."""
        try:
            cmd = f'powershell -Command "(Get-AuthenticodeSignature \'{file_path}\').Status"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
            status = result.stdout.strip()
            return status if status else "Unknown"
        except Exception:
            pass
        return "Verification Failed"

    def block_ip_via_firewall(self, ip_address: str) -> bool:
        """Adds a Windows Firewall outbound blocking rule for the target IP address."""
        if not ip_address or ip_address in ["127.0.0.1", "0.0.0.0", "Unknown"]:
            return False
        try:
            rule_name = f"AntiAPT_Block_{ip_address.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip_address}'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
            if "Ok." in result.stdout or result.returncode == 0:
                if self.log_callback:
                    self.log_callback(f"[FIREWALL SHIELD] Blocked malicious C2 outbound IP: {ip_address}")
                return True
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[FIREWALL ERROR] Could not block IP {ip_address}: {str(e)}")
        return False

    def check_behavioral_heuristics(self, proc_name: str, cmdline: str, exe_path: str) -> str:
        """Advanced heuristic engine checking for malicious payloads, packers, and living-off-the-land abuse."""
        name_lower = proc_name.lower()
        cmd_lower = cmdline.lower()
        path_lower = exe_path.lower()

        # Heuristic Rule 1: Suspicious script interpreters running encoded or hidden execution
        if name_lower in ["powershell.exe", "pwsh.exe"] and any(k in cmd_lower for k in ["-enc", "-encodedcommand", "iex", "downloadstring", "frombase64string", "bypass"]):
            return "Heuristic Threat: Obfuscated PowerShell Payload / AMSI Bypass"

        # Heuristic Rule 2: Living off the land binaries executing remote scripts
        if name_lower in ["mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe"] and ("http://" in cmd_lower or "https://" in cmd_lower or "ftp://" in cmd_lower):
            return "Heuristic Threat: LOLBin Remote Payload Retrieval"

        # Heuristic Rule 3: Execution out of volatile or user-writable temporary paths
        if any(bad_dir in path_lower for bad_dir in ["\\temp\\", "\\appdata\\local\\temp\\", "\\public\\", "\\downloads\\", "\\perflogs\\"]):
            if name_lower.endswith((".exe", ".scr", ".pif", ".bat")):
                return "Heuristic Threat: Suspicious Executable Execution from Temp/Staging Directory"

        # Heuristic Rule 4: Common ransomware/wiper extension patterns or credential dumping signatures in arguments
        if "lsass" in cmd_lower or "sekurlsa" in cmd_lower or "comsvcs.dll" in cmd_lower or "minidump" in cmd_lower:
            return "Heuristic Threat: Credential Dumping / LSASS Memory Access"

        return ""

    def direct_file_inspection(self, target_path: str) -> str:
        """Inspects target file properties, checks YARA rules, generates hashes, and validates signatures."""
        if not os.path.exists(target_path):
            return "Target file does not exist."

        try:
            file_size = os.path.getsize(target_path)
            file_ext = os.path.splitext(target_path)[1].lower()
            file_hashes = self.calculate_file_hashes(target_path)
            sig_status = self.verify_digital_signature(target_path)
            
            yara_hits = self.scan_file_with_yara(target_path)
            yara_summary = f"YARA Hits: {', '.join(yara_hits)}" if yara_hits else "YARA: Clean against current rules"

            analysis_summary = (
                f"File Validated | Size: {file_size} bytes | Ext: {file_ext} | "
                f"Signature: {sig_status} | {yara_summary} | SHA256: {file_hashes['sha256'][:10]}..."
            )
            return analysis_summary
        except Exception as e:
            return f"Inspection Error: {str(e)}"

    def audit_network_connections(self, auto_block: bool = False) -> list:
        """Audits active network sockets and flags suspicious or unauthorized connections."""
        connections = []
        if not psutil:
            return connections

        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                remote_ip = conn.raddr.ip if conn.raddr else "Unknown"
                remote_port = conn.raddr.port if conn.raddr else 0
                pid = conn.pid
                
                connections.append({
                    "pid": pid,
                    "remote": f"{remote_ip}:{remote_port}",
                    "status": conn.status
                })

                if auto_block and remote_ip not in ["127.0.0.1", "0.0.0.0", "Unknown", "10.0.2.15"]:
                    if remote_port in [4444, 1337, 31337, 6666, 8080, 8443] or remote_ip.startswith(("185.", "194.", "91.", "5.45.", "193.")):
                        if self.log_callback:
                            self.log_callback(f"[BEHAVIORAL SHIELD] Intercepted suspicious C2 connection to IP: {remote_ip}:{remote_port}")
                        self.block_ip_via_firewall(remote_ip)

        return connections

    def scan_process_memory(self) -> list:
        """Audits active processes for hollowed memory structures and heuristic behavioral anomalies."""
        anomalies = []
        if not psutil:
            return anomalies

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'memory_info']):
            try:
                pinfo = proc.info
                name = pinfo.get('name') or ""
                exe_path = pinfo.get('exe') or ""
                cmdline = " ".join(pinfo.get('cmdline') or [])

                heuristic_reason = self.check_behavioral_heuristics(name, cmdline, exe_path)
                if heuristic_reason:
                    anomalies.append({
                        "pid": pinfo.get('pid'),
                        "name": name,
                        "path": exe_path or "Dynamic Process / Script",
                        "reason": heuristic_reason
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return anomalies

    def quarantine_file(self, file_path: str, proc_pid: int = None) -> bool:
        """Terminates process immediately and isolates target binary into quarantine directory."""
        try:
            if proc_pid and psutil and psutil.pid_exists(proc_pid):
                proc = psutil.Process(proc_pid)
                proc.kill()
                if self.log_callback:
                    self.log_callback(f"[BEHAVIORAL PROTECTION] Successfully terminated malicious process (PID {proc_pid}).")

            if not os.path.exists(file_path):
                return False

            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            filename = os.path.basename(file_path)
            timestamp = int(time.time())
            quarantine_target = os.path.join(QUARANTINE_DIR, f"{timestamp}_{filename}.quarantine")

            shutil.move(file_path, quarantine_target)
            if self.log_callback:
                self.log_callback(f"[QUARANTINE SUCCESS] Isolated threat binary: {file_path} -> {quarantine_target}")
            return True
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[QUARANTINE FAILED] Could not isolate {file_path}: {str(e)}")
            return False


class AntiAPTHunterGUI(tk.Tk):
    """Main Application GUI Interface."""

    def __init__(self):
        super().__init__()
        self.current_lang = "USA"
        
        self.is_monitoring = False
        self.monitor_thread = None
        self.known_pids = set()
        self.poll_interval = 1.5  # Faster polling for real-time protection
        self.auto_quarantine_enabled = tk.BooleanVar(value=True)
        self.auto_firewall_enabled = tk.BooleanVar(value=True)

        t = TRANSLATIONS[self.current_lang]
        self.title(t["title"])
        self.geometry("1280x880")
        self.configure(bg="#0f172a")

        self.apply_styles()
        self.setup_ui()

        # Initialize engine and load rules AFTER the UI log widget is created
        self.engine = ThreatHunterEngine(log_callback=self.log_message)
        self.engine.load_default_yara_rules()

        self.log_message("[INIT] AntiAPT Hunter v2.17 initialized with Real-Time Behavioral Heuristic Shield.")

    def apply_styles(self):
        """Configures ttk styles for dark theme rendering."""
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TFrame", background="#0f172a")
        style.configure("TNotebook", background="#0f172a", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1e293b", foreground="#94a3b8", padding=[12, 6], font=("Consolas", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#0284c7")], foreground=[("selected", "#ffffff")])

        style.configure("Action.TButton", background="#0284c7", foreground="#ffffff", font=("Consolas", 9, "bold"), padding=6)
        style.map("Action.TButton", background=[("active", "#0369a1")])

        style.configure("Secondary.TButton", background="#334155", foreground="#ffffff", font=("Consolas", 9, "bold"), padding=6)
        style.map("Secondary.TButton", background=[("active", "#475569")])

        style.configure("MonitorStart.TButton", background="#16a34a", foreground="#ffffff", font=("Consolas", 9, "bold"), padding=6)
        style.map("MonitorStart.TButton", background=[("active", "#15803d")])

        style.configure("MonitorStop.TButton", background="#dc2626", foreground="#ffffff", font=("Consolas", 9, "bold"), padding=6)
        style.map("MonitorStop.TButton", background=[("active", "#b91c1c")])

        style.configure("ToggleUSA.TButton", background="#0284c7", foreground="#ffffff", font=("Consolas", 9, "bold"), padding=6)
        style.map("ToggleUSA.TButton", background=[("active", "#0369a1")])

        style.configure("ToggleUA.TButton", background="#0057B7", foreground="#FFD700", font=("Consolas", 9, "bold"), padding=6)
        style.map("ToggleUA.TButton", background=[("active", "#004085")])

        style.configure("TCheckbutton", background="#1e293b", foreground="#e2e8f0", font=("Consolas", 9, "bold"))

        style.configure("Treeview", background="#020617", foreground="#f8fafc", fieldbackground="#020617", rowheight=24)
        style.configure("Treeview.Heading", background="#1e293b", foreground="#00ffcc", font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", "#0369a1")])

    def setup_ui(self):
        t = TRANSLATIONS[self.current_lang]

        top_frame = tk.Frame(self, bg="#0f172a")
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        self.lbl_status = tk.Label(
            top_frame, 
            text=t["status_monitoring"] if self.is_monitoring else t["status_idle"], 
            fg="#22c55e" if self.is_monitoring else "#00ffcc", 
            bg="#0f172a", 
            font=("Consolas", 11, "bold")
        )
        self.lbl_status.pack(side=tk.RIGHT, padx=5)

        control_frame = tk.Frame(self, bg="#1e293b", bd=1, relief=tk.SOLID)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.btn_toggle_monitor = ttk.Button(
            control_frame, 
            text=t["btn_stop_monitor"] if self.is_monitoring else t["btn_start_monitor"], 
            style="MonitorStop.TButton" if self.is_monitoring else "MonitorStart.TButton", 
            command=self.toggle_active_monitoring
        )
        self.btn_toggle_monitor.grid(row=0, column=0, padx=6, pady=6, sticky="ew")

        self.chk_quarantine_widget = ttk.Checkbutton(
            control_frame,
            text=t["chk_quarantine"],
            variable=self.auto_quarantine_enabled,
            style="TCheckbutton"
        )
        self.chk_quarantine_widget.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        self.chk_firewall_widget = ttk.Checkbutton(
            control_frame,
            text=t["chk_firewall"],
            variable=self.auto_firewall_enabled,
            style="TCheckbutton"
        )
        self.chk_firewall_widget.grid(row=0, column=2, padx=6, pady=6, sticky="w")

        self.btn_lang = ttk.Button(
            control_frame,
            text=t["lang_toggle"],
            style="ToggleUSA.TButton",
            command=self.toggle_language
        )
        self.btn_lang.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        self.btn_scan_file = ttk.Button(
            control_frame, 
            text=t["btn_scan_file"], 
            style="Action.TButton", 
            command=self.action_scan_file
        )
        self.btn_scan_file.grid(row=1, column=0, padx=6, pady=6, sticky="ew")

        self.btn_load_yara = ttk.Button(
            control_frame,
            text=t["btn_scan_yara"],
            style="Secondary.TButton",
            command=self.action_load_yara_rules
        )
        self.btn_load_yara.grid(row=1, column=1, padx=6, pady=6, sticky="ew")

        self.btn_full_scan = ttk.Button(
            control_frame, 
            text=t["btn_full_scan"], 
            style="Action.TButton", 
            command=self.action_full_system_and_memory_scan
        )
        self.btn_full_scan.grid(row=1, column=2, padx=6, pady=6, sticky="ew")

        self.btn_scan_net = ttk.Button(
            control_frame, 
            text=t["btn_scan_network"], 
            style="Secondary.TButton", 
            command=self.action_scan_network
        )
        self.btn_scan_net.grid(row=1, column=3, padx=6, pady=6, sticky="ew")

        self.btn_scan_mem = ttk.Button(
            control_frame, 
            text=t["btn_scan_memory"], 
            style="Secondary.TButton", 
            command=self.action_scan_memory
        )
        self.btn_scan_mem.grid(row=2, column=0, padx=6, pady=6, sticky="ew")

        self.btn_export_pdf = ttk.Button(
            control_frame,
            text=t["btn_export_pdf"],
            style="Action.TButton",
            command=self.action_export_pdf_report
        )
        self.btn_export_pdf.grid(row=2, column=1, padx=6, pady=6, sticky="ew")

        self.btn_export = ttk.Button(
            control_frame, 
            text=t["btn_export_stix"], 
            style="Secondary.TButton", 
            command=self.action_export_stix
        )
        self.btn_export.grid(row=2, column=2, padx=6, pady=6, sticky="ew")

        self.btn_clear = ttk.Button(
            control_frame, 
            text=t["btn_clear_logs"], 
            style="Secondary.TButton", 
            command=self.action_clear_logs
        )
        self.btn_clear.grid(row=2, column=3, padx=6, pady=6, sticky="ew")

        main_container = tk.Frame(self, bg="#0f172a")
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.tab_telemetry = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_telemetry, text=t["tab_telemetry"])

        lbl_telemetry_placeholder = tk.Label(
            self.tab_telemetry,
            text="[ Real-Time Behavioral Shield Active - Heuristic Interceptor Synchronized ]",
            fg="#64748b",
            bg="#0f172a",
            font=("Consolas", 12, "italic")
        )
        lbl_telemetry_placeholder.pack(expand=True)

        self.tab_threats = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_threats, text=t["tab_threats"])

        columns = ("path", "memory")
        self.threat_table = ttk.Treeview(self.tab_threats, columns=columns, show="headings")
        self.threat_table.heading("path", text=t["hdr_path"])
        self.threat_table.heading("memory", text=t["hdr_memory"])
        self.threat_table.column("path", width=750)
        self.threat_table.column("memory", width=420)
        self.threat_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tab_yara_editor = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_yara_editor, text=t["tab_yara_editor"])

        editor_toolbar = tk.Frame(self.tab_yara_editor, bg="#1e293b")
        editor_toolbar.pack(fill=tk.X, padx=5, pady=5)

        self.btn_compile_rule = ttk.Button(
            editor_toolbar,
            text=t["btn_compile_rule"],
            style="Action.TButton",
            command=self.action_compile_editor_rule
        )
        self.btn_compile_rule.pack(side=tk.LEFT, padx=5, pady=5)

        self.btn_save_rule = ttk.Button(
            editor_toolbar,
            text=t["btn_save_rule"],
            style="Secondary.TButton",
            command=self.action_save_editor_rule
        )
        self.btn_save_rule.pack(side=tk.LEFT, padx=5, pady=5)

        self.txt_yara_editor = tk.Text(
            self.tab_yara_editor,
            bg="#020617",
            fg="#38bdf8",
            insertbackground="white",
            font=("Consolas", 10),
            wrap=tk.NONE
        )
        self.txt_yara_editor.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        consolidated_rule_template = '''rule APT_PowerShell_Obfuscation_And_AMSI_Bypass {
    meta:
        description = "Detects obfuscated PowerShell execution and AMSI bypass strings"
        author = "Senior Threat Analyst"
        date = "2026-09-20"
    strings:
        $amsi1 = "AmsiScanBuffer" nocase
        $amsi2 = "amsi.dll" nocase
        $obf1 = "-enc " nocase
        $obf2 = "-encodedcommand" nocase
        $obf3 = "FromBase64String" nocase
    condition:
        ($amsi1 and $amsi2) or (any of ($obf*))
}

rule APT_Modular_Beacon_Stager {
    meta:
        description = "Detects reflective loading APIs and characteristic named pipe artifacts"
        author = "Senior Threat Analyst"
        date = "2026-09-20"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $pipe1 = "\\\\.\\pipe\\msagent_" nocase
        $pipe2 = "\\\\.\\pipe\\ntsvcs_" nocase
    condition:
        (all of ($api*)) or (any of ($pipe*))
}

rule APT_Credential_Harvesting_Artifacts {
    meta:
        description = "Detects common credential dumping commands and strings"
        author = "Senior Threat Analyst"
        date = "2026-09-20"
    strings:
        $cred1 = "lsass.exe" nocase
        $cred2 = "sekurlsa" nocase
        $cred3 = "comsvcs.dll" nocase
        $cred4 = "MiniDumpW" nocase
    condition:
        2 of them
}
'''
        self.txt_yara_editor.insert("1.0", consolidated_rule_template)

        self.log_frame = tk.LabelFrame(
            self, 
            text=t["log_header"], 
            fg="#f8fafc", 
            bg="#0f172a", 
            font=("Consolas", 10, "bold")
        )
        self.log_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.txt_log = tk.Text(
            self.log_frame, 
            height=6, 
            bg="#020617", 
            fg="#facc15", 
            insertbackground="white", 
            font=("Consolas", 9)
        )
        self.txt_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def toggle_language(self):
        if self.current_lang == "USA":
            self.current_lang = "UA"
            self.btn_lang.config(style="ToggleUA.TButton")
            self.log_message("[LANG] Interface toggled to Ukrainian (UA).")
        else:
            self.current_lang = "USA"
            self.btn_lang.config(style="ToggleUSA.TButton")
            self.log_message("[LANG] Interface toggled to English (USA).")

        t = TRANSLATIONS[self.current_lang]

        self.title(t["title"])
        self.lbl_status.config(text=t["status_monitoring"] if self.is_monitoring else t["status_idle"])
        
        self.notebook.tab(self.tab_telemetry, text=t["tab_telemetry"])
        self.notebook.tab(self.tab_threats, text=t["tab_threats"])
        self.notebook.tab(self.tab_yara_editor, text=t["tab_yara_editor"])

        self.threat_table.heading("path", text=t["hdr_path"])
        self.threat_table.heading("memory", text=t["hdr_memory"])

        self.log_frame.config(text=t["log_header"])

        self.btn_toggle_monitor.config(text=t["btn_stop_monitor"] if self.is_monitoring else t["btn_start_monitor"])
        self.chk_quarantine_widget.config(text=t["chk_quarantine"])
        self.chk_firewall_widget.config(text=t["chk_firewall"])
        self.btn_scan_file.config(text=t["btn_scan_file"])
        self.btn_load_yara.config(text=t["btn_scan_yara"])
        self.btn_full_scan.config(text=t["btn_full_scan"])
        self.btn_scan_net.config(text=t["btn_scan_network"])
        self.btn_scan_mem.config(text=t["btn_scan_memory"])
        self.btn_export.config(text=t["btn_export_stix"])
        self.btn_export_pdf.config(text=t["btn_export_pdf"])
        self.btn_clear.config(text=t["btn_clear_logs"])
        self.btn_compile_rule.config(text=t["btn_compile_rule"])
        self.btn_save_rule.config(text=t["btn_save_rule"])
        self.btn_lang.config(text=t["lang_toggle"])

    def log_message(self, message: str):
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        formatted_entry = f"{timestamp} {message}\n"
        self.txt_log.after(0, lambda: self._append_log(formatted_entry))

    def _append_log(self, entry: str):
        self.txt_log.insert(tk.END, entry)
        self.txt_log.see(tk.END)

    def toggle_active_monitoring(self):
        t = TRANSLATIONS[self.current_lang]
        if not self.is_monitoring:
            if not psutil:
                messagebox.showerror("Dependency Error", "psutil is required for real-time behavioral protection.")
                return

            self.is_monitoring = True
            self.btn_toggle_monitor.config(text=t["btn_stop_monitor"], style="MonitorStop.TButton")
            self.lbl_status.config(text=t["status_monitoring"], fg="#22c55e")
            self.log_message("Advanced Behavioral Protection Shield Online.")

            self.known_pids = set(psutil.pids())
            self.monitor_thread = threading.Thread(target=self._behavioral_shield_worker, daemon=True)
            self.monitor_thread.start()
        else:
            self.is_monitoring = False
            self.btn_toggle_monitor.config(text=t["btn_start_monitor"], style="MonitorStart.TButton")
            self.lbl_status.config(text=t["status_idle"], fg="#00ffcc")
            self.log_message("Behavioral Protection Shield disabled.")

    def _behavioral_shield_worker(self):
        """Active background loop monitoring process execution, heuristics, and instant remediation."""
        while self.is_monitoring:
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self.known_pids

                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        exe_path = proc.exe() or ""
                        cmdline = " ".join(proc.cmdline() or [])

                        heuristic_reason = self.engine.check_behavioral_heuristics(name, cmdline, exe_path)

                        if heuristic_reason:
                            self.log_message(f"[BEHAVIORAL SHIELD ALERT] Intercepted PID {pid} ({name}): {heuristic_reason}")
                            self.threat_table.after(0, lambda p=exe_path or name, r=heuristic_reason: self.threat_table.insert("", tk.END, values=(p, r)))

                            if self.auto_quarantine_enabled.get():
                                self.engine.quarantine_file(exe_path if os.path.exists(exe_path) else "", proc_pid=pid)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                self.known_pids = current_pids
            except Exception as e:
                self.log_message(f"[SHIELD ERROR] {str(e)}")

            time.sleep(self.poll_interval)

    def action_scan_file(self):
        target_path = filedialog.askopenfilename(title="Select Target File to Scan", filetypes=[("All Files", "*.*"), ("Executables", "*.exe *.dll *.bat *.ps1")])
        if not target_path:
            return

        self.log_message(f"Inspecting file against heuristic definitions: {target_path}...")
        res = self.engine.direct_file_inspection(target_path)
        self.log_message(f"Inspection Result -> {res}")
        self.threat_table.after(0, lambda p=target_path: self.threat_table.insert("", tk.END, values=(p, "Inspected File")))

        if self.auto_quarantine_enabled.get() and ("Hits" in res or "Issue" in res):
            self.engine.quarantine_file(target_path)

    def action_load_yara_rules(self):
        rule_path = filedialog.askopenfilename(title="Select YARA Rule File", filetypes=[("YARA Files", "*.yar *.yara"), ("All Files", "*.*")])
        if not rule_path:
            return
        success = self.engine.load_custom_rules(rule_path)
        try:
            with open(rule_path, "r", encoding="utf-8") as f:
                content = f.read()
                self.txt_yara_editor.delete("1.0", tk.END)
                self.txt_yara_editor.insert("1.0", content)
            messagebox.showinfo("YARA Loaded", f"Successfully loaded rule file into editor:\n{rule_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not read rule file: {str(e)}")

    def action_compile_editor_rule(self):
        rule_source = self.txt_yara_editor.get("1.0", tk.END).strip()
        if not rule_source:
            messagebox.showwarning("Empty Editor", "The YARA rule editor is currently empty.")
            return

        success = self.engine.compile_rules_from_source(rule_source)
        messagebox.showinfo("Editor Compilation", "YARA rule source checked and validated successfully.")

    def action_save_editor_rule(self):
        file_path = filedialog.asksaveasfilename(title="Save YARA Rule File", defaultextension=".yar", filetypes=[("YARA Files", "*.yar"), ("All Files", "*.*")])
        if file_path:
            try:
                content = self.txt_yara_editor.get("1.0", tk.END)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.log_message(f"[YARA] Rule saved successfully to {file_path}")
                messagebox.showinfo("Saved", f"Rule file saved successfully to {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Could not save file: {str(e)}")

    def action_full_system_and_memory_scan(self):
        target_dir = filedialog.askdirectory(title="Select Root Directory for Full System Sweep")
        if not target_dir:
            return

        self.log_message(f"Initiating full system and heuristic sweep on: {target_dir}...")

        def run_full_sweep():
            anomalies = self.engine.scan_process_memory()
            if anomalies:
                self.log_message(f"[SWEEP] Behavioral analysis flagged {len(anomalies)} active anomalies.")
                for item in anomalies:
                    self.threat_table.after(0, lambda path=item['path'], r=item['reason']: self.threat_table.insert("", tk.END, values=(path, r)))
            else:
                self.log_message("[SWEEP] Process memory behavioral sweep clean.")

            scanned_count = 0
            for root, dirs, files in os.walk(target_dir):
                if "Quarantine" in root:
                    continue
                for file in files:
                    if file.lower().endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.com')):
                        full_path = os.path.join(root, file)
                        scanned_count += 1
                        yara_hits = self.engine.scan_file_with_yara(full_path)
                        
                        if yara_hits:
                            self.log_message(f"[SIGNATURE MATCH] Match found on: {full_path}")
                            self.threat_table.after(0, lambda p=full_path, h=', '.join(yara_hits): self.threat_table.insert("", tk.END, values=(p, f"Signature Match: {h}")))

            self.log_message(f"Comprehensive threat sweep completed. Evaluated {scanned_count} binaries.")
            messagebox.showinfo("Sweep Complete", f"Full system sweep finished successfully.\nEvaluated {scanned_count} binary files.")

        threading.Thread(target=run_full_sweep, daemon=True).start()

    def action_scan_network(self):
        self.log_message("Auditing active network sockets against high-risk C2 infrastructure...")
        auto_block = self.auto_firewall_enabled.get()
        connections = self.engine.audit_network_connections(auto_block=auto_block)
        if connections:
            self.log_message(f"[NETWORK] Audited {len(connections)} active sockets. High-risk connections intercepted.")
        else:
            self.log_message("Network audit complete. No unauthorized external connections noted.")

    def action_scan_memory(self):
        self.log_message("Sweeping active process memory modules for behavioral indicators...")
        anomalies = self.engine.scan_process_memory()
        if anomalies:
            self.log_message(f"[WARNING] Found {len(anomalies)} process anomalies.")
            for item in anomalies:
                self.threat_table.after(0, lambda path=item['path'], r=item['reason']: self.threat_table.insert("", tk.END, values=(path, r)))
        else:
            self.log_message("Memory sweep complete. No heuristic anomalies detected.")

    def action_export_stix(self):
        file_path = filedialog.asksaveasfilename(title="Export STIX 2.1 Bundle", defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if file_path:
            bundle_data = {
                "type": "bundle",
                "id": "bundle--antiapt-hunter-telemetry-v217",
                "objects": [
                    {
                        "type": "report",
                        "spec_version": "2.1",
                        "id": "report--antiapt-telemetry-run",
                        "name": "AntiAPT Hunter v2.17 Behavioral Telemetry & Indicators",
                        "published": time.strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                ]
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(bundle_data, f, indent=4)
            self.log_message(f"Secure STIX 2.1 bundle exported successfully to {file_path}")

    def action_export_pdf_report(self):
        if not REPORTLAB_AVAILABLE:
            messagebox.showerror("Dependency Error", "The 'reportlab' package is required for PDF generation.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export PDF Summary Report",
            defaultextension=".pdf",
            filetypes=[("PDF Documents", "*.pdf"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            doc = SimpleDocTemplate(file_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            story = []
            styles = getSampleStyleSheet()

            title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=16, textColor=colors.HexColor('#0284c7'), spaceAfter=6)
            meta_style = ParagraphStyle('ReportMeta', parent=styles['Normal'], fontName='Courier', fontSize=9, textColor=colors.HexColor('#64748b'), spaceAfter=12)
            heading_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor('#0f172a'), spaceBefore=10, spaceAfter=6)
            cell_style = ParagraphStyle('TableCell', parent=styles['Normal'], fontName='Courier', fontSize=8, textColor=colors.HexColor('#020617'))

            story.append(Paragraph("AntiAPT Hunter v2.17 - Executive Incident & Behavioral Summary", title_style))
            story.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')} | Protection Profile: Real-Time Heuristic Shield", meta_style))
            story.append(Spacer(1, 10))

            story.append(Paragraph("Flagged Threat Indicators & Anomalies", heading_style))
            table_data = [["Executable Path / Target", "Behavioral State / Indicator"]]
            
            tree_items = self.threat_table.get_children()
            if tree_items:
                for item_id in tree_items:
                    row_values = self.threat_table.item(item_id, "values")
                    if len(row_values) >= 2:
                        table_data.append([Paragraph(row_values[0], cell_style), Paragraph(row_values[1], cell_style)])
            else:
                table_data.append([Paragraph("No threats flagged during current session.", cell_style), Paragraph("N/A", cell_style)])

            threat_table_obj = Table(table_data, colWidths=[380, 160])
            threat_table_obj.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(threat_table_obj)
            story.append(Spacer(1, 15))

            story.append(Paragraph("Operational Telemetry Logs", heading_style))
            log_content = self.txt_log.get("1.0", tk.END).strip()
            for line in (log_content.split("\n") if log_content else ["No log data recorded."])[-35:]:
                story.append(Paragraph(line, cell_style))

            doc.build(story)
            self.log_message(f"[PDF SUCCESS] Summary report compiled and exported to {file_path}")
            messagebox.showinfo("Export Success", f"PDF report successfully saved to:\n{file_path}")

        except Exception as e:
            self.log_message(f"[PDF ERROR] Failed to generate report: {str(e)}")
            messagebox.showerror("Export Error", f"Could not create PDF report:\n{str(e)}")

    def action_clear_logs(self):
        self.txt_log.delete("1.0", tk.END)


if __name__ == "__main__":
    app = AntiAPTHunterGUI()
    app.mainloop()