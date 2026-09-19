#!/usr/bin/env python3
"""
AntiAPT Hunter v2.2 Telemetry Platform
OSINT & Endpoint Incident Response Suite
"""

import os
import sys
import time
import shutil
import threading
import subprocess
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --- Dependency Imports with Hybrid YARA Fallback ---

try:
    import psutil
except ImportError:
    psutil = None

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

# Attempt importing compiled C-extension first; fallback to standalone binary
YARA_EXE_PATH = r"C:\Tools\YARA\yara64.exe"
QUARANTINE_DIR = r"C:\AntiAPT-Hunter\Quarantine"
yara = None
yara_mode = None

try:
    import yara
    yara_mode = "MODULE"
except ImportError:
    if os.path.exists(YARA_EXE_PATH):
        yara = True
        yara_mode = "CLI"
    else:
        yara = None
        yara_mode = None

# --- Localization Dictionary (English & Ukrainian) ---

TRANSLATIONS = {
    "en": {
        "title": "AntiAPT Hunter v2.2 Telemetry Platform",
        "status_idle": "System Status: IDLE / READY",
        "status_monitoring": "System Status: ACTIVE MONITORING",
        "tab_telemetry": "STIX 2.1 Telemetry",
        "tab_threats": "Detected Threat Indicators",
        "hdr_path": "Executable Path",
        "hdr_memory": "Memory State",
        "log_header": "Operational Telemetry Logs",
        "msg_missing_deps": "Warning: Essential dependencies missing.",
        "yara_cli_active": "YARA engine initialized via standalone binary at C:\\Tools\\YARA\\yara64.exe.",
        "yara_mod_active": "YARA engine initialized via yara-python module.",
        "yara_missing": "YARA engine unavailable. Neither yara-python nor yara64.exe was detected.",
        "btn_scan_file": "Run YARA File Scan",
        "btn_scan_memory": "Sweep Memory",
        "btn_export_stix": "Export STIX 2.1",
        "btn_clear_logs": "Clear Logs",
        "btn_start_monitor": "Start Active Monitor",
        "btn_stop_monitor": "Stop Active Monitor",
        "chk_quarantine": "Auto-Quarantine Threats",
        "lang_toggle": "🇺🇦 / 🇬🇧 UA"
    },
    "uk": {
        "title": "Платформа Телеметрії AntiAPT Hunter v2.2",
        "status_idle": "Статус системи: ОЧІКУВАННЯ / ГОТОВО",
        "status_monitoring": "Статус системи: АКТИВНИЙ МОНІТОРИНГ",
        "tab_telemetry": "Телеметрія STIX 2.1",
        "tab_threats": "Виявлені Індикатори Загроз",
        "hdr_path": "Шлях до виконуваного файлу",
        "hdr_memory": "Стан пам'яті",
        "log_header": "Журнали оперативної телеметрії",
        "msg_missing_deps": "Попередження: Відсутні важливі залежності.",
        "yara_cli_active": "Рушій YARA ініціалізовано через автономний бінарний файл C:\\Tools\\YARA\\yara64.exe.",
        "yara_mod_active": "Рушій YARA ініціалізовано через модуль yara-python.",
        "yara_missing": "Рушій YARA недоступний. Не знайдено ні yara-python, ні yara64.exe.",
        "btn_scan_file": "Сканування YARA",
        "btn_scan_memory": "Аналіз пам'яті",
        "btn_export_stix": "Експорт STIX 2.1",
        "btn_clear_logs": "Очистити логи",
        "btn_start_monitor": "Запустити моніторинг",
        "btn_stop_monitor": "Зупинити моніторинг",
        "chk_quarantine": "Автокарантин загроз",
        "lang_toggle": "🇬🇧 / 🇺🇦 EN"
    }
}


class ThreatHunterEngine:
    """Core analytical and threat detection engine."""

    def __init__(self, log_callback=None):
        self.log_callback = log_callback

    def validate_yara_rules(self, rule_path: str) -> bool:
        """Validates YARA rule syntax prior to executing scans."""
        if yara_mode == "MODULE":
            try:
                yara.compile(filepath=rule_path)
                return True
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"[YARA SYNTAX ERROR] {str(e)}")
                return False
        elif yara_mode == "CLI":
            try:
                cmd = [YARA_EXE_PATH, "-n", rule_path, sys.executable]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                # Exit code 0 or 1 typically indicates valid rule parsing; code 2 indicates syntax errors
                if result.returncode == 2:
                    if self.log_callback:
                        self.log_callback(f"[YARA SYNTAX ERROR] {result.stderr.strip()}")
                    return False
                return True
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"[YARA CLI Validation Error] {str(e)}")
                return False
        return False

    def scan_file_with_yara(self, rule_path: str, target_path: str) -> str:
        """Scans a target file using either Python YARA or yara64.exe safely."""
        if not os.path.exists(target_path):
            return "Target file does not exist."

        if not self.validate_yara_rules(rule_path):
            return "Scan aborted due to invalid YARA rule syntax."

        if yara_mode == "MODULE":
            try:
                rules = yara.compile(filepath=rule_path)
                matches = rules.match(target_path)
                return f"Matches: {matches}" if matches else "No matches found."
            except Exception as e:
                return f"YARA Module Scan Error: {str(e)}"

        elif yara_mode == "CLI":
            if not os.path.exists(YARA_EXE_PATH):
                return "YARA binary missing from C:\\Tools\\YARA\\yara64.exe."
            if not os.path.exists(rule_path):
                return f"Rule file not found: {rule_path}"

            try:
                cmd = [YARA_EXE_PATH, rule_path, target_path]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                output = result.stdout.strip()
                return output if output else "No matches found."
            except Exception as e:
                return f"YARA CLI Scan Error: {str(e)}"

        else:
            return "YARA scanning unavailable."

    def scan_process_memory(self) -> list:
        """Audits active process memory modules for anomalous path indicators."""
        anomalies = []
        if not psutil:
            return anomalies

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info']):
            try:
                pinfo = proc.info
                exe_path = pinfo.get('exe')
                if exe_path and any(term in exe_path.lower() for term in ["temp", "appdata", "public", "downloads"]):
                    anomalies.append({
                        "pid": pinfo.get('pid'),
                        "name": pinfo.get('name'),
                        "path": exe_path,
                        "rss": pinfo.get('memory_info').rss if pinfo.get('memory_info') else 0
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return anomalies

    def quarantine_file(self, file_path: str, proc_pid: int = None) -> bool:
        """Terminates process if running and isolates target binary into quarantine directory."""
        try:
            if proc_pid and psutil and psutil.pid_exists(proc_pid):
                proc = psutil.Process(proc_pid)
                proc.kill()
                if self.log_callback:
                    self.log_callback(f"[QUARANTINE] Terminated execution process (PID {proc_pid}).")

            if not os.path.exists(file_path):
                return False

            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            filename = os.path.basename(file_path)
            timestamp = int(time.time())
            quarantine_target = os.path.join(QUARANTINE_DIR, f"{timestamp}_{filename}.quarantine")

            shutil.move(file_path, quarantine_target)
            if self.log_callback:
                self.log_callback(f"[QUARANTINE SUCCESS] Isolated file move: {file_path} -> {quarantine_target}")
            return True
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[QUARANTINE FAILED] Could not isolate {file_path}: {str(e)}")
            return False


class AntiAPTHunterGUI(tk.Tk):
    """Main Application GUI Interface."""

    def __init__(self):
        super().__init__()
        self.current_lang = "en"
        self.engine = ThreatHunterEngine(log_callback=self.log_message)

        # Active monitoring & Quarantine attributes
        self.is_monitoring = False
        self.monitor_thread = None
        self.known_pids = set()
        self.poll_interval = 2.0
        self.auto_quarantine_enabled = tk.BooleanVar(value=False)

        t = TRANSLATIONS[self.current_lang]
        self.title(t["title"])
        self.geometry("1100x780")
        self.configure(bg="#0f172a")

        self.apply_styles()
        self.setup_ui()
        self.check_dependencies()

    def apply_styles(self):
        """Configures ttk styles for seamless dark theme rendering."""
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

        style.configure("Lang.TButton", background="#d97706", foreground="#ffffff", font=("Consolas", 9, "bold"), padding=6)
        style.map("Lang.TButton", background=[("active", "#b45309")])

        style.configure("TCheckbutton", background="#1e293b", foreground="#e2e8f0", font=("Consolas", 9, "bold"))

        style.configure("Treeview", background="#020617", foreground="#f8fafc", fieldbackground="#020617", rowheight=24)
        style.configure("Treeview.Heading", background="#1e293b", foreground="#00ffcc", font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", "#0369a1")])

    def setup_ui(self):
        t = TRANSLATIONS[self.current_lang]

        # Top Banner
        top_frame = tk.Frame(self, bg="#0f172a")
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        self.lbl_status = tk.Label(
            top_frame, 
            text=t["status_monitoring"] if self.is_monitoring else t["status_idle"], 
            fg="#22c55e" if self.is_monitoring else "#00ffcc", 
            bg="#0f172a", 
            font=("Consolas", 11, "bold")
        )
        self.lbl_status.pack(side=tk.RIGHT, padx=10)

        # Control Panel / Action Toolbar
        control_frame = tk.Frame(self, bg="#1e293b", bd=1, relief=tk.SOLID)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        # Active Monitor Toggle Button
        self.btn_toggle_monitor = ttk.Button(
            control_frame, 
            text=t["btn_stop_monitor"] if self.is_monitoring else t["btn_start_monitor"], 
            style="MonitorStop.TButton" if self.is_monitoring else "MonitorStart.TButton", 
            command=self.toggle_active_monitoring
        )
        self.btn_toggle_monitor.pack(side=tk.LEFT, padx=5, pady=5)

        # Auto-Quarantine Checkbox Toggle
        self.chk_quarantine_widget = ttk.Checkbutton(
            control_frame,
            text=t["chk_quarantine"],
            variable=self.auto_quarantine_enabled,
            style="TCheckbutton"
        )
        self.chk_quarantine_widget.pack(side=tk.LEFT, padx=10, pady=5)

        self.btn_scan_file = ttk.Button(
            control_frame, 
            text=t["btn_scan_file"], 
            style="Action.TButton", 
            command=self.action_scan_file
        )
        self.btn_scan_file.pack(side=tk.LEFT, padx=5, pady=5)

        self.btn_scan_mem = ttk.Button(
            control_frame, 
            text=t["btn_scan_memory"], 
            style="Action.TButton", 
            command=self.action_scan_memory
        )
        self.btn_scan_mem.pack(side=tk.LEFT, padx=5, pady=5)

        self.btn_export = ttk.Button(
            control_frame, 
            text=t["btn_export_stix"], 
            style="Secondary.TButton", 
            command=self.action_export_stix
        )
        self.btn_export.pack(side=tk.LEFT, padx=5, pady=5)

        # Language Toggle Button (Right Side)
        self.btn_lang = ttk.Button(
            control_frame,
            text=t["lang_toggle"],
            style="Lang.TButton",
            command=self.toggle_language
        )
        self.btn_lang.pack(side=tk.RIGHT, padx=5, pady=5)

        self.btn_clear = ttk.Button(
            control_frame, 
            text=t["btn_clear_logs"], 
            style="Secondary.TButton", 
            command=self.action_clear_logs
        )
        self.btn_clear.pack(side=tk.RIGHT, padx=5, pady=5)

        # Main Layout Container
        main_container = tk.Frame(self, bg="#0f172a")
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Tab Navigation Frame
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Telemetry
        self.tab_telemetry = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_telemetry, text=t["tab_telemetry"])

        lbl_telemetry_placeholder = tk.Label(
            self.tab_telemetry,
            text="[ STIX 2.1 Telemetry Feed Active ]",
            fg="#64748b",
            bg="#0f172a",
            font=("Consolas", 12, "italic")
        )
        lbl_telemetry_placeholder.pack(expand=True)

        # Tab 2: Detected Threats
        self.tab_threats = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_threats, text=t["tab_threats"])

        columns = ("path", "memory")
        self.threat_table = ttk.Treeview(self.tab_threats, columns=columns, show="headings")
        self.threat_table.heading("path", text=t["hdr_path"])
        self.threat_table.heading("memory", text=t["hdr_memory"])
        self.threat_table.column("path", width=700)
        self.threat_table.column("memory", width=350)
        self.threat_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Operational Log Section
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
        """Switches UI language between English and Ukrainian."""
        self.current_lang = "uk" if self.current_lang == "en" else "en"
        t = TRANSLATIONS[self.current_lang]

        # Update Window & Labels
        self.title(t["title"])
        self.lbl_status.config(text=t["status_monitoring"] if self.is_monitoring else t["status_idle"])
        
        # Update Notebook Tabs
        self.notebook.tab(self.tab_telemetry, text=t["tab_telemetry"])
        self.notebook.tab(self.tab_threats, text=t["tab_threats"])

        # Update Threat Table Headings
        self.threat_table.heading("path", text=t["hdr_path"])
        self.threat_table.heading("memory", text=t["hdr_memory"])

        # Update Log Frame Title
        self.log_frame.config(text=t["log_header"])

        # Update Buttons & Checkbox
        self.btn_toggle_monitor.config(text=t["btn_stop_monitor"] if self.is_monitoring else t["btn_start_monitor"])
        self.chk_quarantine_widget.config(text=t["chk_quarantine"])
        self.btn_scan_file.config(text=t["btn_scan_file"])
        self.btn_scan_mem.config(text=t["btn_scan_memory"])
        self.btn_export.config(text=t["btn_export_stix"])
        self.btn_clear.config(text=t["btn_clear_logs"])
        self.btn_lang.config(text=t["lang_toggle"])

    def log_message(self, message: str):
        """Appends timestamped operational logs to the interface thread-safely."""
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        formatted_entry = f"{timestamp} {message}\n"
        self.txt_log.after(0, lambda: self._append_log(formatted_entry))

    def _append_log(self, entry: str):
        self.txt_log.insert(tk.END, entry)
        self.txt_log.see(tk.END)

    def check_dependencies(self):
        """Verifies environment dependencies on startup."""
        missing = []
        if not psutil: 
            missing.append("psutil")
        if not win32evtlog: 
            missing.append("pywin32")

        if missing:
            t = TRANSLATIONS[self.current_lang]
            warn_msg = f"{t['msg_missing_deps']} ({', '.join(missing)})"
            self.log_message(warn_msg)

        t = TRANSLATIONS[self.current_lang]
        if yara_mode == "MODULE":
            self.log_message(t["yara_mod_active"])
        elif yara_mode == "CLI":
            self.log_message(t["yara_cli_active"])
        else:
            self.log_message(t["yara_missing"])

    def toggle_active_monitoring(self):
        t = TRANSLATIONS[self.current_lang]
        if not self.is_monitoring:
            if not psutil:
                messagebox.showerror("Dependency Error", "psutil is required for active process monitoring.")
                return

            self.is_monitoring = True
            self.btn_toggle_monitor.config(text=t["btn_stop_monitor"], style="MonitorStop.TButton")
            self.lbl_status.config(text=t["status_monitoring"], fg="#22c55e")
            self.log_message("Active endpoint monitoring initialized.")

            self.known_pids = set(psutil.pids())
            self.monitor_thread = threading.Thread(target=self._monitor_worker, daemon=True)
            self.monitor_thread.start()
        else:
            self.is_monitoring = False
            self.btn_toggle_monitor.config(text=t["btn_start_monitor"], style="MonitorStart.TButton")
            self.lbl_status.config(text=t["status_idle"], fg="#00ffcc")
            self.log_message("Active endpoint monitoring stopped.")

    def _monitor_worker(self):
        """Background thread monitoring new processes in real-time."""
        while self.is_monitoring:
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self.known_pids

                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        exe_path = proc.exe()

                        log_entry = f"[MONITOR] New Process Spawned -> PID: {pid} | Name: {name} | Path: {exe_path}"
                        self.log_message(log_entry)

                        if any(term in exe_path.lower() for term in ["temp", "appdata", "public"]):
                            self.log_message(f"[ALERT] Suspicious execution path detected for PID {pid}: {exe_path}")
                            self.threat_table.after(0, lambda p=exe_path: self.threat_table.insert("", tk.END, values=(p, "Suspicious Path")))

                            if self.auto_quarantine_enabled.get():
                                self.engine.quarantine_file(exe_path, proc_pid=pid)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                self.known_pids = current_pids
            except Exception as e:
                self.log_message(f"[MONITOR ERROR] {str(e)}")

            time.sleep(self.poll_interval)

    def action_scan_file(self):
        rule_path = filedialog.askopenfilename(title="Select YARA Rule File", filetypes=[("YARA Rules", "*.yar *.yara"), ("All Files", "*.*")])
        if not rule_path:
            return

        target_path = filedialog.askopenfilename(title="Select Target File to Scan", filetypes=[("All Files", "*.*")])
        if not target_path:
            return

        self.log_message(f"Initiating scan on {target_path} using rule {rule_path}...")
        res = self.engine.scan_file_with_yara(rule_path, target_path)
        self.log_message(f"Scan result: {res}")

        if "Matches:" in res and self.auto_quarantine_enabled.get():
            self.engine.quarantine_file(target_path)

    def action_scan_memory(self):
        self.log_message("Sweeping active process memory modules...")
        anomalies = self.engine.scan_process_memory()
        if anomalies:
            self.log_message(f"[WARNING] Found {len(anomalies)} processes running from non-standard paths.")
            for item in anomalies:
                self.threat_table.after(0, lambda path=item['path'], pid=item['pid']: self.threat_table.insert("", tk.END, values=(path, f"Memory Hook (PID {pid})")))
        else:
            self.log_message("Memory sweep complete. No unauthorized path hooks detected.")

    def action_export_stix(self):
        file_path = filedialog.asksaveasfilename(title="Export STIX 2.1 Bundle", defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if file_path:
            bundle_data = {
                "type": "bundle",
                "id": "bundle--antiapt-hunter-telemetry",
                "objects": [
                    {
                        "type": "report",
                        "spec_version": "2.1",
                        "id": "report--antiapt-telemetry-run",
                        "name": "AntiAPT Hunter v2.2 Execution Log",
                        "published": time.strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                ]
            }
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(bundle_data, f, indent=4)
            self.log_message(f"STIX 2.1 bundle exported successfully to {file_path}")

    def action_clear_logs(self):
        self.txt_log.delete("1.0", tk.END)


if __name__ == "__main__":
    app = AntiAPTHunterGUI()
    app.mainloop()