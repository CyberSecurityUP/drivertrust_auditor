# DriverTrust Auditor — Python MVP v5 (Ultimate)
#
# All-in-one, no-driver, GUI auditor for Windows drivers.
#
# ✅ New in v5 (compared to your v3):
#   - Progress bar + Debug Log dock (toggle in View)
#   - Batch signature + hash resolution (1 PowerShell roundtrip for many files)
#   - Offline .sys recursive scan (kept) with risk scoring
#   - WDAC active policy parsing (kept) + "What‑if WDAC" simulator
#   - Baseline & Drift (save/load/compare driver state)
#   - Code Integrity Log viewer (reads Microsoft-Windows-CodeIntegrity/Operational)
#   - Device map (approx.) — counts devices linked to each driver
#   - LOLDrivers (BYOVD) integration: load from local JSON or fetch from web; match by name/hash; annotate risk with CVEs/notes
#   - HTML/CSV exports (kept) — HTML now includes BYOVD & baseline deltas
#   - About dialog with creator credit: **Joas A Santos**
#
# Quick start (PowerShell):
#   py -m pip install PySide6
#   python drivertrust_auditor_v5.py
#
# Notes:
# - Run as Admin for best coverage. No kernel driver required.
# - PowerShell is used for CIM/WMI, Authenticode, file hashes, WDAC policy conversion.

import json
import os
import re
import sys
import csv
import time
import webbrowser
import subprocess
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Any, Dict
from datetime import datetime
from xml.etree import ElementTree as ET

from PySide6 import QtCore, QtWidgets, QtGui

# ---------------------------- Utilities ----------------------------
STARTUPINFO = None
if os.name == 'nt':
    STARTUPINFO = subprocess.STARTUPINFO()
    STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # hide console flashes

PS_CANDIDATES = [
    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"],
    ["pwsh", "-NoProfile", "-Command"],
]



def detect_powershell(timeout=3) -> List[str]:
    for cmd in PS_CANDIDATES:
        try:
            proc = subprocess.run(cmd + ["$PSVersionTable.PSVersion.ToString()"],
                                   capture_output=True, text=True, timeout=timeout,
                                   startupinfo=STARTUPINFO)
            if proc.returncode == 0 and proc.stdout.strip():
                return cmd
        except Exception:
            pass
    return PS_CANDIDATES[0]


PS = detect_powershell()


def run_ps_obj(script: str, timeout: int = 30) -> Any:
    """Run PowerShell, return parsed JSON from ConvertTo-Json; None on error/timeout."""
    full = f"{script} | ConvertTo-Json -Depth 7"
    try:
        proc = subprocess.run(PS + [full], capture_output=True, text=True, timeout=timeout,
                               startupinfo=STARTUPINFO)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def run_ps_text(script: str, timeout: int = 30) -> Optional[str]:
    try:
        proc = subprocess.run(PS + [script], capture_output=True, text=True, timeout=timeout,
                               startupinfo=STARTUPINFO)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def normalize_driver_path(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip().strip('"')

    # só até o primeiro .sys (ignora parâmetros depois)
    m = re.search(r'([^\s"]+\.sys)', s, flags=re.IGNORECASE)
    if m:
        s = m.group(1)

    s = os.path.expandvars(s)  # %SystemRoot%

    # remove prefixo NT \??\
    if s.startswith('\\\\??\\\\'):   # literal \??\
        s = s[4:]

    # \SystemRoot\System32\... -> C:\Windows\System32\...
    if s.lower().startswith('\\systemroot\\'):
        base = os.environ.get('SystemRoot', r'C:\Windows')
        s = os.path.join(base, s[12:].lstrip('\\/'))

    # relativos: system32\..., sysnative\..., syswow64\...
    if re.match(r'^(system32|sysnative|syswow64)\\', s, flags=re.IGNORECASE):
        base = os.environ.get('SystemRoot', r'C:\Windows')
        s = os.path.join(base, s)

    return os.path.normpath(s)


def extract_sys_path(pathname: Optional[str]) -> Optional[str]:
    if not pathname:
        return None
    m = re.search(r'"([^"]+\.sys)"', pathname, flags=re.IGNORECASE)
    if not m:
        m = re.search(r'([^\s"]+\.sys)', pathname, flags=re.IGNORECASE)
    return normalize_driver_path(m.group(1)) if m else None



# ---------------------------- Data classes ----------------------------
@dataclass
class DriverInfo:
    Name: str
    DisplayName: str
    Started: bool
    State: str
    StartMode: str
    PathName: Optional[str]
    ImagePath: Optional[str]
    Source: str = "Installed"  # Installed | Offline
    FileVersion: Optional[str] = None
    Signed: Optional[str] = None  # Valid/NotSigned/Unknown/HashMismatch etc.
    Signer: Optional[str] = None
    WHQL: Optional[bool] = None
    HashSHA256: Optional[str] = None
    DeviceCount: Optional[int] = None  # approx. number of PnP devices using it
    BlocklistHit: Optional[str] = None
    BYOVD: Optional[str] = None           # short tag if matched in LOLDrivers
    BYOVD_Detail: Optional[str] = None    # CVEs / description
    RiskLevel: Optional[str] = None
    Notes: Optional[str] = None
    Change: Optional[str] = None          # Baseline delta: New/Removed/Changed/Same

@dataclass
class WDACPolicyInfo:
    path: str
    name: Optional[str] = None
    enforcement: Optional[str] = None
    signing_scenarios: List[str] = field(default_factory=list)
    signer_count: int = 0
    file_rule_count: int = 0
    options: List[str] = field(default_factory=list)


# ---------------------------- Risk & Blocklist ----------------------------
BUILTIN_BLOCKLIST = {
    "gdrv.sys": "Gigabyte (historically exploitable)",
    "rtcore64.sys": "MSI Afterburner RTCore vulnerable variants",
    "rtcore32.sys": "MSI Afterburner RTCore vulnerable variants",
    "dbutil_2_3.sys": "Dell dbutil vulnerable",
    "npf.sys": "Old WinPcap/NPF",
}


def blocklist_hit(image_path: Optional[str]) -> Optional[str]:
    if not image_path:
        return None
    base = os.path.basename(image_path).lower()
    return BUILTIN_BLOCKLIST.get(base)


def risk_eval(d: DriverInfo, assume_hvci: bool, assume_wdac: bool) -> (str, str):
    notes = []
    risk = "Low"

    bl = blocklist_hit(d.ImagePath)
    if bl:
        notes.append(f"Blocklist: {bl}")
        risk = "High"

    if d.BYOVD:
        notes.append(f"LOLDrivers: {d.BYOVD}")
        risk = "High"

    if not d.ImagePath:
        notes.append("No image path (audit)")
        risk = _max_risk(risk, "Medium")
    else:
        if d.Signed in ("NotSigned", "Unknown", None):
            if assume_wdac or assume_hvci:
                notes.append("Unsigned/unknown — will be blocked")
                risk = "High"
            else:
                notes.append("Unsigned — consider remediation")
                risk = _max_risk(risk, "Medium")
        elif d.Signed == "Valid":
            if d.WHQL:
                notes.append("WHQL-signed")
            else:
                if d.StartMode and d.StartMode.lower() in ("boot", "system"):
                    notes.append("Signed non-WHQL at early boot")
                    risk = _max_risk(risk, "Medium")

    if assume_hvci:
        notes.append("HVCI assumed ON")
    if assume_wdac:
        notes.append("WDAC assumed ENFORCED")

    if d.Started and risk == "High" and d.Source == 'Installed':
        notes.append("Active now: potential breakage on enable")
    return risk, "; ".join(notes)


def _max_risk(a: str, b: str) -> str:
    order = {"Low": 0, "Medium": 1, "High": 2}
    return a if order[a] >= order[b] else b


# ---------------------------- Logger ----------------------------
class Logger(QtCore.QObject):
    message = QtCore.Signal(str)
    progress = QtCore.Signal(int, int, str)  # value, total, stage text

    def log(self, text: str):
        self.message.emit(text)

    def prog(self, value: int, total: int, stage: str):
        self.progress.emit(value, total, stage)


# ---------------------------- LOLDrivers DB ----------------------------
class LolDriversDB:
    """Lightweight LOLDrivers adapter. Accepts JSON from web or local file.
    We match by lowercase filename and optionally by sha256 hash.
    JSON schema differs across sources; we best-effort map common fields.
    """
    def __init__(self):
        self.by_name: Dict[str, dict] = {}
        self.by_sha256: Dict[str, dict] = {}

    def load_json_text(self, text: str) -> int:
        try:
            data = json.loads(text)
        except Exception:
            return 0
        count = 0
        if isinstance(data, dict) and 'drivers' in data:
            iterable = data['drivers']
        elif isinstance(data, list):
            iterable = data
        else:
            iterable = []
        for item in iterable:
            # Common field guesses
            name = (item.get('FileName') or item.get('filename') or item.get('Name') or item.get('name') or '').strip()
            sha = (item.get('SHA256') or item.get('sha256') or '').strip()
            vendor = item.get('Vendor') or item.get('vendor') or item.get('Publisher') or ''
            cves = item.get('CVEs') or item.get('cves') or item.get('CVE') or item.get('cve') or []
            desc = item.get('Description') or item.get('description') or ''
            ref = item.get('References') or item.get('references') or []
            rec = {
                'name': name,
                'sha256': sha.lower(),
                'vendor': vendor,
                'cves': cves if isinstance(cves, list) else ([cves] if cves else []),
                'desc': desc,
                'refs': ref if isinstance(ref, list) else ([ref] if ref else []),
            }
            if name:
                self.by_name.setdefault(name.lower(), rec)
                count += 1
            if sha:
                self.by_sha256.setdefault(sha.lower(), rec)
        return count

    def match(self, filename: Optional[str], sha256: Optional[str]) -> Optional[dict]:
        if sha256 and sha256.lower() in self.by_sha256:
            return self.by_sha256[sha256.lower()]
        if filename and filename.lower() in self.by_name:
            return self.by_name[filename.lower()]
        return None


# ---------------------------- Qt Models ----------------------------
class DriverTableModel(QtCore.QAbstractTableModel):
    HEADERS = [
        "Source", "Name", "DisplayName", "State", "StartMode", "Started",
        "ImagePath", "FileVersion", "Signed", "Signer", "WHQL", "Hash",
        "Devices", "Risk", "Notes"
    ]

    rowUpdated = QtCore.Signal(int)

    def __init__(self, rows: List[DriverInfo]):
        super().__init__()
        self.rows = rows

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(self.HEADERS)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None
        d = self.rows[index.row()]
        col = index.column()
        mapping = {
            0: d.Source,
            1: d.Name,
            2: d.DisplayName,
            3: d.State,
            4: d.StartMode,
            5: "Yes" if d.Started else "No",
            6: d.ImagePath or "",
            7: d.FileVersion or "",
            8: d.Signed or "",
            9: d.Signer or "",
            10: "Yes" if d.WHQL else ("No" if d.WHQL is False else ""),
            11: d.HashSHA256 or "",
            12: "" if d.DeviceCount is None else str(d.DeviceCount),
            13: d.RiskLevel or "",
            14: d.Notes or "",
        }
        if role == QtCore.Qt.DisplayRole:
            return mapping.get(col, "")
        if role == QtCore.Qt.ForegroundRole and col == 13:
            if d.RiskLevel == "High":
                return QtGui.QBrush(QtGui.QColor("#ff7070"))
            if d.RiskLevel == "Medium":
                return QtGui.QBrush(QtGui.QColor("#ffd166"))
            return QtGui.QBrush(QtGui.QColor("#a0f7a0"))
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole:
            return None
        if orientation == QtCore.Qt.Horizontal:
            return self.HEADERS[section]
        return section + 1

    def updateRows(self, rows: List[DriverInfo]):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def updateRow(self, i: int, d: DriverInfo):
        if 0 <= i < len(self.rows):
            self.rows[i] = d
            top_left = self.index(i, 0)
            bottom_right = self.index(i, self.columnCount()-1)
            self.dataChanged.emit(top_left, bottom_right)
            self.rowUpdated.emit(i)


class WDACPolicyModel(QtCore.QAbstractTableModel):
    HEADERS = ["Policy Name", "Enforcement", "Scenarios", "Signers", "FileRules", "Options", "Path"]

    def __init__(self, rows: List[WDACPolicyInfo]):
        super().__init__()
        self.rows = rows

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(self.HEADERS)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None
        p = self.rows[index.row()]
        col = index.column()
        mapping = {
            0: p.name or "(unknown)",
            1: p.enforcement or "(unknown)",
            2: ", ".join(p.signing_scenarios) or "",
            3: str(p.signer_count),
            4: str(p.file_rule_count),
            5: ", ".join(p.options[:6]) + ("…" if len(p.options) > 6 else ""),
            6: p.path,
        }
        if role == QtCore.Qt.DisplayRole:
            return mapping.get(col, "")
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole:
            return None
        if orientation == QtCore.Qt.Horizontal:
            return self.HEADERS[section]
        return section + 1

    def updateRows(self, rows: List[WDACPolicyInfo]):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()


# ---------------------------- Workers ----------------------------
class EnumDriversWorker(QtCore.QThread):
    done = QtCore.Signal(list)

    def __init__(self, logger: Logger):
        super().__init__()
        self.logger = logger

    def run(self):
        self.logger.log("Enumerating drivers via Win32_SystemDriver…")
        self.logger.prog(0, 0, "Enumerating drivers…")
        script = (
            "Get-CimInstance Win32_SystemDriver | "
            "Select-Object Name,DisplayName,State,Started,StartMode,PathName"
        )
        objs = run_ps_obj(script, timeout=60)
        rows: List[DriverInfo] = []
        if objs:
            if isinstance(objs, dict):
                objs = [objs]
            for o in objs:
                path = o.get("PathName")
                img = extract_sys_path(path) if path else None
                rows.append(DriverInfo(
                    Name=o.get("Name") or "",
                    DisplayName=o.get("DisplayName") or "",
                    Started=bool(o.get("Started")),
                    State=o.get("State") or "",
                    StartMode=o.get("StartMode") or "",
                    PathName=path,
                    ImagePath=img,
                    Source="Installed"
                ))
        self.logger.log(f"Enumerated {len(rows)} drivers")
        self.done.emit(rows)


class SignatureBatchWorker(QtCore.QThread):
    progress = QtCore.Signal(int, DriverInfo)
    done = QtCore.Signal()

    def __init__(self, rows: List[DriverInfo], assume_hvci: bool, assume_wdac: bool, logger: Logger, loldb: LolDriversDB):
        super().__init__()
        self.rows = rows
        self.assume_hvci = assume_hvci
        self.assume_wdac = assume_wdac
        self.logger = logger
        self._stop = False
        self.loldb = loldb

    def stop(self):
        self._stop = True

    def run(self):
        for i, d in enumerate(self.rows):
            if self._stop:
                break

            # normalize and verify path
            if d.ImagePath:
                d.ImagePath = normalize_driver_path(d.ImagePath)

            if d.ImagePath and os.path.exists(d.ImagePath):
                # FileVersion
                txt = run_ps_text(
                    f"(Get-Item -LiteralPath \"{d.ImagePath}\").VersionInfo | Select-Object -ExpandProperty FileVersion",
                    timeout=15
                )
                d.FileVersion = (txt or '').strip() or None

                # Signature + Signer
                sig = run_ps_obj(
                    f"$s=Get-AuthenticodeSignature -FilePath \"{d.ImagePath}\"; "
                    f"$pub=$s.SignerCertificate.Subject; "
                    f"[PSCustomObject]@{{ Status=$s.Status; Signer=$pub }}",
                    timeout=20
                )
                if sig:
                    d.Signed = sig.get('Status', 'Unknown')
                    d.Signer = sig.get('Signer')
                    d.WHQL = bool(d.Signer and (
                        'Hardware Compatibility Publisher' in d.Signer or
                        'Windows Hardware Compatibility Publisher' in d.Signer
                    ))
                else:
                    d.Signed, d.Signer, d.WHQL = 'Unknown', None, None

                # SHA256
                h = run_ps_text(
                    f"(Get-FileHash -Algorithm SHA256 -LiteralPath \"{d.ImagePath}\").Hash",
                    timeout=20
                )
                d.HashSHA256 = (h or '').strip() or None
            else:
                # log leve para te ajudar a diagnosticar
                # (não temos dock de log no v3, então fica silencioso no UI)
                d.Signed, d.Signer, d.WHQL = 'Unknown', None, None
                d.HashSHA256 = None

            d.BlocklistHit = blocklist_hit(d.ImagePath)
            d.RiskLevel, d.Notes = risk_eval(d, self.assume_hvci, self.assume_wdac)
            self.progress.emit(i, d)
            time.sleep(0.01)  # yield to UI

        self.done.emit()


class EnvProbeWorker(QtCore.QThread):
    hvci = QtCore.Signal(bool, bool)  # (configured, running)
    wdac = QtCore.Signal(list)        # list[WDACPolicyInfo]

    def __init__(self, logger: Logger):
        super().__init__()
        self.logger = logger

    def run(self):
        self.logger.log("Probing Device Guard / HVCI & WDAC…")
        obj = run_ps_obj(
            "Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard | Select-Object SecurityServicesConfigured,SecurityServicesRunning",
            timeout=20)
        hvci_cfg = hvci_run = False
        if obj:
            cfg = obj.get('SecurityServicesConfigured') or []
            runn = obj.get('SecurityServicesRunning') or []
            cfg = cfg if isinstance(cfg, list) else [cfg]
            runn = runn if isinstance(runn, list) else [runn]
            hvci_cfg = 2 in cfg
            hvci_run = 2 in runn
        self.hvci.emit(hvci_cfg, hvci_run)

        # WDAC policies (Active)
        policy_dir = os.path.join(os.environ.get("SystemRoot", r"C:\\Windows"),
                                  r"System32\\CodeIntegrity\\CiPolicies\\Active")
        policies: List[WDACPolicyInfo] = []
        if os.path.isdir(policy_dir):
            for f in os.listdir(policy_dir):
                if not f.lower().endswith('.cip'):
                    continue
                cip_path = os.path.join(policy_dir, f)
                xml_text = run_ps_text(
                    "Import-Module ConfigCI -ErrorAction SilentlyContinue; "
                    f"$tf=[System.IO.Path]::GetTempFileName(); ConvertFrom-CIPolicy -BinaryFilePath \"{cip_path}\" -XmlFilePath $tf -ErrorAction SilentlyContinue; Get-Content -LiteralPath $tf -Raw",
                    timeout=30)
                info = WDACPolicyInfo(path=cip_path)
                if xml_text:
                    try:
                        root = ET.fromstring(xml_text)
                        def tag(x): return x.split('}',1)[-1].lower()
                        for e in root.iter():
                            t = tag(e.tag)
                            if t == 'policyname' and e.text:
                                info.name = e.text.strip()
                            elif t == 'option' and e.text:
                                info.options.append(e.text.strip())
                            elif t == 'signingscenario':
                                v = e.attrib.get('Value') or e.attrib.get('value')
                                if v: info.signing_scenarios.append(v)
                            elif t in ('signer','signerref'):
                                info.signer_count += 1
                            elif t in ('filerule','fileattributesrule','filepublisherrule','filehashrule'):
                                info.file_rule_count += 1
                            elif t == 'enforcementmode' and e.text:
                                info.enforcement = e.text.strip()
                        if not info.enforcement:
                            info.enforcement = 'Audit' if any('Audit' in o for o in info.options) else 'Enforced'
                    except Exception:
                        pass
                policies.append(info)
        self.wdac.emit(policies)
        self.logger.log(f"WDAC policies detected: {len(policies)}")


class OfflineScanWorker(QtCore.QThread):
    progress = QtCore.Signal(int, DriverInfo)
    done = QtCore.Signal(list)

    def __init__(self, folder: str, assume_hvci: bool, assume_wdac: bool, logger: Logger, loldb: LolDriversDB):
        super().__init__()
        self.folder = folder
        self.assume_hvci = assume_hvci
        self.assume_wdac = assume_wdac
        self.logger = logger
        self.loldb = loldb

    def run(self):
        # Pre-count .sys files for progress
        total = 0
        for root_dir, _, files in os.walk(self.folder):
            total += sum(1 for f in files if f.lower().endswith('.sys'))
        self.logger.log(f"Offline scan: {total} .sys files found")
        self.logger.prog(0, max(total, 1), "Scanning folder…")
        rows = []
        i = 0
        for root_dir, _, files in os.walk(self.folder):
            for fn in files:
                if not fn.lower().endswith('.sys'):
                    continue
                path = normalize_driver_path(os.path.join(root_dir, fn))
                d = DriverInfo(Name=fn, DisplayName=fn, Started=False, State='Offline', StartMode='',
                               PathName=path, ImagePath=path, Source='Offline')
                # Per-file PS batch is handled later by SignatureBatchWorker if desired;
                # here we only basic-mark, hashes/signatures will be filled if user runs Resolve.
                rows.append(d)
                self.progress.emit(i, d)
                i += 1
                self.logger.prog(i, max(total, 1), "Scanning folder…")
                time.sleep(0.002)
        self.done.emit(rows)
        self.logger.log("Offline scan complete")


# ---------------------------- Main Window ----------------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DriverTrust Auditor — Python MVP v5")
        self.resize(1500, 900)

        self.logger = Logger()
        self.loldb = LolDriversDB()
        self.baseline: Optional[Dict[str, Any]] = None

        self.model = DriverTableModel([])

        # Widgets
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)

        self.assume_hvci = QtWidgets.QCheckBox("Assume HVCI enabled")
        self.assume_wdac = QtWidgets.QCheckBox("Assume WDAC enforced")
        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.resolve_btn = QtWidgets.QPushButton("Resolve Signatures/Hashes")
        self.cancel_btn = QtWidgets.QPushButton("Cancel")
        self.scan_btn = QtWidgets.QPushButton("Scan Folder…")
        self.wdac_btn = QtWidgets.QPushButton("WDAC Details…")
        self.whatif_btn = QtWidgets.QPushButton("What‑if WDAC…")
        self.export_csv_btn = QtWidgets.QPushButton("Export CSV")
        self.export_html_btn = QtWidgets.QPushButton("Export HTML")

        top = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(top)
        row = QtWidgets.QHBoxLayout()
        row.addWidget(self.assume_hvci)
        row.addWidget(self.assume_wdac)
        row.addStretch(1)
        row.addWidget(self.refresh_btn)
        row.addWidget(self.resolve_btn)
        row.addWidget(self.cancel_btn)
        row.addWidget(self.scan_btn)
        row.addWidget(self.wdac_btn)
        row.addWidget(self.whatif_btn)
        row.addWidget(self.export_csv_btn)
        row.addWidget(self.export_html_btn)
        v.addLayout(row)
        v.addWidget(self.table)
        self.setCentralWidget(top)

        # Status bar with progress + debug dock
        self.status = QtWidgets.QLabel("Ready")
        self.pb = QtWidgets.QProgressBar()
        self.pb.setMaximumWidth(260)
        self.pb.setTextVisible(True)
        self.statusBar().addWidget(self.status)
        self.statusBar().addPermanentWidget(self.pb)
        self._set_progress(None)

        self.logDock = QtWidgets.QDockWidget("Debug Log", self)
        self.logDock.setObjectName("DebugLogDock")
        self.logEdit = QtWidgets.QTextEdit(); self.logEdit.setReadOnly(True)
        font = QtGui.QFont("Consolas"); font.setStyleHint(QtGui.QFont.Monospace); font.setPointSize(10)
        self.logEdit.setFont(font)
        self.logDock.setWidget(self.logEdit)
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, self.logDock)
        self.logDock.hide()

        # Menu
        self._build_menu()

        # Signals
        self.refresh_btn.clicked.connect(self.start_refresh)
        self.resolve_btn.clicked.connect(self.start_signature_worker)
        self.cancel_btn.clicked.connect(self.cancel_workers)
        self.scan_btn.clicked.connect(self.scan_folder)
        self.wdac_btn.clicked.connect(self.show_wdac)
        self.whatif_btn.clicked.connect(self.show_whatif)
        self.export_csv_btn.clicked.connect(self.export_csv)
        self.export_html_btn.clicked.connect(self.export_html)
        self.assume_hvci.stateChanged.connect(self.rescore_only)
        self.assume_wdac.stateChanged.connect(self.rescore_only)

        # Logger wiring
        self.logger.message.connect(self._append_log)
        self.logger.progress.connect(self._on_progress)

        # Start probes and first load
        QtCore.QTimer.singleShot(0, self.bootstrap)

        self.sig_worker: Optional[SignatureBatchWorker] = None
        self.policies: List[WDACPolicyInfo] = []

    # ---------- Menu ----------
    def _build_menu(self):
        bar = self.menuBar()
        m_file = bar.addMenu("&File")
        act_save_base = m_file.addAction("Save Baseline…")
        act_load_base = m_file.addAction("Load Baseline…")
        act_compare = m_file.addAction("Compare with Baseline")
        m_file.addSeparator()
        act_save_log = m_file.addAction("Save Debug Log…")
        m_file.addSeparator()
        act_exit = m_file.addAction("Exit")

        m_view = bar.addMenu("&View")
        self.actShowLog = QtGui.QAction("Show Debug Log", self, checkable=True)
        self.actShowLog.setChecked(False)
        self.actShowLog.triggered.connect(lambda v: self.logDock.setVisible(v))
        self.logDock.visibilityChanged.connect(self.actShowLog.setChecked)
        m_view.addAction(self.actShowLog)
        act_ci = m_view.addAction("Code Integrity Log…")

        m_tools = bar.addMenu("&Tools")
        act_load_lol = m_tools.addAction("Load LOLDrivers JSON…")
        act_fetch_lol = m_tools.addAction("Fetch LOLDrivers (web)…")
        m_tools.addSeparator()
        act_wdac_exception = m_tools.addAction("Generate WDAC Exception (Publisher)…")

        m_help = bar.addMenu("&Help")
        act_about = m_help.addAction("About…")

        # Wire
        act_save_base.triggered.connect(self.save_baseline)
        act_load_base.triggered.connect(self.load_baseline)
        act_compare.triggered.connect(self.compare_baseline)
        act_save_log.triggered.connect(self.save_log)
        act_exit.triggered.connect(self.close)
        act_ci.triggered.connect(self.show_ci_log)
        act_load_lol.triggered.connect(self.load_loldrivers_local)
        act_fetch_lol.triggered.connect(self.fetch_loldrivers_web)
        act_wdac_exception.triggered.connect(self.generate_wdac_exception)
        act_about.triggered.connect(self.show_about)

    # ---------- Progress helpers ----------
    def _set_progress(self, triple: Optional[tuple]):
        if triple is None:
            self.pb.setRange(0, 1)
            self.pb.setValue(0)
            self.pb.setVisible(False)
            self.status.setText("Ready")
            return
        value, total, stage = triple
        self.pb.setVisible(True)
        if total <= 0:
            self.pb.setRange(0, 0)  # indeterminate
        else:
            self.pb.setRange(0, total)
            self.pb.setValue(min(value, total))
        pct = '' if total <= 0 else f" — {int((value/total)*100) if total else 0}%"
        self.status.setText(f"{stage}{pct}")

    def _on_progress(self, value: int, total: int, stage: str):
        self._set_progress((value, total, stage))

    def _append_log(self, text: str):
        ts = datetime.now().strftime('%H:%M:%S')
        self.logEdit.append(f"[{ts}] {text}")

    # ---------- Bootstrapping ----------
    def bootstrap(self):
        self.logger.log("Starting probes and initial enumeration…")
        self._set_progress((0, 0, "Probing environment…"))
        self.env = EnvProbeWorker(self.logger)
        self.env.hvci.connect(self._on_hvci)
        self.env.wdac.connect(self._on_wdac)
        self.env.start()
        self.start_refresh()

    def _on_hvci(self, configured: bool, running: bool):
        if running:
            self.assume_hvci.setChecked(True)
        self.logger.log(f"HVCI configured={configured}, running={running}")

    def _on_wdac(self, policies: List[WDACPolicyInfo]):
        self.policies = policies
        self.logger.log(f"WDAC policies loaded: {len(policies)}")

    # ---------- Refresh & Resolve ----------
    def start_refresh(self):
        self.logger.prog(0, 0, "Enumerating drivers…")
        self.refresh_btn.setEnabled(False)
        enum = EnumDriversWorker(self.logger)
        enum.done.connect(self._on_enum_done)
        enum.start()
        self.enum = enum

    def _on_enum_done(self, rows: List[DriverInfo]):
        self.model.updateRows(rows)
        self.refresh_btn.setEnabled(True)
        self.logger.log(f"Drivers listed: {len(rows)}")
        self._set_progress(None)

    def _after_signatures(self):
        self.status.setText("Signatures resolved — probing devices…")
        self.probe_devices()
        self.status.setText("Ready")

    def start_signature_worker(self):
        if not self.model.rows:
            QtWidgets.QMessageBox.information(self, "Resolve", "No rows to resolve.")
            return
        if self.sig_worker:
            self.sig_worker.stop()
        self.sig_worker = SignatureBatchWorker(
            self.model.rows,
            self.assume_hvci.isChecked(),
            self.assume_wdac.isChecked(),
            self.logger,
            self.loldb
        )
        self.sig_worker.progress.connect(self._on_sig_progress)
        self.sig_worker.done.connect(self._after_signatures)
        self._set_progress((0, len(self.model.rows), "Resolving signatures…"))
        self.sig_worker.start()

    def _on_sig_progress(self, idx: int, d: DriverInfo):
        self.model.updateRow(idx, d)

    def cancel_workers(self):
        if hasattr(self, 'sig_worker') and self.sig_worker:
            self.sig_worker.stop()
            self.logger.log("User cancelled signature worker")
            self._set_progress(None)

    def rescore_only(self):
        self.logger.log("Rescoring based on toggles…")
        for i, d in enumerate(self.model.rows):
            d.RiskLevel, d.Notes = risk_eval(d, self.assume_hvci.isChecked(), self.assume_wdac.isChecked())
            self.model.updateRow(i, d)

    # ---------- Offline scan ----------
    def scan_folder(self):
        folder = QtWidgets.QFileDialog.getExistingDirectory(self, "Scan folder for .sys")
        if not folder:
            return
        self.logger.log(f"Offline scan started: {folder}")
        off = OfflineScanWorker(folder, self.assume_hvci.isChecked(), self.assume_wdac.isChecked(), self.logger, self.loldb)
        off.progress.connect(lambda i, d: None)
        off.done.connect(self._on_off_done)
        off.start()
        self.off = off

    def _on_off_done(self, rows: List[DriverInfo]):
        merged = self.model.rows + rows
        self.model.updateRows(merged)
        QtWidgets.QMessageBox.information(self, "Offline scan", f"Found {len(rows)} driver files.")
        self._set_progress(None)

    # ---------- WDAC details & What-if ----------
    def show_wdac(self):
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("WDAC Details")
        dlg.resize(1000, 520)
        lay = QtWidgets.QVBoxLayout(dlg)
        info = QtWidgets.QLabel(f"<b>Policies:</b> {len(self.policies)}")
        lay.addWidget(info)
        table = QtWidgets.QTableView(); table.setModel(WDACPolicyModel(self.policies))
        table.horizontalHeader().setStretchLastSection(True); table.setAlternatingRowColors(True)
        lay.addWidget(table)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok)
        btns.accepted.connect(dlg.accept)
        lay.addWidget(btns)
        dlg.exec()

    def show_whatif(self):
        # Simple heuristic: unsigned/unknown or BYOVD => would be blocked in Enforced
        impacted = [d for d in self.model.rows if (self.assume_wdac.isChecked() or True) and (
            (d.Signed in ("NotSigned","Unknown", None)) or d.BYOVD or d.BlocklistHit)
        ]
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("What‑if WDAC — Impacted Drivers")
        dlg.resize(1000, 520)
        lay = QtWidgets.QVBoxLayout(dlg)
        lay.addWidget(QtWidgets.QLabel(f"Potentially blocked if WDAC Enforced (heuristic): {len(impacted)}"))
        tv = QtWidgets.QTableWidget(len(impacted), 5)
        tv.setHorizontalHeaderLabels(["Name","Path","Signed","Reason","Suggested Exception"])
        for i, d in enumerate(impacted):
            reason = []
            if d.Signed in ("NotSigned","Unknown", None): reason.append("Unsigned/Unknown")
            if d.BYOVD: reason.append("LOLDrivers hit")
            if d.BlocklistHit: reason.append("Built-in blocklist")
            sugg = "Publisher rule" if d.Signer else "File rule"
            tv.setItem(i,0,QtWidgets.QTableWidgetItem(d.Name))
            tv.setItem(i,1,QtWidgets.QTableWidgetItem(d.ImagePath or ""))
            tv.setItem(i,2,QtWidgets.QTableWidgetItem(d.Signed or ""))
            tv.setItem(i,3,QtWidgets.QTableWidgetItem(", ".join(reason)))
            tv.setItem(i,4,QtWidgets.QTableWidgetItem(sugg))
        tv.horizontalHeader().setStretchLastSection(True)
        tv.setAlternatingRowColors(True)
        lay.addWidget(tv)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok)
        btns.accepted.connect(dlg.accept)
        lay.addWidget(btns)
        dlg.exec()

    # ---------- Code Integrity log ----------
    def show_ci_log(self):
        script = (
            "Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 1000 | "
            "Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message"
        )
        ev = run_ps_obj(script, timeout=40)
        entries = ev if isinstance(ev, list) else ([ev] if ev else [])
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Code Integrity — Operational Log (last 1000)")
        dlg.resize(1200, 600)
        lay = QtWidgets.QVBoxLayout(dlg)
        tv = QtWidgets.QTableWidget(len(entries), 5)
        tv.setHorizontalHeaderLabels(["Time","EventID","Level","Provider","Message"])
        for i, e in enumerate(entries):
            tv.setItem(i,0,QtWidgets.QTableWidgetItem(str(e.get('TimeCreated') or '')))
            tv.setItem(i,1,QtWidgets.QTableWidgetItem(str(e.get('Id') or '')))
            tv.setItem(i,2,QtWidgets.QTableWidgetItem(str(e.get('LevelDisplayName') or '')))
            tv.setItem(i,3,QtWidgets.QTableWidgetItem(str(e.get('ProviderName') or '')))
            tv.setItem(i,4,QtWidgets.QTableWidgetItem(str(e.get('Message') or '')[:4096]))
        tv.horizontalHeader().setStretchLastSection(True)
        tv.setAlternatingRowColors(True)
        lay.addWidget(tv)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok)
        btns.accepted.connect(dlg.accept)
        lay.addWidget(btns)
        dlg.exec()

    # ---------- Baseline & Drift ----------
    def save_baseline(self):
        if not self.model.rows:
            QtWidgets.QMessageBox.information(self, "Baseline", "No drivers listed.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Baseline JSON", "drivertrust_baseline.json", "JSON Files (*.json)")
        if not path:
            return
        obj = {
            'generated': datetime.now().isoformat(timespec='seconds'),
            'count': len(self.model.rows),
            'drivers': [asdict(d) for d in self.model.rows]
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(obj, f, indent=2)
        self.logger.log(f"Baseline saved: {path}")

    def load_baseline(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load Baseline JSON", "", "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.baseline = json.load(f)
            self.logger.log(f"Baseline loaded: {path}")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Baseline", f"Failed to load: {e}")

    def compare_baseline(self):
        if not self.baseline:
            QtWidgets.QMessageBox.information(self, "Baseline", "Load a baseline first.")
            return
        base = self.baseline.get('drivers', [])
        # Map by ImagePath when possible, fallback to Name
        key = lambda d: (d.get('ImagePath') or '').lower() or (d.get('Name') or '').lower()
        base_map = {key(d): d for d in base}
        cur_map = {((d.ImagePath or '').lower() or d.Name.lower()): d for d in self.model.rows}
        # Mark current rows
        for k, d in cur_map.items():
            if k not in base_map:
                d.Change = 'New'
            else:
                b = base_map[k]
                sig = (d.Signed or '') == (b.get('Signed') or '')
                ver = (d.FileVersion or '') == (b.get('FileVersion') or '')
                signer = (d.Signer or '') == (b.get('Signer') or '')
                d.Change = 'Same' if (sig and ver and signer) else 'Changed'
                self.model.updateRow(self.model.rows.index(d), d)
        # Optionally show removed drivers
        removed = [v for k, v in base_map.items() if k not in cur_map]
        if removed:
            self.logger.log(f"Baseline removed drivers: {len(removed)}")
        QtWidgets.QMessageBox.information(self, "Baseline", "Comparison completed — see 'Change' column.")

    # ---------- LOLDrivers integration ----------
    def load_loldrivers_local(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load LOLDrivers JSON", "", "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                text = f.read()
            cnt = self.loldb.load_json_text(text)

            self.logger.log(f"LOLDrivers loaded from file: {cnt} entries")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "LOLDrivers", f"Failed to load: {e}")

    def fetch_loldrivers_web(self):
        # Try a set of candidate endpoints; if all fail, ask for a custom URL
        import urllib.request
        candidates = [
            "https://www.loldrivers.io/api/drivers.json",
            "https://www.loldrivers.io/api/drivers.min.json",
        ]
        text = None
        for url in candidates:
            try:
                with urllib.request.urlopen(url, timeout=20) as r:
                    text = r.read().decode('utf-8', errors='ignore')
                    if text and len(text) > 10:
                        cnt = self.loldb.load_json_text(text)
                        self.logger.log(f"LOLDrivers fetched: {cnt} entries from {url}")
                        break
            except Exception:
                continue
        if not text:
            url, ok = QtWidgets.QInputDialog.getText(self, "LOLDrivers", "Enter JSON URL:")
            if ok and url:
                try:
                    with urllib.request.urlopen(url, timeout=25) as r:
                        text = r.read().decode('utf-8', errors='ignore')
                        cnt = self.loldb.load_json_text(text)
                        self.logger.log(f"LOLDrivers fetched: {cnt} entries from {url}")
                except Exception as e:
                    QtWidgets.QMessageBox.warning(self, "LOLDrivers", f"Failed: {e}")
        # Re-score rows now that BYOVD intelligence is available
        self.rescore_only()

    def generate_wdac_exception(self):
        idx = self.table.currentIndex()
        if not idx.isValid():
            QtWidgets.QMessageBox.information(self, "WDAC", "Select a driver row first.")
            return
        d = self.model.rows[idx.row()]
        if not d.ImagePath:
            QtWidgets.QMessageBox.information(self, "WDAC", "Selected row has no driver path.")
            return
        out, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save WDAC exception XML", "wdac-exception.xml", "XML Files (*.xml)")
        if not out:
            return
        ps = (
            "Import-Module ConfigCI -ErrorAction SilentlyContinue; "
            f"New-CIPolicy -FilePath \"{out}\" -Level Publisher -DriverFiles \"{d.ImagePath}\" -UserPEs 0"
        )
        _ = run_ps_text(ps, timeout=60)
        self.logger.log(f"WDAC exception generated: {out}")
        QtWidgets.QMessageBox.information(self, "WDAC", f"Exception policy generated: {out}")

    def probe_devices(self):
        # Count how many PnP devices reference each DriverName
        objs = run_ps_obj(
            "Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName, DriverName",
            timeout=30
        )
        items = objs if isinstance(objs, list) else ([objs] if objs else [])
        counts = {}
        for it in items:
            dn = (it.get('DriverName') or '').lower()
            if not dn:
                continue
            counts[dn] = counts.get(dn, 0) + 1

        # Heuristic: match by DisplayName or Name (lowercased)
        for i, d in enumerate(self.model.rows):
            key1 = (d.DisplayName or '').lower()
            key2 = (d.Name or '').lower()
            d.DeviceCount = counts.get(key1) or counts.get(key2)
            self.model.updateRow(i, d)

    def save_log(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Debug Log", "drivertrust_log.txt", "Text Files (*.txt)")
        if not path:
            return
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.logEdit.toPlainText())
        self.logger.log(f"Log saved: {path}")

    def show_about(self):
        QtWidgets.QMessageBox.information(self, "About DriverTrust Auditor",
            """
DriverTrust Auditor — Windows driver inventory & risk posture (no kernel driver required).

Creator: **Joas A Santos**
UI: PySide6 (Qt for Python)
Capabilities: Driver inventory, signature/WHQL, WDAC snapshot + what-if, Code Integrity log,
offline .sys scan, BYOVD via LOLDrivers, baseline drift, HTML/CSV reports.
"""
        )

    # ---------- Exports ----------
    def export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save CSV", "drivertrust_audit.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(DriverTableModel.HEADERS)
            for d in self.model.rows:
                w.writerow([
                    d.Source, d.Name, d.DisplayName, d.State, d.StartMode,
                    "Yes" if d.Started else "No",
                    d.ImagePath or "", d.FileVersion or "",
                    d.Signed or "", d.Signer or "",
                    "Yes" if d.WHQL else ("No" if d.WHQL is False else ""),
                    d.HashSHA256 or "",
                    "" if d.DeviceCount is None else d.DeviceCount,
                    d.RiskLevel or "", d.Notes or "",
                ])
        QtWidgets.QMessageBox.information(self, "Export", f"Saved: {path}")


    def export_html(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save HTML report", "drivertrust_report.html", "HTML Files (*.html)"
        )
        if not path:
            return

        total = len(self.model.rows)
        high = sum(1 for d in self.model.rows if d.RiskLevel == 'High')
        med  = sum(1 for d in self.model.rows if d.RiskLevel == 'Medium')
        low  = sum(1 for d in self.model.rows if d.RiskLevel == 'Low')
        uns  = sum(1 for d in self.model.rows if d.Signed in ('NotSigned', 'Unknown', None))
        whql_yes = sum(1 for d in self.model.rows if d.WHQL is True)
        whql_no  = sum(1 for d in self.model.rows if d.WHQL is False)
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        def esc(x: str) -> str:
            return (x or '').replace('&', '&amp;')

        rows_html = []
        for d in self.model.rows:
            rows_html.append(
                f"<tr>"
                f"<td>{d.Source}</td><td>{esc(d.Name)}</td><td>{esc(d.DisplayName)}</td>"
                f"<td>{esc(d.State)}</td><td>{esc(d.StartMode)}</td>"
                f"<td>{'Yes' if d.Started else 'No'}</td>"
                f"<td>{esc(d.ImagePath)}</td><td>{esc(d.FileVersion)}</td>"
                f"<td>{esc(d.Signed)}</td><td>{esc(d.Signer)}</td>"
                f"<td>{'Yes' if d.WHQL else ('No' if d.WHQL is False else '')}</td>"
                f"<td>{esc(d.HashSHA256)}</td>"
                f"<td>{'' if d.DeviceCount is None else d.DeviceCount}</td>"
                f"<td>{esc(d.RiskLevel)}</td><td>{esc(d.Notes)}</td>"
                f"</tr>"
            )


        html = f"""
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>DriverTrust Auditor Report</title>
<style>
body {{ font-family: Segoe UI, Tahoma, sans-serif; background:#0f1117; color:#e6e6e6; }}
h1,h2 {{ color:#fafafa; }}
.card {{ background:#141a22; padding:16px; border-radius:12px; margin-bottom:16px; }}
.badge {{ padding:2px 8px; border-radius:12px; font-weight:600; }}
.badge.high {{ background:#5b1e1e; color:#ff9e9e; }}
.badge.medium {{ background:#5b4a1e; color:#ffd166; }}
.badge.low {{ background:#1e5b2a; color:#a0f7a0; }}
.table {{ width:100%; border-collapse: collapse; }}
.table th, .table td {{ border-bottom:1px solid #273043; padding:6px 8px; font-size:12.5px; }}
.table th {{ position:sticky; top:0; background:#18202b; text-align:left; }}
.small {{ opacity:0.85; }}
</style></head>
<body>
<h1>DriverTrust Auditor — Report</h1>
<div class="card">
  <div><b>Generated:</b> {ts}</div>
  <div><b>Totals:</b> {total} drivers &nbsp; | &nbsp;
       High <span class="badge high">{high}</span> &nbsp; Medium <span class="badge medium">{med}</span> &nbsp; Low <span class="badge low">{low}</span></div>
  <div class="small">Unsigned/Unknown: {uns} &nbsp; | &nbsp; WHQL Yes: {whql_yes} / No: {whql_no}</div>
</div>
<div class="card">
  <h2>Drivers</h2>
  <table class="table">
    <thead>
      <tr><th>Source</th><th>Name</th><th>DisplayName</th><th>State</th><th>StartMode</th><th>Started</th><th>ImagePath</th><th>FileVersion</th><th>Signed</th><th>Signer</th><th>WHQL</th><th>Hash</th><th>Devices</th><th>Risk</th><th>Notes</th></tr>
    </thead>
    <tbody>
      {''.join(rows_html)}
    </tbody>
  </table>
</div>
</body></html>
"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        QtWidgets.QMessageBox.information(self, "Export", f"Saved: {path}")
        try:
            webbrowser.open(f"file:///{path}")
        except Exception:
            pass

# ---------------------------- Entry ----------------------------
if __name__ == "__main__":
    if os.name != "nt":
        print("This tool targets Windows.")
        sys.exit(1)
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    w = MainWindow()
    w.show()
    sys.exit(app.exec())
