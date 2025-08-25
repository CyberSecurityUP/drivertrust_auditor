# DriverTrust Auditor

**All-in-one, no-kernel-driver, GUI auditor for Windows drivers.**
Inventory loaded/installed drivers, verify Authenticode/WHQL, snapshot WDAC/HVCI posture, simulate “what-if” policies, scan offline `.sys` trees, and enrich risk with **LOLDrivers (BYOVD)** intelligence — all from a responsive Qt (PySide6) UI.

> Creator: **Joas A Santos**

---

## Highlights

* ✅ **No kernel driver required** (read-only, user-mode).
* ⚡ **Fast & responsive UI**: heavy work runs in background threads.
* 🔐 **Signature & WHQL**: batch resolves FileVersion, Authenticode status, signer, and **SHA-256 hash**.
* 🧭 **WDAC posture**: reads active `.cip` policies (via `ConfigCI`) and shows enforcement/signers/rules/options.
* 🧪 **What-if WDAC**: predicts breakage if you enforced WDAC/HVCI on this host.
* 🧾 **Code Integrity log viewer**: reads `Microsoft-Windows-CodeIntegrity/Operational`.
* 🗂️ **Offline catalog**: recursively scan any folder for `.sys` and analyze like installed drivers.
* 🧩 **LOLDrivers (BYOVD)**: load local JSON or fetch from the web; match by filename/hash; annotate CVEs/notes.
* 📈 **Baseline & drift**: save, load, and compare driver states (New/Removed/Changed).
* 📤 **Exports**: HTML report (executive summary + table) and CSV.
* 🧰 **Device map (approx.)**: counts PnP devices per driver to help prioritize impact.
* 🧯 **Built-in blocklist**: flags common risky driver families (e.g., RTCore, dbutil, gdrv).

---

## Requirements

* **Windows 10 / Windows Server 2016** or later (x64 recommended)
* **Python 3.9+**
* **PowerShell** (Windows PowerShell 5.x or PowerShell 7+). The app autodetects `powershell` and `pwsh`.
* **PySide6** (`pip install PySide6`)
* Recommended: **Run as Administrator** for best file access/CI log coverage.

---

## Installation

```powershell
py -m pip install --upgrade pip
py -m pip install PySide6
```

Clone or copy the repository files. The main entry point is one of:

* `drivertrust_auditor_v5.py` (Ultimate version)
* `drivertrust_auditor_v3.py` (lightweight responsive baseline)

Run:

```powershell
python .\drivertrust_auditor_v5.py
```

> If you prefer a single EXE:
> `py -m pip install pyinstaller`
> `pyinstaller --noconfirm --windowed --name DriverTrustAuditor --collect-all PySide6 drivertrust_auditor_v5.py`

---

## Quick start (GUI)

1. **Refresh** — loads `Win32_SystemDriver` via CIM/WMI.
2. **Resolve Signatures/Hashes** — batch-resolves FileVersion, Authenticode `Status`, `Signer`, `WHQL` (heuristic), and SHA-256.
3. **(Optional) Scan Folder…** — add offline `.sys` from a directory tree.
4. **Tools → LOLDrivers** — **Load JSON** (local) or **Fetch** (web) to enable BYOVD cross-reference.
5. **View posture** — tick **Assume HVCI / Assume WDAC** to rescore risks; open **WDAC Details…**.
6. **What-if WDAC…** — see which drivers would likely be blocked and suggested exception type.
7. **Exports** — **CSV** or **HTML** (includes executive summary and BYOVD/WHQL notes).
8. **Baselines** — **Save Baseline…**, later **Load** and **Compare** for drift (New/Removed/Changed).

<img width="1506" height="892" alt="image" src="https://github.com/user-attachments/assets/8452289b-926a-4759-844c-b1b0c00164df" />


---

## Columns (data model)

* **Source**: `Installed` or `Offline`
* **Name / DisplayName / State / StartMode / Started**
* **ImagePath**: normalized Win32 path (e.g., `C:\Windows\System32\drivers\acpi.sys`)
* **FileVersion**
* **Signed**: Authenticode status (`Valid`, `NotSigned`, `Unknown`, etc.)
* **Signer**: certificate subject (publisher)
* **WHQL**: heuristic true/false from signer containing *Hardware Compatibility Publisher*
* **Hash**: SHA-256 (from `Get-FileHash`)
* **Devices**: approximate PnP device count linked to the driver name
* **Risk**: `Low/Medium/High` (see scoring)
* **Notes**: human-readable rationale, e.g., “Unsigned”, “WHQL-signed”, “LOLDrivers hit …”

---

## Risk scoring (simplified)

* **High**

  * Known risky **blocklist** or **LOLDrivers/BYOVD** match
  * Unsigned/Unknown while **Assume WDAC/HVCI** is ON
* **Medium**

  * Unsigned/Unknown (no assumptions)
  * Signed but **non-WHQL** at early boot (`StartMode=Boot/System`)
* **Low**

  * Signed and **WHQL** (or otherwise benign)

Notes explain why (e.g., “Unsigned — consider remediation”, “HVCI assumed ON”, “Active now: potential breakage on enable”).

---

## WDAC: active policies & what-if

* **Active WDAC**: parses `.cip` → XML using `ConvertFrom-CIPolicy` (PowerShell `ConfigCI` module).
* Displays **Policy Name**, **Enforcement** (Audit/Enforced), **Scenarios**, **Signer/FileRule counts**, **Options**.
* **What-if WDAC**: flags entries likely blocked (Unsigned/Unknown/BYOVD/blocklist) and suggests **Publisher** vs **File** exception.

> You can also generate a **Publisher exception** stub (`Tools → Generate WDAC Exception…`). The tool writes an XML with the rule — it does **not** apply any policy.

---

## LOLDrivers (BYOVD) integration

* **Load local JSON** or **Fetch from web** (e.g. `https://www.loldrivers.io/api/drivers.json`).
* Matching:

  * **Hash** (SHA-256) if available
  * Fallback to **filename** (lowercase)
* Annotates **BYOVD** tag and **CVEs/description** in Notes, and raises risk accordingly.

> If your environment blocks outbound requests, use **Load JSON…** and point to a cached file.

---

## Code Integrity log

* Reads the last \~1000 events from `Microsoft-Windows-CodeIntegrity/Operational` via `Get-WinEvent`.
* Useful to correlate real enforcement/audit outcomes with “what-if” predictions.

---

## How it works (internals)

* **Enumeration**: `Get-CimInstance Win32_SystemDriver`
* **Path normalization**: converts `\SystemRoot\…`, `\??\C:\…`, or `system32\…` to valid Win32 paths
* **Batch signature/hash**: one PowerShell roundtrip for many files (VersionInfo, Authenticode, SHA-256)
* **WHQL**: inferred from signer subject containing *Hardware Compatibility Publisher* (heuristic)
* **Devices**: aggregates `Win32_PnPSignedDriver.DriverName` counts (approximate)
* **Threads**: all heavy work runs in `QThread` workers; UI stays responsive
* **No kernel components**: read-only; does not hook or patch the OS

---

## Troubleshooting

* **Empty “Hash/Signed/Version/WHQL”**

  * Run as **Administrator** (ACLs can block reads under `System32\drivers`).
  * Ensure paths are normalized; the app does this, but check `ImagePath` is a real `C:\…\*.sys`.
  * Corporate AV might block `Get-FileHash` on some paths.

* **“Resolve” does nothing**

  * PowerShell not found? The app tries `powershell` then `pwsh`. Install one of them, or ensure it’s on `PATH`.
  * Verify your version matches **v5** (uses `SignatureBatchWorker`).
  * Check the bottom **Debug Log** (toggle via **View → Show Debug Log**).

* **WDAC policies not listed**

  * `ConfigCI` module required (`ConvertFrom-CIPolicy`); also needs read access to `%SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\*.cip`.
  * Some environments limit access unless elevated.

* **White or frozen window**

  * Fixed in v3+ by moving all work off the UI thread. If you custom-patched, ensure every long task uses a `QThread`.

---

## Security & privacy

* **Read-only by default**: the app does not modify drivers/policies.
* The **WDAC exception** action only **creates** an XML file; it **does not** enable or import WDAC policies.
* Be mindful when using BYOVD intelligence in production: follow your org’s security policy.

---

## Roadmap ideas

* Catalog (.cat) chain introspection & timestamp validation
* INF correlation (PnP IDs ↔ driver package)
* ETW telemetry join (kernel trace → actual driver callsites)
* Remote/at-scale collection (WinRM)
* Deeper signer trust model (EKU, countersigners)
* Packaging: signed MSI with auto-updates

---

## Build & contribute

PRs and issues welcome. Please keep contributions focused on **read-only auditing** and performance/UX improvements.

Suggested dev workflow:

```powershell
# create venv
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt  # contains PySide6 (or install PySide6 directly)
python drivertrust_auditor.py
```

---

## License

MIT (recommended). If you need a different license, update this section accordingly.

---

## Acknowledgments

* **LOLDrivers** — community BYOVD intelligence
* Microsoft: **WDAC/Device Guard** docs & `ConfigCI` tooling
* **PySide6/Qt for Python** — modern, responsive GUI
* All the researchers who keep driver security in the spotlight 🙏

---

### One-liner to run

```powershell
py -m pip install PySide6 ; python .\drivertrust_auditor.py
```

Happy auditing!
