# VulnGuard — Build Instructions

## Requirements
- Visual Studio 2022 **or** .NET 8 SDK
- Windows 10/11 (x64)

---

## Build in Visual Studio 2022

1. Open **Visual Studio 2022**
2. File → Open → Project/Solution → select `VulnGuard.csproj`
3. Set configuration to **Release | x64**
4. Build → **Build Solution** (Ctrl+Shift+B)
5. Output EXE is at:
   `VulnGuard\bin\Release\net8.0-windows\VulnGuard.exe`

---

## Build a standalone single-file EXE (recommended)

Open **Developer Command Prompt** or any terminal inside the project folder:

```
cd VulnGuard
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

Output: `VulnGuard\bin\Release\net8.0-windows\win-x64\publish\VulnGuard.exe`

This single EXE runs on ANY Windows 10/11 machine with no .NET install required.

---

## Running VulnGuard

- **Double-click** `VulnGuard.exe` — basic scan works for current user
- **Right-click → Run as Administrator** — enables full system access:
  - Registry reads that need elevation
  - Service control
  - Group policy checks
  - Auto-fix / patch application

---

## What each button does

| Button | Action |
|---|---|
| `[ RUN FULL VULNERABILITY SCAN ]` | All 16 checks — full scan |
| `[ AUTO-PATCH ALL FIXABLE ISSUES ]` | Applies PowerShell fixes for everything flagged |
| `[ HARDEN FIREWALL ]` | Firewall check + fix only |
| `[ LOCK DOWN SSH ]` | RDP/SSH check + fix only |
| `[ HARDEN KERNEL PARAMS ]` | Registry security check only |
| `[ RESTORE DEFAULTS ]` | Reverts Firewall, Defender, UAC, Windows Update to ON |
| `[ QUICK SCAN ]` (top bar) | 7 essential checks only — fast |

---

## Scan covers

- Windows Defender / AV status + signature age
- Windows Update service + group policy
- Firewall status (all profiles)
- Open ports (FTP, Telnet, RDP, VNC, Redis, MongoDB, etc.)
- Guest account status
- UAC level
- RDP / NLA / SSH exposure
- SMBv1 (WannaCry vector)
- NetBIOS over TCP/IP
- Registry: NTLMv1, RestrictAnonymous, LLMNR, Auto-login
- Dangerous services (RemoteRegistry, Telnet, SNMP, Spooler)
- Logon audit policy
- Scheduled tasks (non-Microsoft)
- World-writable system paths
- BitLocker encryption status
- Password policy (length + expiry)

---

## Report
After each scan a `.txt` report is saved to your **Desktop** automatically.

---

## Notes
- VulnGuard scans **your machine only** — no network scanning
- Closing the window minimizes to system tray
- Right-click tray icon → Exit to fully quit
