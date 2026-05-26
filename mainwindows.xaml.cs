using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Forms  = System.Windows.Forms;
using WpfApp = System.Windows.Application;
using WpfMsg = System.Windows.MessageBox;
using WpfClr = System.Windows.Media.Color;
using WinForms = System.Windows.Forms;

namespace VulnGuard_Project
{
    // ── Finding model ────────────────────────────────────────────────────────
    public enum Severity { High, Medium, Info }

    public class Finding
    {
        public Severity  Severity  { get; set; }
        public string    Category  { get; set; } = "";
        public string    Title     { get; set; } = "";
        public string    Detail    { get; set; } = "";
        public string?   FixCmd    { get; set; }       // PowerShell command string
        public string?   FixDesc   { get; set; }
        public DateTime  Timestamp { get; set; } = DateTime.Now;
        public bool      Fixed     { get; set; }
    }

    // ── Main window ──────────────────────────────────────────────────────────
    public partial class MainWindow : Window
    {
        private readonly StringBuilder   _logBuffer = new();
        private readonly List<Finding>   _findings  = new();
        private readonly object          _findingsLock = new();
        private Forms.NotifyIcon         _trayIcon  = null!;
        private bool                     _scanning;

        // Progress state
        private int _totalChecks;
        private int _doneChecks;

        // Set up the audio manager file connection
        private AudioManager _audio = new AudioManager();

        public MainWindow()
        {
            InitializeComponent();

            // Drag anywhere
            MouseLeftButtonDown += (s, e) => { if (e.LeftButton == System.Windows.Input.MouseButtonState.Pressed) DragMove(); };

            // Hide to tray on close
            Closing += (s, e) => { e.Cancel = true; HideToTray(); };

            InitTrayIcon();
            Log("VulnGuard initializing...");
            Log("Run as Administrator for full scan access.");
            Log("Ready. Select a scan option above.");

            // Tells the app to start the music once everything is loaded
            this.Loaded += MainWindow_Loaded;
        }
        // Starts the looping music on startup
        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _audio.StartMusic();
        }

        // Toggles the music mute status when clicked
        private void Mute_Click(object sender, RoutedEventArgs e)
        {
            _audio.ToggleMute();
            MuteBtn.Content = _audio.IsMuted ? "🔇" : "🔊";
        }
        // ── TRAY ─────────────────────────────────────────────────────────────
        private void InitTrayIcon()
        {
            _trayIcon = new Forms.NotifyIcon
            {
                Text    = "VulnGuard — Standing by",
                Visible = true,
                Icon    = LoadTrayIcon()
            };
            var menu = new Forms.ContextMenuStrip();
            menu.Items.Add("⬡ Open VulnGuard", null, (s, e) => ShowFromTray());
            menu.Items.Add("-");
            menu.Items.Add("✕ Exit",            null, (s, e) => ExitApp());
            _trayIcon.ContextMenuStrip = menu;
            _trayIcon.DoubleClick += (s, e) => ShowFromTray();
        }

        private static System.Drawing.Icon LoadTrayIcon()
        {
            try
            {
                var streamInfo = WpfApp.GetResourceStream(new Uri("pack://application:,,,/app_icon.ico", UriKind.Absolute));
                if (streamInfo?.Stream == null) return System.Drawing.SystemIcons.Shield;

                using var icon = new System.Drawing.Icon(streamInfo.Stream);
                return (System.Drawing.Icon)icon.Clone();
            }
            catch
            {
                return System.Drawing.SystemIcons.Shield;
            }
        }

        private void HideToTray()
        {
            Hide();
            _trayIcon.ShowBalloonTip(2000, "⬡ VulnGuard", "Still watching. Right-click tray to open.", Forms.ToolTipIcon.Info);
        }

        private void ShowFromTray() { Show(); WindowState = WindowState.Normal; Activate(); }

        private void ExitApp()
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            WpfApp.Current.Shutdown();
        }

        // ── TITLE BAR BUTTONS ────────────────────────────────────────────────
        private void Close_Click(object sender, RoutedEventArgs e) => HideToTray();
        private void Min_Click(object sender, RoutedEventArgs e)   => WindowState = WindowState.Minimized;

        private void About_Click(object sender, RoutedEventArgs e)
        {
            WpfMsg.Show(
                "⬡ VULNGUARD v1.0 ⬡\n\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━\n" +
                " LOCAL VULNERABILITY SCANNER\n" +
                " + AUTO-PATCH ENGINE\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
                "Scans YOUR machine only.\n" +
                "Finds weaknesses before attackers do.\n" +
                "Auto-patches what it can.\n\n" +
                "Run as Administrator for full access.\n\n" +
                "Checks:\n" +
                " • Windows security updates\n" +
                " • Firewall / open ports\n" +
                " • SSH & RDP exposure\n" +
                " • Dangerous services\n" +
                " • Registry security policy\n" +
                " • UAC / guest accounts\n" +
                " • Defender / antivirus status\n" +
                " • Scheduled task tampering\n" +
                " • World-writable paths\n" +
                " • SMB / NetBIOS exposure\n\n" +
                "Stay patched. Stay dark.",
                "About VulnGuard",
                MessageBoxButton.OK);
        }

        // ── LOGGING ──────────────────────────────────────────────────────────
        private void Log(string msg)
        {
            Dispatcher.Invoke(() =>
            {
                _logBuffer.AppendLine($"> [{DateTime.Now:HH:mm:ss}] {msg}");
                ConsoleLog.Text = _logBuffer.ToString();
                Scroller.ScrollToEnd();
            });
        }

        private void SetStatus(string text, bool red = false)
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = text;
                StatusLight.Fill = new SolidColorBrush(red
                    ? WpfClr.FromRgb(255, 34, 34)
                    : WpfClr.FromRgb(0, 255, 65));
                TrayText.Text = text;
            });
        }

        // ── PROGRESS ─────────────────────────────────────────────────────────
        private void SetProgress(int done, int total)
        {
            Dispatcher.Invoke(() =>
            {
                double pct = total == 0 ? 0 : Math.Clamp((double)done / total, 0, 1);
                double maxW = Math.Max(0, ScanProgressTrack.ActualWidth - ScanProgressTrack.BorderThickness.Left - ScanProgressTrack.BorderThickness.Right);
                ScanProgress.Width = Math.Max(0, pct * maxW);
                ScanProgressText.Text = $"{(int)(pct * 100)}%";
            });
        }

        private void AddFinding(Finding f)
        {
            lock (_findingsLock)
            {
                _findings.Add(f);
            }

            string sev = f.Severity == Severity.High ? "[HIGH]" : f.Severity == Severity.Medium ? "[MED] " : "[INFO]";
            Log($"{sev} {f.Title}");
            if (!string.IsNullOrEmpty(f.Detail)) Log($"       {f.Detail}");
            if (f.FixDesc != null)               Log($"       → FIX: {f.FixDesc}");
            UpdateCounts();
        }

        private void UpdateCounts()
        {
            int high;
            int med;
            int ok;
            int fix;
            lock (_findingsLock)
            {
                high = _findings.Count(f => f.Severity == Severity.High);
                med  = _findings.Count(f => f.Severity == Severity.Medium);
                ok   = _findings.Count(f => f.Severity == Severity.Info);
                fix  = _findings.Count(f => f.FixCmd != null);
            }

            Dispatcher.Invoke(() =>
            {
                CountHigh.Text = high.ToString();
                CountMed.Text  = med.ToString();
                CountOk.Text   = ok.ToString();
                CountFix.Text  = fix.ToString();
            });
        }

        private void SetButtonsEnabled(bool enabled)
        {
            Dispatcher.Invoke(() =>
            {
                FullScanBtn.IsEnabled  = enabled;
                ScanQuickBtn.IsEnabled = enabled;
                FirewallBtn.IsEnabled  = enabled;
                SshBtn.IsEnabled       = enabled;
                KernelBtn.IsEnabled    = enabled;
                RestoreBtn.IsEnabled   = enabled;
                lock (_findingsLock)
                {
                    AutoFixBtn.IsEnabled = enabled && _findings.Any(f => f.FixCmd != null && !f.Fixed);
                }
            });
        }

        // ═════════════════════════════════════════════════════════════════════
        // SCAN ENTRY POINTS
        // ═════════════════════════════════════════════════════════════════════

        private async void FullScan_Click(object sender, RoutedEventArgs e) => await RunScan(full: true);
        private async void ScanQuick_Click(object sender, RoutedEventArgs e) => await RunScan(full: false);
        private async void Firewall_Click(object sender, RoutedEventArgs e) => await RunSpecific(CheckFirewall);
        private async void Ssh_Click(object sender, RoutedEventArgs e)      => await RunSpecific(CheckRdpSsh);
        private async void Kernel_Click(object sender, RoutedEventArgs e)   => await RunSpecific(CheckRegistrySecurity);

        private async Task RunSpecific(Action check)
        {
            if (_scanning) return;
            _scanning = true;
            lock (_findingsLock) _findings.Clear();
            try
            {
                SetButtonsEnabled(false);
                SetStatus("SCANNING");
                await Task.Run(() => RunCheckSafely("Selected Check", check));
                FinalizeReport();
            }
            catch (Exception ex)
            {
                HandleScanFailure(ex);
            }
        }

        private async Task RunScan(bool full)
        {
            if (_scanning) return;
            _scanning = true;
            lock (_findingsLock) _findings.Clear();

            try
            {
                UpdateCounts();
                SetButtonsEnabled(false);
                SetStatus("SCANNING");
                Log(full ? "=== FULL SCAN INITIATED ===" : "=== QUICK SCAN INITIATED ===");

                var checks = full ? GetFullChecks() : GetQuickChecks();
                _totalChecks = checks.Count;
                _doneChecks  = 0;
                SetProgress(0, _totalChecks);

                foreach (var (label, check) in checks)
                {
                    Log($"Checking: {label}...");
                    await Task.Run(() => RunCheckSafely(label, check));
                    _doneChecks++;
                    SetProgress(_doneChecks, _totalChecks);
                }

                FinalizeReport();
            }
            catch (Exception ex)
            {
                HandleScanFailure(ex);
            }
        }

        private void RunCheckSafely(string label, Action check)
        {
            try
            {
                check();
            }
            catch (Exception ex)
            {
                Log($"{label} check crashed: {ex.Message}");
                AddFinding(new Finding
                {
                    Severity = Severity.Medium,
                    Category = "Scanner",
                    Title = $"{label} check could not complete",
                    Detail = ex.Message
                });
            }
        }

        private void HandleScanFailure(Exception ex)
        {
            Log($"Scan stopped unexpectedly: {ex.GetType().Name}: {ex.Message}");
            SetStatus("SCAN ERROR", red: true);
            _scanning = false;
            SetButtonsEnabled(true);
            WpfMsg.Show($"VulnGuard hit an error during the scan, but the app stayed open.\n\n{ex.Message}",
                        "VulnGuard Scan Error",
                        MessageBoxButton.OK);
        }

        private List<(string, Action)> GetQuickChecks() => new()
        {
            ("Defender / AV",         CheckDefender),
            ("Windows Updates",       CheckWindowsUpdate),
            ("Firewall",              CheckFirewall),
            ("Guest Account",         CheckGuestAccount),
            ("UAC Level",             CheckUac),
            ("RDP / SSH Exposure",    CheckRdpSsh),
            ("SMB Settings",          CheckSmb),
        };

        private List<(string, Action)> GetFullChecks() => new()
        {
            ("Defender / AV",         CheckDefender),
            ("Windows Updates",       CheckWindowsUpdate),
            ("Firewall",              CheckFirewall),
            ("Open Ports",            CheckOpenPorts),
            ("Guest Account",         CheckGuestAccount),
            ("UAC Level",             CheckUac),
            ("RDP / SSH Exposure",    CheckRdpSsh),
            ("SMB Settings",          CheckSmb),
            ("Registry Security",     CheckRegistrySecurity),
            ("Dangerous Services",    CheckDangerousServices),
            ("Auto-Login",            CheckAutoLogin),
            ("Audit Policy",          CheckAuditPolicy),
            ("Scheduled Tasks",       CheckScheduledTasks),
            ("World-Writable Paths",  CheckWorldWritable),
            ("BitLocker",             CheckBitLocker),
            ("Password Policy",       CheckPasswordPolicy),
        };

        private void FinalizeReport()
        {
            int high;
            int med;
            int fix;
            lock (_findingsLock)
            {
                high = _findings.Count(f => f.Severity == Severity.High);
                med  = _findings.Count(f => f.Severity == Severity.Medium);
                fix  = _findings.Count(f => f.FixCmd   != null);
            }

            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Log($"SCAN COMPLETE — HIGH: {high}  MED: {med}  FIXABLE: {fix}");

            string report = SaveReport();
            Log($"Report saved → {report}");
            Dispatcher.Invoke(() =>
            {
                LastScanLabel.Text   = $"LAST SCAN: {DateTime.Now:HH:mm dd/MM/yy}";
                ReportPathLabel.Text = report;
                AutoFixBtn.IsEnabled = fix > 0;
            });

            SetStatus(high > 0 ? "VULNERABLE" : med > 0 ? "WARNINGS" : "SECURE", red: high > 0);
            SetProgress(_totalChecks, _totalChecks);
            _scanning = false;
            SetButtonsEnabled(true);

            if (high > 0)
                WpfMsg.Show($"⬡ SCAN COMPLETE ⬡\n\n{high} HIGH severity issue(s) found.\n{fix} can be auto-patched.\n\nClick [ AUTO-PATCH ALL FIXABLE ISSUES ] to remediate.",
                            "VulnGuard", MessageBoxButton.OK);
        }

        // ═════════════════════════════════════════════════════════════════════
        // INDIVIDUAL CHECKS
        // ═════════════════════════════════════════════════════════════════════

        private void CheckDefender()
        {
            try
            {
                // Check via WMI/registry if Defender real-time protection is on
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                var rtpDisabled = key?.GetValue("DisableRealtimeMonitoring");
                bool disabled = rtpDisabled is int i && i == 1;

                if (disabled)
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Antivirus",
                        Title    = "Windows Defender real-time protection is DISABLED",
                        Detail   = "Your system has no active malware scanning.",
                        FixCmd   = "Set-MpPreference -DisableRealtimeMonitoring $false",
                        FixDesc  = "Re-enable Defender real-time protection"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Antivirus", Title = "Defender real-time protection is active" });

                // Check Defender last update
                using var defKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows Defender\Signature Updates");
                var lastUpdate = defKey?.GetValue("SignaturesLastUpdated");
                if (lastUpdate != null)
                {
                    // Stored as 8-byte FILETIME
                    if (lastUpdate is byte[] bytes && bytes.Length == 8)
                    {
                        long ft = BitConverter.ToInt64(bytes, 0);
                        var dt = DateTime.FromFileTime(ft);
                        if ((DateTime.Now - dt).TotalDays > 7)
                            AddFinding(new Finding
                            {
                                Severity = Severity.Medium,
                                Category = "Antivirus",
                                Title    = $"Defender signatures are {(int)(DateTime.Now - dt).TotalDays} days old",
                                Detail   = $"Last updated: {dt:dd/MM/yyyy}",
                                FixCmd   = "Update-MpSignature",
                                FixDesc  = "Force Defender signature update"
                            });
                        else
                            AddFinding(new Finding { Severity = Severity.Info, Category = "Antivirus", Title = $"Defender signatures up to date (last: {dt:dd/MM/yyyy})" });
                    }
                }
            }
            catch (Exception ex) { Log($"Defender check error: {ex.Message}"); }
        }

        private void CheckWindowsUpdate()
        {
            try
            {
                // Check if Windows Update service is disabled
                using var sc = new ServiceController("wuauserv");
                if (sc.StartType == ServiceStartMode.Disabled)
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Updates",
                        Title    = "Windows Update service is DISABLED",
                        Detail   = "System cannot receive security patches.",
                        FixCmd   = "Set-Service -Name wuauserv -StartupType Automatic; Start-Service wuauserv",
                        FixDesc  = "Re-enable Windows Update service"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Updates", Title = "Windows Update service is running" });

                // Check AU policy
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
                var noAuto = key?.GetValue("NoAutoUpdate");
                if (noAuto is int ni && ni == 1)
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Updates",
                        Title    = "Automatic updates are disabled via Group Policy",
                        Detail   = "NoAutoUpdate = 1 in registry.",
                        FixCmd   = "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue",
                        FixDesc  = "Remove NoAutoUpdate policy key"
                    });
            }
            catch (InvalidOperationException)
            {
                Log("Windows Update service not found (non-standard install?)");
            }
            catch (Exception ex) { Log($"Update check error: {ex.Message}"); }
        }

        private void CheckFirewall()
        {
            try
            {
                // Check each profile via netsh
                var result = RunCmd("netsh", "advfirewall show allprofiles state");
                bool allOn = true;
                foreach (var line in result.Split('\n'))
                {
                    if (line.Trim().StartsWith("State") && line.Contains("OFF"))
                    {
                        allOn = false;
                        break;
                    }
                }

                if (!allOn)
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Firewall",
                        Title    = "Windows Firewall is OFF on one or more profiles",
                        Detail   = result.Contains("OFF") ? "Domain/Private/Public profile(s) unprotected." : "",
                        FixCmd   = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
                        FixDesc  = "Enable firewall on all profiles"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Firewall", Title = "Windows Firewall is ON for all profiles" });

                // Check default inbound policy
                bool inboundBlock = result.Contains("Block") || result.Contains("block");
                if (!inboundBlock)
                    AddFinding(new Finding
                    {
                        Severity = Severity.Medium,
                        Category = "Firewall",
                        Title    = "Firewall default inbound policy may allow connections",
                        Detail   = "Recommended: default deny inbound.",
                        FixCmd   = "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block",
                        FixDesc  = "Set default inbound action to Block"
                    });
            }
            catch (Exception ex) { Log($"Firewall check error: {ex.Message}"); }
        }

        private void CheckOpenPorts()
        {
            try
            {
                var dangerous = new Dictionary<int, (string name, string reason, Severity sev)>
                {
                    [21]    = ("FTP",           "Cleartext file transfer — use SFTP instead",           Severity.High),
                    [23]    = ("Telnet",         "Cleartext remote shell — extremely dangerous",         Severity.High),
                    [135]   = ("MS-RPC",         "Exposed — attack surface for RPC exploits",            Severity.Medium),
                    [139]   = ("NetBIOS",         "Legacy SMB — disable if not needed",                  Severity.Medium),
                    [445]   = ("SMB",             "EternalBlue/WannaCry vector — restrict carefully",    Severity.Medium),
                    [1433]  = ("SQL Server",      "Database port exposed to network",                    Severity.High),
                    [3306]  = ("MySQL",           "Database port exposed to network",                    Severity.High),
                    [3389]  = ("RDP",             "Remote Desktop — brute-force / BlueKeep target",     Severity.High),
                    [5900]  = ("VNC",             "Often weakly authenticated remote desktop",           Severity.High),
                    [6379]  = ("Redis",           "No auth by default — full data access",               Severity.High),
                    [27017] = ("MongoDB",         "No auth by default — full data access",               Severity.High),
                };

                var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
                bool foundAny = false;
                foreach (var ep in listeners)
                {
                    if (dangerous.TryGetValue(ep.Port, out var info))
                    {
                        foundAny = true;
                        AddFinding(new Finding
                        {
                            Severity = info.sev,
                            Category = "Ports",
                            Title    = $"Port {ep.Port} ({info.name}) is listening",
                            Detail   = info.reason,
                            FixDesc  = $"Disable {info.name} service or restrict via firewall"
                        });
                    }
                }
                if (!foundAny)
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Ports", Title = "No high-risk ports detected listening" });
            }
            catch (Exception ex) { Log($"Port check error: {ex.Message}"); }
        }

        private void CheckGuestAccount()
        {
            try
            {
                var result = RunCmd("net", "user Guest");
                bool active = result.Contains("Account active               Yes") ||
                              result.Contains("Account active               YES");
                if (active)
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Accounts",
                        Title    = "Guest account is ACTIVE",
                        Detail   = "Guest account allows unauthenticated access.",
                        FixCmd   = "net user Guest /active:no",
                        FixDesc  = "Disable Guest account"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Accounts", Title = "Guest account is disabled" });
            }
            catch (Exception ex) { Log($"Guest check error: {ex.Message}"); }
        }

        private void CheckUac()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                var uacEnabled = key?.GetValue("EnableLUA");
                var consent    = key?.GetValue("ConsentPromptBehaviorAdmin");

                if (uacEnabled is int u && u == 0)
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "UAC",
                        Title    = "UAC (User Account Control) is DISABLED",
                        Detail   = "All processes run with admin rights without prompting.",
                        FixCmd   = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord",
                        FixDesc  = "Re-enable UAC"
                    });
                else if (consent is int c && c == 0)
                    AddFinding(new Finding
                    {
                        Severity = Severity.Medium,
                        Category = "UAC",
                        Title    = "UAC set to 'Never notify' (silent elevation)",
                        Detail   = "Admin actions happen with no user prompt.",
                        FixCmd   = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord",
                        FixDesc  = "Set UAC to prompt on admin actions"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "UAC", Title = "UAC is enabled and configured" });
            }
            catch (Exception ex) { Log($"UAC check error: {ex.Message}"); }
        }

        private void CheckRdpSsh()
        {
            try
            {
                // RDP
                using var rdpKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server");
                var deny = rdpKey?.GetValue("fDenyTSConnections");
                bool rdpEnabled = deny is int d && d == 0;
                if (rdpEnabled)
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Remote Access",
                        Title    = "Remote Desktop (RDP) is ENABLED",
                        Detail   = "Port 3389 is open — BlueKeep / brute-force risk. Restrict to VPN only.",
                        FixCmd   = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Type DWord",
                        FixDesc  = "Disable RDP (or restrict via firewall to trusted IPs only)"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Remote Access", Title = "RDP is disabled" });

                // NLA required for RDP?
                using var nlaKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
                var nla = nlaKey?.GetValue("UserAuthentication");
                if (rdpEnabled && nla is int n && n == 0)
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Remote Access",
                        Title    = "RDP Network Level Authentication (NLA) is DISABLED",
                        Detail   = "NLA forces auth before session creation — required for security.",
                        FixCmd   = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord",
                        FixDesc  = "Enable NLA for RDP"
                    });

                // OpenSSH
                var sshListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
                bool sshOpen = sshListeners.Any(ep => ep.Port == 22);
                if (sshOpen)
                    AddFinding(new Finding
                    {
                        Severity = Severity.Medium,
                        Category = "Remote Access",
                        Title    = "OpenSSH server is listening on port 22",
                        Detail   = "Ensure key-based auth only and root login disabled.",
                        FixDesc  = "Edit %ProgramData%\\ssh\\sshd_config — set PasswordAuthentication no, PermitRootLogin no"
                    });
            }
            catch (Exception ex) { Log($"RDP/SSH check error: {ex.Message}"); }
        }

        private void CheckSmb()
        {
            try
            {
                // SMBv1 — WannaCry vector
                var result = RunPowerShell("(Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol').State");
                if (result.Contains("Enabled") || result.Contains("enabled"))
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Network",
                        Title    = "SMBv1 is ENABLED — EternalBlue / WannaCry vulnerability",
                        Detail   = "SMBv1 is the protocol exploited by WannaCry ransomware.",
                        FixCmd   = "Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart",
                        FixDesc  = "Disable SMBv1 (requires reboot)"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Network", Title = "SMBv1 is disabled" });

                // NetBIOS
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces");
                if (key != null)
                {
                    bool anyEnabled = false;
                    foreach (var sub in key.GetSubKeyNames())
                    {
                        using var sk = key.OpenSubKey(sub);
                        var nb = sk?.GetValue("NetbiosOptions");
                        if (nb is int v && v == 0) { anyEnabled = true; break; }
                    }
                    if (anyEnabled)
                        AddFinding(new Finding
                        {
                            Severity = Severity.Medium,
                            Category = "Network",
                            Title    = "NetBIOS over TCP/IP enabled (legacy broadcast protocol)",
                            Detail   = "NetBIOS leaks hostname and workgroup info — disable if not needed.",
                            FixDesc  = "Network adapter settings → Advanced → NetBIOS → Disable"
                        });
                    else
                        AddFinding(new Finding { Severity = Severity.Info, Category = "Network", Title = "NetBIOS over TCP/IP is disabled" });
                }
            }
            catch (Exception ex) { Log($"SMB check error: {ex.Message}"); }
        }

        private void CheckRegistrySecurity()
        {
            try
            {
                var checks = new (string path, string name, int badVal, Severity sev, string title, string detail, string fixVal)[]
                {
                    (@"SYSTEM\CurrentControlSet\Control\Lsa",
                     "LmCompatibilityLevel", -1, // expect >= 3
                     Severity.High,
                     "LAN Manager auth level too low (NTLMv1 allowed)",
                     "LmCompatibilityLevel < 3 allows weak NTLMv1 authentication.",
                     "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord"),

                    (@"SYSTEM\CurrentControlSet\Control\Lsa",
                     "RestrictAnonymous", 0,
                     Severity.Medium,
                     "Anonymous enumeration of SAM accounts is allowed",
                     "RestrictAnonymous = 0 lets anyone list user accounts.",
                     "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -Value 1 -Type DWord"),

                    (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                     "AutoAdminLogon", 1, // 1 = bad
                     Severity.High,
                     "Auto-login is ENABLED (password stored in registry)",
                     "AutoAdminLogon = 1 stores credentials in plaintext registry.",
                     "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'AutoAdminLogon' -Value 0 -Type DWord"),

                    (@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                     "EnableMulticast", 1, // 1 = LLMNR on = bad
                     Severity.Medium,
                     "LLMNR (Link-Local Multicast Name Resolution) is enabled",
                     "LLMNR can be spoofed to capture credentials (Responder attack).",
                     "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord"),
                };

                foreach (var (path, name, badVal, sev, title, detail, fixCmd) in checks)
                {
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(path);
                        var val = key?.GetValue(name);

                        bool isBad;
                        if (badVal == -1) // special: check < 3 for NTLMv1
                            isBad = val is int lm && lm < 3;
                        else
                            isBad = val is int v && v == badVal;

                        if (isBad)
                            AddFinding(new Finding { Severity = sev, Category = "Registry", Title = title, Detail = detail, FixCmd = fixCmd, FixDesc = $"Set {name} to secure value" });
                        else
                            AddFinding(new Finding { Severity = Severity.Info, Category = "Registry", Title = $"OK: {title}" });
                    }
                    catch { /* key may not exist — skip */ }
                }
            }
            catch (Exception ex) { Log($"Registry check error: {ex.Message}"); }
        }

        private void CheckAutoLogin()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                var autoLogin = key?.GetValue("AutoAdminLogon")?.ToString();
                var pw        = key?.GetValue("DefaultPassword")?.ToString();

                if (autoLogin == "1")
                    AddFinding(new Finding
                    {
                        Severity = Severity.High,
                        Category = "Accounts",
                        Title    = "Auto-login is enabled — credentials stored in registry",
                        Detail   = string.IsNullOrEmpty(pw) ? "Password may be stored." : "Password IS stored in plaintext.",
                        FixCmd   = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'AutoAdminLogon' -Value '0'; Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue",
                        FixDesc  = "Disable auto-login and remove stored password"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Accounts", Title = "Auto-login is not configured" });
            }
            catch (Exception ex) { Log($"Auto-login check error: {ex.Message}"); }
        }

        private void CheckDangerousServices()
        {
            var dangerous = new[]
            {
                ("RemoteRegistry",  "Remote Registry",   "Allows remote registry editing",                          Severity.High),
                ("Telnet",          "Telnet Server",     "Cleartext remote shell — disable immediately",            Severity.High),
                ("TlntSvr",         "Telnet Server Alt", "Cleartext remote shell",                                  Severity.High),
                ("SNMP",            "SNMP Service",      "Often misconfigured, leaks system info",                  Severity.Medium),
                ("Spooler",         "Print Spooler",     "PrintNightmare vulnerability on non-print servers",       Severity.Medium),
            };

            foreach (var (svcName, svcLabel, reason, sev) in dangerous)
            {
                try
                {
                    using var sc = new ServiceController(svcName);
                    if (sc.Status == ServiceControllerStatus.Running)
                        AddFinding(new Finding
                        {
                            Severity = sev,
                            Category = "Services",
                            Title    = $"Service '{svcLabel}' is running",
                            Detail   = reason,
                            FixCmd   = $"Stop-Service -Name '{svcName}' -Force; Set-Service -Name '{svcName}' -StartupType Disabled",
                            FixDesc  = $"Stop and disable {svcLabel}"
                        });
                    else
                        AddFinding(new Finding { Severity = Severity.Info, Category = "Services", Title = $"Service '{svcLabel}' is stopped/disabled" });
                }
                catch (InvalidOperationException) { /* service not installed — fine */ }
                catch (Exception ex) { Log($"Service check ({svcName}) error: {ex.Message}"); }
            }
        }

        private void CheckAuditPolicy()
        {
            try
            {
                var result = RunCmd("auditpol", "/get /category:*");
                bool auditLogon = result.Contains("Logon") && result.Contains("Success and Failure");
                if (!auditLogon)
                    AddFinding(new Finding
                    {
                        Severity = Severity.Medium,
                        Category = "Audit",
                        Title    = "Logon audit policy not fully configured",
                        Detail   = "Logon success and failure events should be logged.",
                        FixCmd   = "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable",
                        FixDesc  = "Enable logon success+failure auditing"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Audit", Title = "Logon audit policy is configured" });
            }
            catch (Exception ex) { Log($"Audit check error: {ex.Message}"); }
        }

        private void CheckScheduledTasks()
        {
            try
            {
                var result = RunPowerShell(
                    "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | Select-Object -ExpandProperty TaskName | ConvertTo-Json");
                if (result.Length > 10)
                {
                    var tasks = result.Trim('[', ']').Split(',').Select(t => t.Trim(' ', '"', '\r', '\n')).Where(t => t.Length > 0).ToList();
                    if (tasks.Count > 0)
                        AddFinding(new Finding
                        {
                            Severity = Severity.Medium,
                            Category = "Tasks",
                            Title    = $"{tasks.Count} non-Microsoft scheduled task(s) found",
                            Detail   = string.Join(", ", tasks.Take(8)) + (tasks.Count > 8 ? "..." : ""),
                            FixDesc  = "Review each task in Task Scheduler — remove anything unrecognised"
                        });
                    else
                        AddFinding(new Finding { Severity = Severity.Info, Category = "Tasks", Title = "No unexpected scheduled tasks found" });
                }
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Tasks", Title = "No unexpected scheduled tasks found" });
            }
            catch (Exception ex) { Log($"Scheduled task check error: {ex.Message}"); }
        }

        private void CheckWorldWritable()
        {
            try
            {
                // Check common writable-by-everyone paths
                var paths = new[] {
                    @"C:\Windows\Temp",
                    @"C:\Temp",
                    @"C:\Users\Public",
                    @"C:\ProgramData",
                };
                var writableByAll = new List<string>();
                foreach (var p in paths)
                {
                    if (!Directory.Exists(p)) continue;
                    try
                    {
                        var acl = new System.Security.AccessControl.DirectorySecurity(p,
                            System.Security.AccessControl.AccessControlSections.Access);
                        var rules = acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                        foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
                        {
                            // SID S-1-1-0 = Everyone
                            if (rule.IdentityReference.Value == "S-1-1-0" &&
                                rule.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.Write))
                            {
                                writableByAll.Add(p);
                                break;
                            }
                        }
                    }
                    catch { /* no permission to read ACL */ }
                }
                if (writableByAll.Any())
                    AddFinding(new Finding
                    {
                        Severity = Severity.Medium,
                        Category = "Filesystem",
                        Title    = $"{writableByAll.Count} path(s) writable by Everyone",
                        Detail   = string.Join(", ", writableByAll),
                        FixDesc  = "Remove Everyone write access from system directories"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Filesystem", Title = "No unexpected world-writable system paths" });
            }
            catch (Exception ex) { Log($"World-writable check error: {ex.Message}"); }
        }

        private void CheckBitLocker()
        {
            try
            {
                var result = RunPowerShell(
                    "(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus");
                if (result.Contains("Off") || result.Trim() == "" || result.Contains("0"))
                    AddFinding(new Finding
                    {
                        Severity = Severity.Medium,
                        Category = "Encryption",
                        Title    = "BitLocker is NOT enabled on C:",
                        Detail   = "Drive encryption protects data if the device is stolen.",
                        FixDesc  = "Enable BitLocker via Control Panel → BitLocker Drive Encryption"
                    });
                else
                    AddFinding(new Finding { Severity = Severity.Info, Category = "Encryption", Title = "BitLocker is active on C:" });
            }
            catch (Exception ex) { Log($"BitLocker check error: {ex.Message}"); }
        }

        private void CheckPasswordPolicy()
        {
            try
            {
                var result = RunCmd("net", "accounts");
                // Minimum password length
                var lenLine = result.Split('\n').FirstOrDefault(l => l.Contains("Minimum password length"));
                if (lenLine != null)
                {
                    var parts = lenLine.Split(':');
                    if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out int len))
                    {
                        if (len < 8)
                            AddFinding(new Finding
                            {
                                Severity = Severity.High,
                                Category = "Accounts",
                                Title    = $"Minimum password length = {len} (too short)",
                                Detail   = "At least 12 characters recommended.",
                                FixCmd   = "net accounts /MINPWLEN:12",
                                FixDesc  = "Set minimum password length to 12"
                            });
                        else
                            AddFinding(new Finding { Severity = Severity.Info, Category = "Accounts", Title = $"Minimum password length = {len} (ok)" });
                    }
                }

                // Max password age
                var ageLine = result.Split('\n').FirstOrDefault(l => l.Contains("Maximum password age"));
                if (ageLine != null)
                {
                    var parts = ageLine.Split(':');
                    if (parts.Length > 1)
                    {
                        var ageStr = parts[1].Trim();
                        if (ageStr.Contains("Unlimited") || ageStr == "0")
                            AddFinding(new Finding
                            {
                                Severity = Severity.Medium,
                                Category = "Accounts",
                                Title    = "Maximum password age is Unlimited",
                                Detail   = "Passwords never expire — rotate periodically.",
                                FixCmd   = "net accounts /MAXPWAGE:90",
                                FixDesc  = "Set max password age to 90 days"
                            });
                    }
                }
            }
            catch (Exception ex) { Log($"Password policy check error: {ex.Message}"); }
        }

        // ═════════════════════════════════════════════════════════════════════
        // AUTO-FIX
        // ═════════════════════════════════════════════════════════════════════

        private async void AutoFix_Click(object sender, RoutedEventArgs e)
        {
            var fixable = _findings.Where(f => f.FixCmd != null && !f.Fixed).ToList();
            if (!fixable.Any()) { WpfMsg.Show("Nothing to fix!"); return; }

            var list = string.Join("\n", fixable.Select(f => $"• {f.Title}"));
            var res  = WpfMsg.Show(
                $"⬡ AUTO-PATCH ⬡\n\nWill apply {fixable.Count} fix(es):\n\n{list}\n\nProceed?",
                "VulnGuard Auto-Patch",
                MessageBoxButton.YesNo);

            if (res != MessageBoxResult.Yes) return;

            SetButtonsEnabled(false);
            SetStatus("PATCHING");
            Log("=== AUTO-PATCH INITIATED ===");

            int ok = 0, fail = 0;
            foreach (var f in fixable)
            {
                Log($"Applying: {f.Title}...");
                bool success = await Task.Run(() => ApplyFix(f.FixCmd!));
                if (success) { f.Fixed = true; ok++;   Log("✓ Applied."); }
                else         {                  fail++; Log("✗ Failed (may need admin)."); }
            }

            Log($"=== PATCH COMPLETE — Applied: {ok}  Failed: {fail} ===");
            SetStatus(fail == 0 ? "PATCHED" : "PARTIAL", red: fail > 0);
            SetButtonsEnabled(true);
            WpfMsg.Show($"⬡ PATCH COMPLETE ⬡\n\nApplied: {ok}\nFailed:  {fail}\n\n{(fail > 0 ? "Run as Administrator for full access." : "All fixes applied successfully.")}");
        }

        private bool ApplyFix(string psCmd)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName        = "powershell.exe",
                    Arguments       = $"-NonInteractive -Command \"{psCmd.Replace("\"", "\\\"")}\"",
                    Verb            = "runas",
                    UseShellExecute = true,
                    WindowStyle     = ProcessWindowStyle.Hidden,
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(30_000);
                return p?.ExitCode == 0;
            }
            catch { return false; }
        }

        // ═════════════════════════════════════════════════════════════════════
        // RESTORE DEFAULTS
        // ═════════════════════════════════════════════════════════════════════

        private async void Restore_Click(object sender, RoutedEventArgs e)
        {
            var res = WpfMsg.Show(
                "⬡ RESTORE DEFAULTS ⬡\n\n" +
                "This will restore:\n" +
                "• Windows Firewall → ON\n" +
                "• Windows Update  → ON\n" +
                "• Defender        → ON\n" +
                "• UAC             → ON\n" +
                "• SMBv1           → OFF (stays disabled — safer)\n\n" +
                "Are you sure?",
                "Restore Defaults",
                MessageBoxButton.YesNo);

            if (res != MessageBoxResult.Yes) return;

            SetButtonsEnabled(false);
            SetStatus("RESTORING");
            Log("=== RESTORE INITIATED ===");

            await Task.Run(() =>
            {
                ApplyFix("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True");
                Log("Firewall restored.");
                ApplyFix("Set-Service -Name wuauserv -StartupType Automatic; Start-Service wuauserv -ErrorAction SilentlyContinue");
                Log("Windows Update restored.");
                ApplyFix("Set-MpPreference -DisableRealtimeMonitoring $false");
                Log("Defender restored.");
                ApplyFix("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord");
                Log("UAC restored.");
            });

            Log("=== RESTORE COMPLETE ===");
            SetStatus("IDLE");
            SetButtonsEnabled(true);
            WpfMsg.Show("✓ Defaults restored.\n\nRun a fresh scan to verify system status.", "VulnGuard");
        }

        // ═════════════════════════════════════════════════════════════════════
        // REPORT
        // ═════════════════════════════════════════════════════════════════════

        private string SaveReport()
        {
            List<Finding> findings;
            lock (_findingsLock)
            {
                findings = _findings.ToList();
            }

            var sb = new StringBuilder();
            sb.AppendLine("=== VULNGUARD SCAN REPORT ===");
            sb.AppendLine($"Timestamp : {DateTime.Now:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"Machine   : {Environment.MachineName}");
            sb.AppendLine($"User      : {Environment.UserName}");
            sb.AppendLine($"OS        : {Environment.OSVersion}");
            sb.AppendLine();
            sb.AppendLine("FINDINGS:");
            sb.AppendLine("─────────────────────────────────────────");
            foreach (var f in findings.OrderBy(x => x.Severity))
            {
                sb.AppendLine($"[{f.Severity.ToString().ToUpper()}] [{f.Category}] {f.Title}");
                if (!string.IsNullOrEmpty(f.Detail)) sb.AppendLine($"  Detail: {f.Detail}");
                if (f.FixCmd != null) sb.AppendLine($"  Fix:    {f.FixCmd}");
                sb.AppendLine();
            }
            sb.AppendLine("─────────────────────────────────────────");
            sb.AppendLine($"HIGH: {findings.Count(f=>f.Severity==Severity.High)}  MED: {findings.Count(f=>f.Severity==Severity.Medium)}  PASS: {findings.Count(f=>f.Severity==Severity.Info)}");

            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"VulnGuard_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            try { File.WriteAllText(path, sb.ToString()); }
            catch
            {
                try
                {
                    path = Path.Combine(Path.GetTempPath(), Path.GetFileName(path));
                    File.WriteAllText(path, sb.ToString());
                }
                catch
                {
                    path = "(report could not be saved)";
                }
            }
            return path;
        }

        // ═════════════════════════════════════════════════════════════════════
        // HELPERS
        // ═════════════════════════════════════════════════════════════════════

        private static string RunCmd(string exe, string args)
        {
            return RunProcessOutput(exe, args, 10_000);
        }

        private static string RunPowerShell(string script)
        {
            return RunProcessOutput(
                "powershell.exe",
                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "\\\"")}\"",
                15_000);
        }

        private static string RunProcessOutput(string exe, string args, int timeoutMs)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true
            };

            using var p = Process.Start(psi);
            if (p == null) return "";

            var outputTask = p.StandardOutput.ReadToEndAsync();
            var errorTask = p.StandardError.ReadToEndAsync();

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); }
                catch { }
                return $"Command timed out: {exe} {args}";
            }

            Task.WaitAll(new Task[] { outputTask, errorTask }, 2_000);
            var output = outputTask.IsCompletedSuccessfully ? outputTask.Result : "";
            var error = errorTask.IsCompletedSuccessfully ? errorTask.Result : "";

            return string.IsNullOrWhiteSpace(error)
                ? output
                : output + Environment.NewLine + error;
        }
    }
}
