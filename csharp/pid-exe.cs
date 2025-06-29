using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

public class Program
{
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_SET_INFORMATION = 0x0200;
    public const int PROCESS_SUSPEND_RESUME = 0x0800;

    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_READWRITE = 0x04;

    public const int INVALID_HANDLE_VALUE = -1;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void Sleep(uint dwMilliseconds);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    public static void FatalError(string msg, int exitCode)
    {
        Console.Error.WriteLine($"[!] FATAL Error: {msg} Error Code: {Marshal.GetLastWin32Error()}");
        Environment.Exit(exitCode);
    }

    public static void WriteRemoteMemory(IntPtr procHandle, IntPtr addr, byte[] data, string errorMsg, Action cleanup)
    {
        if (!WriteProcessMemory(procHandle, addr, data, data.Length, out IntPtr _))
        {
            cleanup?.Invoke();
            FatalError(errorMsg, Marshal.GetLastWin32Error());
        }
    }

    public static void ReadRemoteMemory(IntPtr procHandle, IntPtr addr, byte[] buffer, string errorMsg, Action cleanup)
    {
        if (!ReadProcessMemory(procHandle, addr, buffer, buffer.Length, out IntPtr _))
        {
            cleanup?.Invoke();
            FatalError(errorMsg, Marshal.GetLastWin32Error());
        }
    }

    public const int OFF_ADDRBLACKLISTSTR_PTR = 0x00DB;
    public const int OFF_COMPAREWIDESTRINGS = 0x0000;
    public const int OFF_ORIGINAL_LDRLOADDLL_PROLOGUE = 0x00E3;
    public const int OFF_REALLOADLIBRARY_PTR = 0x00D3;
    public const int OFF_REHOOK_JMP_TO_REMOTESTUB = 0x00EF;
    public const int OFF_REMOTESTUB = 0x0026;

    public const int STUB_FIXED_DATA_SIZE = 0x28;
    public const int STUB_TOTAL_STATIC_SIZE = 0xFB;

    public const int G_REMOTE_STUB_SIZE = 251;
    public static readonly byte[] G_REMOTE_STUB_BYTES = new byte[]
    {
        0x53, 0x0F, 0xB7, 0x01, 0x0F, 0xB7, 0x1A, 0x66, 0x3B, 0xC3, 0x75, 0x13, 0x66, 0x85, 0xC0, 0x74,
        0x0A, 0x48, 0x83, 0xC1, 0x02, 0x48, 0x83, 0xC2, 0x02, 0xEB, 0xE6, 0x33, 0xC0, 0xEB, 0x05, 0xB8,
        0x01, 0x00, 0x00, 0x00, 0x5B, 0xC3, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x40, 0x53, 0x56,
        0x57, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x48, 0x8D, 0x35, 0xA5, 0x00, 0x00, 0x00, 0x48, 0x8D,
        0x3D, 0x8E, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x3F, 0x48, 0xC7, 0xC1, 0x0C, 0x00, 0x00, 0x00, 0xFC,
        0xF3, 0xA4, 0x48, 0x8B, 0x74, 0x24, 0x08, 0x48, 0x8B, 0x76, 0x08, 0x48, 0x8D, 0x1D, 0x79, 0x00,
        0x00, 0x00, 0x48, 0x8B, 0x1B, 0x48, 0x8B, 0x3B, 0x48, 0x83, 0xFF, 0x00, 0x74, 0x26, 0x56, 0x48,
        0x8B, 0x0C, 0x24, 0x48, 0x8B, 0xD7, 0xE8, 0x85, 0xFF, 0xFF, 0xFF, 0x5E, 0x83, 0xF8, 0x00, 0x74,
        0x06, 0x48, 0x83, 0xC3, 0x08, 0xEB, 0xDE, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0xB8, 0x22, 0x00,
        0x00, 0xC0, 0xEB, 0x1B, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x8D,
        0x05, 0x2E, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x08, 0x50, 0x48,
        0x8D, 0x3D, 0x1D, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x3F, 0x48, 0x8D, 0x35, 0x2F, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC1, 0x0C, 0x00, 0x00, 0x00, 0xFC, 0xF3, 0xA4, 0x58, 0x5F, 0x5E, 0x5B, 0x48, 0x8B,
        0xE5, 0x5D, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    private static byte[] g_originalLdrLoadDllPrologue = new byte[12];
    private static byte[] g_originalDbgUiTargetPrologue = new byte[12];
    private static IntPtr g_addrLdrLoadDllLocal = IntPtr.Zero;
    private static IntPtr g_addrDbgUiHookTarget = IntPtr.Zero;
    private static IntPtr g_procHandle = IntPtr.Zero;

    private static uint g_oldProtectionDbgUi = 0;
    private static uint g_oldProtectLdrLoadDll = 0;

    private static void PrintBytes(string label, byte[] data, int size)
    {
        Console.WriteLine($"{label} (Size: {size} bytes):");
        for (int i = 0; i < size; ++i)
        {
            Console.Write($"{data[i]:X2} ");
            if ((i + 1) % 16 == 0)
            {
                Console.WriteLine();
            }
        }
        Console.WriteLine();
    }

    private static List<string> ReadBlacklistFromFile(string filename)
    {
        List<string> blacklistStrings = new List<string>();
        if (!File.Exists(filename))
        {
            Console.Error.WriteLine($"[!] Error: Could not find blacklist file: {filename}. Make sure it exists.");
            return blacklistStrings;
        }

        Console.WriteLine($"[+] Blacklist loaded from '{filename}':");
        try
        {
            foreach (string line in File.ReadAllLines(filename, Encoding.UTF8))
            {
                string trimmedLine = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmedLine)) continue;

                blacklistStrings.Add(trimmedLine);
                Console.WriteLine($"    - {trimmedLine}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] Error reading blacklist file: {ex.Message}");
            return new List<string>();
        }

        if (blacklistStrings.Count == 0)
        {
            Console.WriteLine("[+] Blacklist file was read, but no valid entries were found.");
        }
        return blacklistStrings;
    }

    private static void PerformCleanup()
    {
        Console.WriteLine("[+] Initiating cleanup: Restoring LdrLoadDll and DbgUi function, closing handles...");

        if (g_procHandle != IntPtr.Zero && g_procHandle != new IntPtr(INVALID_HANDLE_VALUE))
        {
            if (g_addrLdrLoadDllLocal != IntPtr.Zero && g_originalLdrLoadDllPrologue.Length > 0)
            {
                uint tempOldProtectLdrLoadDll = 0;
                if (!VirtualProtectEx(g_procHandle, g_addrLdrLoadDllLocal, g_originalLdrLoadDllPrologue.Length, PAGE_EXECUTE_READWRITE, out tempOldProtectLdrLoadDll))
                {
                    Console.WriteLine($"[!] Warning: Failed to change LdrLoadDll protection for unhook: {Marshal.GetLastWin32Error()}");
                }
                if (!WriteProcessMemory(g_procHandle, g_addrLdrLoadDllLocal, g_originalLdrLoadDllPrologue, g_originalLdrLoadDllPrologue.Length, out IntPtr _))
                {
                    Console.WriteLine($"[!] Error: Failed to unhook LdrLoadDll: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    Console.WriteLine("[+] LdrLoadDll unhooked successfully.");
                }
                if (!VirtualProtectEx(g_procHandle, g_addrLdrLoadDllLocal, g_originalLdrLoadDllPrologue.Length, g_oldProtectLdrLoadDll, out tempOldProtectLdrLoadDll))
                {
                    Console.WriteLine($"[!] Warning: Failed to restore original protection on LdrLoadDll after unhook: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    Console.WriteLine("[+] Original memory protection restored on LdrLoadDll.");
                }
            }

            if (g_addrDbgUiHookTarget != IntPtr.Zero && g_originalDbgUiTargetPrologue.Length > 0)
            {
                uint tempOldProtectDbgUiTarget = 0;
                if (!VirtualProtectEx(g_procHandle, g_addrDbgUiHookTarget, g_originalDbgUiTargetPrologue.Length, PAGE_EXECUTE_READWRITE, out tempOldProtectDbgUiTarget))
                {
                    Console.WriteLine($"[!] Warning: Failed to change DbgUi target protection for unhook: {Marshal.GetLastWin32Error()}");
                }
                if (!WriteProcessMemory(g_procHandle, g_addrDbgUiHookTarget, g_originalDbgUiTargetPrologue, g_originalDbgUiTargetPrologue.Length, out IntPtr _))
                {
                    Console.WriteLine($"[!] Error: Failed to restore DbgUi target function: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    Console.WriteLine($"[+] DbgUi target function (0x{g_addrDbgUiHookTarget:X}) restored successfully.");
                }
                if (!VirtualProtectEx(g_procHandle, g_addrDbgUiHookTarget, g_originalDbgUiTargetPrologue.Length, g_oldProtectionDbgUi, out tempOldProtectDbgUiTarget))
                {
                    Console.WriteLine($"[!] Warning: Failed to restore original protection on DbgUi target after unhook: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    Console.WriteLine("[+] Original memory protection restored on DbgUi target.");
                }
            }
            CloseHandle(g_procHandle);
            Console.WriteLine("[+] Process handle closed.");
            g_procHandle = IntPtr.Zero;
        }
        else
        {
            Console.WriteLine("[+] No process handle to close or it was already closed.");
        }
    }


    public static void Main(string[] args)
    {
        uint targetPid = 0;
        int unhookDelay = 0;

        Action printUsage = () =>
        {
            Console.WriteLine($"Usage: {AppDomain.CurrentDomain.FriendlyName} -pid <process_id> [-unhook <seconds>]");
        };

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("-pid", StringComparison.OrdinalIgnoreCase))
            {
                if (++i < args.Length && uint.TryParse(args[i], out targetPid))
                {
                }
                else
                {
                    Console.Error.WriteLine("[!] Error: -pid requires a process ID.");
                    printUsage();
                    Environment.Exit(1);
                }
            }
            else if (args[i].Equals("-unhook", StringComparison.OrdinalIgnoreCase))
            {
                if (++i < args.Length && int.TryParse(args[i], out unhookDelay))
                {
                    if (unhookDelay <= 0)
                    {
                        Console.Error.WriteLine("[!] Error: -unhook requires a positive integer for seconds.");
                        Environment.Exit(1);
                    }
                }
                else
                {
                    Console.Error.WriteLine("[!] Error: -unhook requires a time in seconds.");
                    printUsage();
                    Environment.Exit(1);
                }
            }
            else
            {
                Console.Error.WriteLine($"[!] Error: Unknown argument: {args[i]}");
                printUsage();
                Environment.Exit(1);
            }
        }

        if (targetPid == 0)
        {
            Console.Error.WriteLine("[!] Error: Please specify a target process ID using -pid.");
            printUsage();
            Environment.Exit(1);
        }

        Console.WriteLine($"[+] Attempting to attach to existing process with PID: {targetPid}...");
        g_procHandle = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME,
            false,
            targetPid
        );

        if (g_procHandle == IntPtr.Zero)
        {
            FatalError("OpenProcess failed. Ensure you have sufficient permissions (e.g., Run as Administrator).", Marshal.GetLastWin32Error());
        }
        Console.WriteLine($"[+] Successfully attached to process with PID: {targetPid}.");

        IntPtr hNtdll = GetModuleHandle("ntdll.dll");
        if (hNtdll == IntPtr.Zero) FatalError("GetModuleHandle failed for ntdll.dll", Marshal.GetLastWin32Error());

        g_addrLdrLoadDllLocal = GetProcAddress(hNtdll, "LdrLoadDll");
        if (g_addrLdrLoadDllLocal == IntPtr.Zero) FatalError("GetProcAddress failed for LdrLoadDll", Marshal.GetLastWin32Error());
        Console.WriteLine($"[+] ntdll.dll base: 0x{hNtdll:X}. LdrLoadDll entry: 0x{g_addrLdrLoadDllLocal:X}.");

        g_addrDbgUiHookTarget = GetProcAddress(hNtdll, "DbgUiConvertStateChangeStructureEx");
        if (g_addrDbgUiHookTarget == IntPtr.Zero) FatalError("GetProcAddress failed for DbgUiConvertStateChangeStructureEx", Marshal.GetLastWin32Error());
        Console.WriteLine($"[+] ntdll.dll base: 0x{hNtdll:X}. DbgUiConvertStateChangeStructureEx entry: 0x{g_addrDbgUiHookTarget:X}.");

        ReadRemoteMemory(g_procHandle, g_addrLdrLoadDllLocal, g_originalLdrLoadDllPrologue,
            "Failed to read original LdrLoadDll prologue", PerformCleanup);
        PrintBytes("Original LdrLoadDll Prologue", g_originalLdrLoadDllPrologue, g_originalLdrLoadDllPrologue.Length);

        ReadRemoteMemory(g_procHandle, g_addrDbgUiHookTarget, g_originalDbgUiTargetPrologue,
            "Failed to read original DbgUi target prologue", PerformCleanup);
        PrintBytes("Original DbgUi Target Prologue (first 12 bytes)", g_originalDbgUiTargetPrologue, g_originalDbgUiTargetPrologue.Length);

        List<string> blacklistWStringsStorage = ReadBlacklistFromFile("blacklist.txt");
        if (blacklistWStringsStorage.Count == 0)
        {
            FatalError("No DLL names found in blacklist.txt or file could not be read. Exiting.", -50);
        }

        long remoteBlacklistStringsDataSize = 0;
        foreach (string ws in blacklistWStringsStorage)
        {
            remoteBlacklistStringsDataSize += (ws.Length + 1) * sizeof(char);
            remoteBlacklistStringsDataSize = (remoteBlacklistStringsDataSize + 7) & ~7;
        }

        long remoteBlacklistPtrsArraySize = (blacklistWStringsStorage.Count + 1) * sizeof(ulong);
        remoteBlacklistPtrsArraySize = (remoteBlacklistPtrsArraySize + 7) & ~7;

        long totalDynamicBlacklistDataSize = remoteBlacklistPtrsArraySize + remoteBlacklistStringsDataSize;
        long totalInjectedSize = G_REMOTE_STUB_SIZE + totalDynamicBlacklistDataSize;

        const long DBG_UI_FUNCTION_MAX_SIZE = 0x6AB;
        if (totalInjectedSize > DBG_UI_FUNCTION_MAX_SIZE)
        {
            FatalError("Calculated total injected size (stub + dynamic blacklist) is too large for the chosen DbgUi function. " +
                               "Total size: 0x{totalInjectedSize:X} bytes. " +
                               "DbgUi function max size: 0x{DBG_UI_FUNCTION_MAX_SIZE:X} bytes.", -100);
        }

        Console.WriteLine($"[+] Calculated total injected size (stub code+data + dynamic blacklist): 0x{totalInjectedSize:X} bytes (Max DbgUi size: 0x{DBG_UI_FUNCTION_MAX_SIZE:X} bytes).");

        byte[] fullInjectedStub = new byte[totalInjectedSize];
        Buffer.BlockCopy(G_REMOTE_STUB_BYTES, 0, fullInjectedStub, 0, G_REMOTE_STUB_BYTES.Length);

        IntPtr remoteBlacklistPtrsArrayAddr = (IntPtr)((long)g_addrDbgUiHookTarget + G_REMOTE_STUB_SIZE);
        IntPtr remoteBlacklistStringsStartAddr = (IntPtr)((long)remoteBlacklistPtrsArrayAddr + remoteBlacklistPtrsArraySize);

        long currentOffsetForPtrsInBuffer = G_REMOTE_STUB_SIZE;
        long currentOffsetForStringsInBuffer = G_REMOTE_STUB_SIZE + remoteBlacklistPtrsArraySize;

        List<ulong> currentBlacklistPtrsValues = new List<ulong>();

        foreach (string ws in blacklistWStringsStorage)
        {
            byte[] stringBytes = Encoding.Unicode.GetBytes(ws + "\0");
            long nameLenBytes = stringBytes.Length;

            if (currentOffsetForStringsInBuffer + nameLenBytes > totalInjectedSize)
            {
                FatalError("Buffer overflow preparing blacklist strings. Blacklist is too large.", -102);
            }

            Buffer.BlockCopy(stringBytes, 0, fullInjectedStub, (int)currentOffsetForStringsInBuffer, stringBytes.Length);

            currentBlacklistPtrsValues.Add((ulong)((long)g_addrDbgUiHookTarget + currentOffsetForStringsInBuffer));

            currentOffsetForStringsInBuffer += nameLenBytes;
            currentOffsetForStringsInBuffer = (currentOffsetForStringsInBuffer + 7) & ~7;
        }
        currentBlacklistPtrsValues.Add(0);

        if (currentOffsetForPtrsInBuffer + currentBlacklistPtrsValues.Count * sizeof(ulong) > totalInjectedSize)
        {
            FatalError("Buffer overflow preparing blacklist pointers. Blacklist is too large.", -103);
        }

        byte[] ptrsByteArray = new byte[currentBlacklistPtrsValues.Count * sizeof(ulong)];
        Buffer.BlockCopy(currentBlacklistPtrsValues.ToArray(), 0, ptrsByteArray, 0, ptrsByteArray.Length);
        Buffer.BlockCopy(ptrsByteArray, 0, fullInjectedStub, (int)currentOffsetForPtrsInBuffer, ptrsByteArray.Length);

        BitConverter.GetBytes((ulong)g_addrLdrLoadDllLocal.ToInt64()).CopyTo(fullInjectedStub, OFF_REALLOADLIBRARY_PTR);

        BitConverter.GetBytes((ulong)remoteBlacklistPtrsArrayAddr.ToInt64()).CopyTo(fullInjectedStub, OFF_ADDRBLACKLISTSTR_PTR);

        Buffer.BlockCopy(g_originalLdrLoadDllPrologue, 0, fullInjectedStub, OFF_ORIGINAL_LDRLOADDLL_PROLOGUE, g_originalLdrLoadDllPrologue.Length);

        byte[] rehookJmpTemplate = new byte[12] { 0x48, 0xB8, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xE0 };
        ulong stubEntryPoint = (ulong)((long)g_addrDbgUiHookTarget + OFF_REMOTESTUB);
        BitConverter.GetBytes(stubEntryPoint).CopyTo(rehookJmpTemplate, 2);
        Buffer.BlockCopy(rehookJmpTemplate, 0, fullInjectedStub, OFF_REHOOK_JMP_TO_REMOTESTUB, rehookJmpTemplate.Length);


        Console.WriteLine($"[+] Writing patched stub and dynamic blacklist data (total size 0x{totalInjectedSize:X}) to DbgUi target 0x{g_addrDbgUiHookTarget:X}.");

        if (!VirtualProtectEx(g_procHandle, g_addrDbgUiHookTarget, (int)totalInjectedSize, PAGE_EXECUTE_READWRITE, out g_oldProtectionDbgUi))
        {
            FatalError("Failed to change DbgUi target memory protection to RWX for stub and blacklist", Marshal.GetLastWin32Error());
        }
        Console.WriteLine($"[+] Original DbgUi protection was: 0x{g_oldProtectionDbgUi:X}.");

        WriteRemoteMemory(g_procHandle, g_addrDbgUiHookTarget, fullInjectedStub,
            "Failed to write stub and blacklist data to DbgUi target", PerformCleanup);
        Console.WriteLine("[+] Stub and dynamic blacklist data written to DbgUi target.");

        Console.WriteLine($"[+] Changing remote stub memory protection (0x{g_addrDbgUiHookTarget:X}) from RWX to RX...");
        if (!VirtualProtectEx(g_procHandle, g_addrDbgUiHookTarget, (int)totalInjectedSize, PAGE_EXECUTE_READ, out uint tempOldProtect))
        {
            FatalError("Failed to change remote stub memory protection to RX", Marshal.GetLastWin32Error());
        }
        Console.WriteLine("[+] Successfully changed remote stub memory protection to RX.");

        byte[] hookLdrLoadDll = new byte[12];
        hookLdrLoadDll[0] = 0x48; hookLdrLoadDll[1] = 0xB8;
        BitConverter.GetBytes(stubEntryPoint).CopyTo(hookLdrLoadDll, 2);
        hookLdrLoadDll[10] = 0xFF; hookLdrLoadDll[11] = 0xE0;

        Console.WriteLine($"[+] Changing memory protection of LdrLoadDll (0x{g_addrLdrLoadDllLocal:X}) to RWX...");
        if (!VirtualProtectEx(g_procHandle, g_addrLdrLoadDllLocal, 12, PAGE_EXECUTE_READWRITE, out g_oldProtectLdrLoadDll))
        {
            FatalError("VirtualProtectEx failed (pre-hook LdrLoadDll)", Marshal.GetLastWin32Error());
        }
        Console.WriteLine($"[+] Original LdrLoadDll protection was: 0x{g_oldProtectLdrLoadDll:X}.");

        WriteRemoteMemory(g_procHandle, g_addrLdrLoadDllLocal, hookLdrLoadDll,
            "Failed to write hook to LdrLoadDll", PerformCleanup);
        Console.WriteLine($"[+] LdrLoadDll hooked successfully to stub at 0x{stubEntryPoint:X}.");

        Console.WriteLine($"[+] Hook installed for PID {targetPid}.");

        if (unhookDelay > 0)
        {
            Console.WriteLine($"[+] Unhooking in {unhookDelay} seconds...");
            Sleep((uint)unhookDelay * 1000);
            PerformCleanup();
        }
        else
        {
            Console.WriteLine("[+] Unhook delay not specified or zero. Exiting without unhooking. Manual cleanup may be required.");
            if (g_procHandle != IntPtr.Zero && g_procHandle != new IntPtr(INVALID_HANDLE_VALUE))
            {
                CloseHandle(g_procHandle);
                Console.WriteLine("[+] Process handle closed.");
            }
        }
    }
}
