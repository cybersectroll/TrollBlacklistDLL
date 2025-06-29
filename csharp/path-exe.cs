using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public class Program
{
    public static class NativeMethods
    {
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint MEM_RELEASE = 0x00008000;

        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_READ = 0x20;

        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_SET_INFORMATION = 0x0200;

        public const uint CREATE_SUSPENDED = 0x00000004;
        public const uint CREATE_NEW_CONSOLE = 0x00000010;
        public const uint STARTF_USESHOWWINDOW = 0x00000001;
        public const short SW_SHOW = 5;

        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess(
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            uint dwProcessId
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            SafeProcessHandle hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flAllocationType,
            uint flProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFreeEx(
            SafeProcessHandle hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint dwFreeType
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtectEx(
            SafeProcessHandle hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
            SafeProcessHandle hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            UIntPtr nSize,
            out UIntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
            SafeProcessHandle hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UIntPtr nSize,
            out UIntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            SafeProcessHandle hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            UIntPtr nSize,
            out UIntPtr lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetThreadId(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
    }

    public class RemoteAllocSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeProcessHandle _processHandle;
        private IntPtr _baseAddress;

        public RemoteAllocSafeHandle() : base(true) { }

        public RemoteAllocSafeHandle(IntPtr handle, SafeProcessHandle processHandle) : base(true)
        {
            SetHandle(handle);
            _processHandle = processHandle;
            _baseAddress = handle;
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid && !IsClosed && _processHandle != null && !_processHandle.IsInvalid && !_processHandle.IsClosed)
            {
                bool success = NativeMethods.VirtualFreeEx(_processHandle, handle, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                if (!success)
                {
                    Console.Error.WriteLine($"[!] Error: Failed to free remote memory at 0x{handle.ToInt64():X} via VirtualFreeEx. Error Code: {Marshal.GetLastWin32Error()}");
                }
                return success;
            }
            return true;
        }
    }

    private static readonly byte[] g_remoteStubBytes = {
        0x53, 0x56, 0x57, 0x0F, 0xB7, 0x01, 0x0F, 0xB7, 0x1A, 0x66, 0x3B, 0xC3, 0x75, 0x13, 0x66, 0x85,
        0xC0, 0x74, 0x0A, 0x48, 0x83, 0xC1, 0x02, 0x48, 0x83, 0xC2, 0x02, 0xEB, 0xE6, 0x33, 0xC0, 0xEB,
        0x05, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5F, 0x5E, 0x5B, 0xC3, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x81,
        0xEC, 0xD8, 0x00, 0x00, 0x00, 0x9C, 0x8F, 0x45, 0xF8, 0x48, 0x89, 0x45, 0xF0, 0x48, 0x89, 0x4D,
        0xE8, 0x48, 0x89, 0x55, 0xE0, 0x4C, 0x89, 0x45, 0xD8, 0x4C, 0x89, 0x4D, 0xD0, 0x4C, 0x89, 0x55,
        0xC8, 0x4C, 0x89, 0x5D, 0xC0, 0x48, 0x89, 0x5D, 0xB8, 0x48, 0x89, 0x75, 0xB0, 0x48, 0x89, 0x7D,
        0xA8, 0x4C, 0x89, 0x65, 0xA0, 0x4C, 0x89, 0x6D, 0x98, 0x4C, 0x89, 0x75, 0x90, 0x4C, 0x89, 0x7D,
        0x88, 0x4C, 0x8D, 0x15, 0xF4, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x12, 0x48, 0x8D, 0x3D, 0xE2, 0x00,
        0x00, 0x00, 0x48, 0x8B, 0x3F, 0x49, 0x8B, 0xF2, 0x48, 0xC7, 0xC1, 0x0C, 0x00, 0x00, 0x00, 0xFC,
        0xF3, 0xA4, 0x48, 0x8B, 0x4D, 0xD8, 0x48, 0x8B, 0x49, 0x08, 0x48, 0x89, 0x8D, 0x78, 0xFF, 0xFF,
        0xFF, 0x48, 0x8D, 0x1D, 0xB4, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x1B, 0x48, 0x8B, 0x13, 0x48, 0x83,
        0xFA, 0x00, 0x74, 0x1E, 0x48, 0x8B, 0x8D, 0x78, 0xFF, 0xFF, 0xFF, 0xE8, 0x40, 0xFF, 0xFF, 0xFF,
        0x83, 0xF8, 0x00, 0x74, 0x06, 0x48, 0x83, 0xC3, 0x08, 0xEB, 0xE0, 0xB8, 0x22, 0x00, 0x00, 0xC0,
        0xEB, 0x28, 0x48, 0x8B, 0x4D, 0xE8, 0x48, 0x8B, 0x55, 0xE0, 0x4C, 0x8B, 0x45, 0xD8, 0x4C, 0x8B,
        0x4D, 0xD0, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x8D, 0x05, 0x77, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x00,
        0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x08, 0x48, 0x89, 0x45, 0x80, 0x48, 0x8D, 0x3D, 0x63, 0x00, 0x00,
        0x00, 0x48, 0x8B, 0x3F, 0x4C, 0x8D, 0x1D, 0x69, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x1B, 0x49, 0x8B,
        0xF3, 0x48, 0xC7, 0xC1, 0x0C, 0x00, 0x00, 0x00, 0xFC, 0xF3, 0xA4, 0x48, 0x8B, 0x45, 0x80, 0x4C,
        0x8B, 0x7D, 0x88, 0x4C, 0x8B, 0x75, 0x90, 0x4C, 0x8B, 0x6D, 0x98, 0x4C, 0x8B, 0x65, 0xA0, 0x48,
        0x8B, 0x7D, 0xA8, 0x48, 0x8B, 0x75, 0xB0, 0x48, 0x8B, 0x5D, 0xB8, 0x4C, 0x8B, 0x5D, 0xC0, 0x4C,
        0x8B, 0x55, 0xC8, 0x4C, 0x8B, 0x4D, 0xD0, 0x4C, 0x8B, 0x45, 0xD8, 0x48, 0x8B, 0x55, 0xE0, 0x48,
        0x8B, 0x4D, 0xE8, 0xFF, 0x75, 0xF8, 0x9D, 0x48, 0x8B, 0xE5, 0x5D, 0xC3, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    private static readonly uint g_remoteStubSize = (uint)g_remoteStubBytes.Length;

    private const int OFF_ADDRBLACKLISTSTR_PTR = 0x15C;
    private const int OFF_BLACKLISTARRAY_DATA = 0x17C;
    private const int OFF_COMPAREWIDESTRINGS = 0x0;
    private const int OFF_DATA_SIZE = 0x28;
    private const int OFF_ORIGINALLDRLOADDLLBYTES_PTR = 0x16C;
    private const int OFF_REALLOADLIBRARY_PTR = 0x164;
    private const int OFF_REHOOKBYTES_PTR = 0x174;
    private const int OFF_REMOTESTUB = 0x2A;
    private const int OFF_TEXT_MN_SIZE = 0x15C;

    private static void FatalError(string msg, int code)
    {
        Console.Error.WriteLine($"[!] FATAL Error: {msg} Error Code: {Marshal.GetLastWin32Error()}");
        Environment.Exit(code);
    }

    private static void PrintBytes(string label, byte[] data, uint size)
    {
        Console.WriteLine($"{label} (Size: {size} bytes):");
        for (uint i = 0; i < size; ++i)
        {
            Console.Write($"{data[i]:X2} ");
            if ((i + 1) % 16 == 0)
            {
                Console.WriteLine();
            }
        }
        Console.WriteLine("\n");
    }

    private static List<string> ReadBlacklistFromFile(string filename)
    {
        List<string> blacklistStrings = new List<string>();
        Console.WriteLine($"[+] Attempting to load blacklist from '{filename}'...");

        if (!File.Exists(filename))
        {
            Console.Error.WriteLine($"[!] Error: Blacklist file not found: {filename}");
            return blacklistStrings;
        }

        try
        {
            string[] lines = File.ReadAllLines(filename);
            Console.WriteLine($"[+] Blacklist loaded from '{filename}':");
            foreach (string line in lines)
            {
                string trimmedLine = line.Trim();
                if (string.IsNullOrEmpty(trimmedLine)) continue;

                blacklistStrings.Add(trimmedLine);
                Console.WriteLine($"    - {trimmedLine}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[!] Error reading blacklist file: " + ex.Message);
        }
        return blacklistStrings;
    }

    private static void WriteRemoteMemory(SafeProcessHandle procHandle, IntPtr addr, byte[] data, string errorMsg, Action cleanupAction)
    {
        UIntPtr lpNumberOfBytesWritten;
        if (!NativeMethods.WriteProcessMemory(procHandle, addr, data, (UIntPtr)data.Length, out lpNumberOfBytesWritten))
        {
            cleanupAction();
            FatalError(errorMsg, Marshal.GetLastWin32Error());
        }
    }

    private static void WriteRemoteMemory(SafeProcessHandle procHandle, IntPtr addr, IntPtr dataPtr, uint size, string errorMsg, Action cleanupAction)
    {
        UIntPtr lpNumberOfBytesWritten;
        if (!NativeMethods.WriteProcessMemory(procHandle, addr, dataPtr, (UIntPtr)size, out lpNumberOfBytesWritten))
        {
            cleanupAction();
            FatalError(errorMsg, Marshal.GetLastWin32Error());
        }
    }

    public static void Main(string[] args)
    {
        uint targetPid = 0;
        string targetPathStr = null;
        bool createNewProcess = false;
        int unhookDelay = 0;

        Action printUsage = () =>
        {
            Console.WriteLine($"Usage: {AppDomain.CurrentDomain.FriendlyName} -pid <process_id> [-unhook <seconds>]");
            Console.WriteLine($"Or: {AppDomain.CurrentDomain.FriendlyName} -path <path_to_executable> [-unhook <seconds>]");
        };

        for (int i = 0; i < args.Length; ++i)
        {
            string arg = args[i].ToLower();
            if (arg == "-pid")
            {
                if (++i < args.Length)
                {
                    if (!uint.TryParse(args[i], out targetPid))
                    {
                        Console.Error.WriteLine("[!] Error: -pid requires a valid process ID.");
                        printUsage();
                        Environment.Exit(1);
                    }
                }
                else { Console.Error.WriteLine("[!] Error: -pid requires a process ID."); printUsage(); Environment.Exit(1); }
            }
            else if (arg == "-path")
            {
                if (++i < args.Length) { targetPathStr = args[i]; createNewProcess = true; }
                else { Console.Error.WriteLine("[!] Error: -path requires an executable path."); printUsage(); Environment.Exit(1); }
            }
            else if (arg == "-unhook")
            {
                if (++i < args.Length)
                {
                    if (!int.TryParse(args[i], out unhookDelay))
                    {
                        Console.Error.WriteLine($"[!] Error: Invalid unhook delay value: {args[i]}.");
                        return;
                    }
                    if (unhookDelay <= 0)
                    {
                        Console.Error.WriteLine("[!] Error: -unhook requires a positive integer for seconds.");
                        return;
                    }
                }
                else { Console.Error.WriteLine("[!] Error: -unhook requires a time in seconds."); printUsage(); Environment.Exit(1); }
            }
            else
            {
                Console.Error.WriteLine($"[!] Error: Unknown argument: {args[i]}"); printUsage(); Environment.Exit(1);
            }
        }

        if ((targetPid != 0 && createNewProcess) || (targetPid == 0 && !createNewProcess))
        {
            Console.Error.WriteLine("[!] Error: Please specify either -pid or -path, but not both.");
            printUsage();
            Environment.Exit(1);
        }

        SafeProcessHandle procHandle = null;
        IntPtr hThread = IntPtr.Zero;

        try
        {
            if (createNewProcess)
            {
                NativeMethods.STARTUPINFO si = new NativeMethods.STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf(si);
                si.dwFlags = NativeMethods.STARTF_USESHOWWINDOW;
                si.wShowWindow = NativeMethods.SW_SHOW;
                NativeMethods.PROCESS_INFORMATION pi = new NativeMethods.PROCESS_INFORMATION();

                Console.WriteLine($"[+] Creating process '{targetPathStr}' suspended in a new console window...");
                if (!NativeMethods.CreateProcess(null, targetPathStr, IntPtr.Zero, IntPtr.Zero, false,
                                                 NativeMethods.CREATE_SUSPENDED | NativeMethods.CREATE_NEW_CONSOLE,
                                                 IntPtr.Zero, null, ref si, out pi))
                {
                    FatalError("CreateProcess failed", Marshal.GetLastWin32Error());
                }

                procHandle = new SafeProcessHandle(pi.hProcess, true);
                targetPid = pi.dwProcessId;
                hThread = pi.hThread;
                Console.WriteLine($"[+] Process '{targetPathStr}' created (PID: {targetPid}, TID: {pi.dwThreadId}) in suspended state.");
            }
            else
            {
                Console.WriteLine($"[+] Attempting to attach to existing process with PID: {targetPid}...");
                procHandle = NativeMethods.OpenProcess(
                    NativeMethods.PROCESS_VM_OPERATION | NativeMethods.PROCESS_VM_WRITE |
                    NativeMethods.PROCESS_VM_READ | NativeMethods.PROCESS_QUERY_INFORMATION |
                    NativeMethods.PROCESS_SET_INFORMATION,
                    false,
                    targetPid
                );

                if (procHandle.IsInvalid)
                {
                    FatalError("OpenProcess failed", Marshal.GetLastWin32Error());
                }
                Console.WriteLine($"[+] Successfully attached to process with PID: {targetPid}.");
            }

            IntPtr hNtdll = NativeMethods.GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero) FatalError("GetModuleHandle failed for ntdll.dll", Marshal.GetLastWin32Error());

            IntPtr addrLdrLoadDllLocal = NativeMethods.GetProcAddress(hNtdll, "LdrLoadDll");
            if (addrLdrLoadDllLocal == IntPtr.Zero) FatalError("GetProcAddress failed for LdrLoadDll", Marshal.GetLastWin32Error());

            Console.WriteLine($"[+] ntdll.dll base: 0x{hNtdll.ToInt64():X}. LdrLoadDll entry: 0x{addrLdrLoadDllLocal.ToInt64():X}.");

            byte[] originalLdrLoadDllPrologue = new byte[12];
            UIntPtr lpNumberOfBytesRead;
            if (!NativeMethods.ReadProcessMemory(procHandle, addrLdrLoadDllLocal, originalLdrLoadDllPrologue, (UIntPtr)originalLdrLoadDllPrologue.Length, out lpNumberOfBytesRead))
            {
                FatalError("Failed to read original LdrLoadDll prologue", Marshal.GetLastWin32Error());
            }
            PrintBytes("Original LdrLoadDll Prologue", originalLdrLoadDllPrologue, (uint)originalLdrLoadDllPrologue.Length);

            byte[] c_original_bytes_data = new byte[12];
            Array.Copy(originalLdrLoadDllPrologue, c_original_bytes_data, c_original_bytes_data.Length);

            byte[] c_rehook_bytes_data = { 0x48, 0xB8, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xE0 };

            List<string> blacklistStringsStorage = ReadBlacklistFromFile("blacklist.txt");
            if (blacklistStringsStorage.Count == 0)
            {
                FatalError("No DLL names found in blacklist.txt or file could not be read. Exiting.", -50);
            }

            List<IntPtr> remoteBlacklistPtrsToWrite = new List<IntPtr>();
            uint remoteBlacklistStringsSize = 0;
            foreach (var ws in blacklistStringsStorage)
            {
                remoteBlacklistPtrsToWrite.Add(IntPtr.Zero);
                remoteBlacklistStringsSize += (uint)((ws.Length + 1) * sizeof(char));
                remoteBlacklistStringsSize = (remoteBlacklistStringsSize + 7) & ~7U;
            }
            remoteBlacklistPtrsToWrite.Add(IntPtr.Zero);

            uint totalRemoteAllocSize = g_remoteStubSize + (uint)c_original_bytes_data.Length +
                                        (uint)c_rehook_bytes_data.Length + remoteBlacklistStringsSize +
                                        (uint)(remoteBlacklistPtrsToWrite.Count * sizeof(long));

            Console.WriteLine($"[+] Allocating remote memory (Total Size: 0x{totalRemoteAllocSize:X}) in PID {targetPid}...");

            using (RemoteAllocSafeHandle remoteAlloc = new RemoteAllocSafeHandle(
                NativeMethods.VirtualAllocEx(procHandle, IntPtr.Zero, (UIntPtr)totalRemoteAllocSize,
                                             NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                                             NativeMethods.PAGE_EXECUTE_READWRITE),
                procHandle))
            {
                if (remoteAlloc.IsInvalid)
                {
                    FatalError("VirtualAllocEx failed", Marshal.GetLastWin32Error());
                }
                Console.WriteLine($"[+] Remote memory allocated at: 0x{remoteAlloc.DangerousGetHandle().ToInt64():X}.");

                IntPtr remoteStubBaseAddr = remoteAlloc.DangerousGetHandle();
                IntPtr remoteOriginalBytesDataAddr = (IntPtr)(remoteStubBaseAddr.ToInt64() + g_remoteStubSize);
                IntPtr remoteRehookBytesDataAddr = (IntPtr)(remoteOriginalBytesDataAddr.ToInt64() + c_original_bytes_data.Length);
                IntPtr remoteBlacklistStringsDataBase = (IntPtr)(remoteRehookBytesDataAddr.ToInt64() + c_rehook_bytes_data.Length);
                IntPtr remoteBlacklistPtrsArrayAddr = (IntPtr)(remoteBlacklistStringsDataBase.ToInt64() + remoteBlacklistStringsSize);

                Console.WriteLine("    Remote memory layout:");
                Console.WriteLine($"      Stub base: 0x{remoteStubBaseAddr.ToInt64():X} (Size: 0x{g_remoteStubSize:X})");
                Console.WriteLine($"      Original LdrLoadDll Bytes: 0x{remoteOriginalBytesDataAddr.ToInt64():X} (Size: 0x{c_original_bytes_data.Length:X})");
                Console.WriteLine($"      Rehook Bytes: 0x{remoteRehookBytesDataAddr.ToInt64():X} (Size: 0x{c_rehook_bytes_data.Length:X})");
                Console.WriteLine($"      Blacklist Strings Data Base: 0x{remoteBlacklistStringsDataBase.ToInt64():X} (Size: 0x{remoteBlacklistStringsSize:X})");
                Console.WriteLine($"      Blacklist Pointers Array: 0x{remoteBlacklistPtrsArrayAddr.ToInt64():X} (Size: 0x{remoteBlacklistPtrsToWrite.Count * sizeof(long):X})");

                byte[] patchedStubBuf = new byte[g_remoteStubBytes.Length];
                Array.Copy(g_remoteStubBytes, patchedStubBuf, g_remoteStubBytes.Length);

                unsafe
                {
                    fixed (byte* ptr = patchedStubBuf)
                    {
                        *(long*)(ptr + OFF_REALLOADLIBRARY_PTR) = addrLdrLoadDllLocal.ToInt64();
                        *(long*)(ptr + OFF_ADDRBLACKLISTSTR_PTR) = remoteBlacklistPtrsArrayAddr.ToInt64();
                        *(long*)(ptr + OFF_ORIGINALLDRLOADDLLBYTES_PTR) = remoteOriginalBytesDataAddr.ToInt64();
                        *(long*)(ptr + OFF_REHOOKBYTES_PTR) = remoteRehookBytesDataAddr.ToInt64();
                    }
                }

                Console.WriteLine($"[+] Writing patched stub (size {patchedStubBuf.Length} bytes) to remote address 0x{remoteStubBaseAddr.ToInt64():X}.");
                WriteRemoteMemory(procHandle, remoteStubBaseAddr, patchedStubBuf, "Failed to write stub", () => { });

                IntPtr remoteStubFunctionEntry = (IntPtr)(remoteStubBaseAddr.ToInt64() + OFF_REMOTESTUB);
                unsafe
                {
                    fixed (byte* ptr = c_rehook_bytes_data)
                    {
                        *(long*)(ptr + 2) = remoteStubFunctionEntry.ToInt64();
                    }
                }
                Console.WriteLine($"[+] Rehook bytes patched with remote stub entry address (0x{remoteStubFunctionEntry.ToInt64():X}).");

                Console.WriteLine("[+] Writing original LdrLoadDll bytes and rehook bytes to remote memory...");
                WriteRemoteMemory(procHandle, remoteOriginalBytesDataAddr, c_original_bytes_data, "Failed to write original LdrLoadDll bytes", () => { });
                WriteRemoteMemory(procHandle, remoteRehookBytesDataAddr, c_rehook_bytes_data, "Failed to write rehook bytes", () => { });

                IntPtr currentRemoteBlacklistStringWriteAddr = remoteBlacklistStringsDataBase;
                for (int i = 0; i < blacklistStringsStorage.Count; ++i)
                {
                    string localName = blacklistStringsStorage[i];
                    IntPtr localNamePtr = Marshal.StringToHGlobalUni(localName);
                    uint nameLenBytes = (uint)((localName.Length + 1) * sizeof(char));

                    Console.WriteLine($"    Writing blacklist string '{localName}' (size {nameLenBytes} bytes) to 0x{currentRemoteBlacklistStringWriteAddr.ToInt64():X}...");
                    WriteRemoteMemory(procHandle, currentRemoteBlacklistStringWriteAddr, localNamePtr, nameLenBytes, "Failed to write blacklist DLL name", () => { });

                    remoteBlacklistPtrsToWrite[i] = currentRemoteBlacklistStringWriteAddr;
                    currentRemoteBlacklistStringWriteAddr = (IntPtr)(((ulong)currentRemoteBlacklistStringWriteAddr.ToInt64() + nameLenBytes + 7) & ~7UL);

                    Marshal.FreeHGlobal(localNamePtr);
                }
                Console.WriteLine("    Successfully wrote blacklist strings.");

                byte[] blacklistPtrsArrayBytes = new byte[remoteBlacklistPtrsToWrite.Count * sizeof(long)];
                for (int i = 0; i < remoteBlacklistPtrsToWrite.Count; i++)
                {
                    byte[] ptrBytes = BitConverter.GetBytes(remoteBlacklistPtrsToWrite[i].ToInt64());
                    Array.Copy(ptrBytes, 0, blacklistPtrsArrayBytes, i * sizeof(long), sizeof(long));
                }

                Console.WriteLine("[+] Writing blacklist pointers array to remote memory...");
                WriteRemoteMemory(procHandle, remoteBlacklistPtrsArrayAddr, blacklistPtrsArrayBytes, "Failed to write blacklist pointers array", () => { });
                Console.WriteLine("    Successfully wrote blacklist pointers array.");

                uint oldProtectionStub;
                Console.WriteLine($"[+] Changing remote stub memory protection (0x{remoteAlloc.DangerousGetHandle().ToInt64():X}) from RWX to RX...");
                if (!NativeMethods.VirtualProtectEx(procHandle, remoteAlloc.DangerousGetHandle(), (UIntPtr)totalRemoteAllocSize, NativeMethods.PAGE_EXECUTE_READ, out oldProtectionStub))
                {
                    FatalError("Failed to change remote stub memory protection to RX", Marshal.GetLastWin32Error());
                }

                byte[] hook = new byte[12] { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
                unsafe
                {
                    fixed (byte* ptr = hook)
                    {
                        *(long*)(ptr + 2) = remoteStubFunctionEntry.ToInt64();
                    }
                }

                uint oldProtect;
                Console.WriteLine($"[+] Changing memory protection of LdrLoadDll (0x{addrLdrLoadDllLocal.ToInt64():X}) to RWX...");
                if (!NativeMethods.VirtualProtectEx(procHandle, addrLdrLoadDllLocal, (UIntPtr)12, NativeMethods.PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    FatalError("VirtualProtectEx failed (pre-hook)", Marshal.GetLastWin32Error());
                }
                Console.WriteLine($"    Original protection was: 0x{oldProtect:X}.");

                Console.WriteLine($"[+] Writing hook bytes to LdrLoadDll at 0x{addrLdrLoadDllLocal.ToInt64():X}.");
                UIntPtr lpNumberOfBytesWrittenForHook;
                if (!NativeMethods.WriteProcessMemory(procHandle, addrLdrLoadDllLocal, hook, (UIntPtr)12, out lpNumberOfBytesWrittenForHook))
                {
                    NativeMethods.VirtualProtectEx(procHandle, addrLdrLoadDllLocal, (UIntPtr)12, oldProtect, out uint tempOldProtect);
                    FatalError("Failed to write hook to LdrLoadDll", Marshal.GetLastWin32Error());
                }
                Console.WriteLine("[+] Hook installed.\n");


                if (createNewProcess)
                {
                    Console.WriteLine($"[+] Resuming {targetPathStr} (PID {targetPid}, TID: {NativeMethods.GetThreadId(hThread)})...");
                    if (NativeMethods.ResumeThread(hThread) == NativeMethods.INVALID_HANDLE_VALUE.ToInt64())
                    {
                        FatalError("ResumeThread failed", Marshal.GetLastWin32Error());
                    }
                    Console.WriteLine($"[+] Successfully resumed {targetPathStr}.");
                }
                else
                {
                    Console.WriteLine($"[+] Hook installed for PID {targetPid}.");
                }

                if (unhookDelay > 0)
                {
                    Console.WriteLine($"[+] Unhooking in {unhookDelay} seconds...");
                    Thread.Sleep(unhookDelay * 1000);

                    Console.WriteLine("[+] Initiating cleanup: Restoring LdrLoadDll, freeing injected memory, and closing handles...");

                    UIntPtr tempBytesWritten;
                    if (!NativeMethods.WriteProcessMemory(procHandle, addrLdrLoadDllLocal, originalLdrLoadDllPrologue, (UIntPtr)originalLdrLoadDllPrologue.Length, out tempBytesWritten))
                    {
                        Console.WriteLine($"[!] Error: Failed to unhook LdrLoadDll: {Marshal.GetLastWin32Error()}");
                    }
                    else
                    {
                        Console.WriteLine("[+] LdrLoadDll unhooked successfully.");
                    }

                    uint tempOldProtectionRestore;
                    if (!NativeMethods.VirtualProtectEx(procHandle, addrLdrLoadDllLocal, (UIntPtr)12, oldProtect, out tempOldProtectionRestore))
                    {
                        Console.WriteLine($"[!] Warning: Failed to restore original memory protection on LdrLoadDll: {Marshal.GetLastWin32Error()}");
                    }
                    else
                    {
                        Console.WriteLine("[+] Original memory protection restored on LdrLoadDll.");
                    }

                    Console.WriteLine($"[+] Injected memory (0x{remoteAlloc.DangerousGetHandle().ToInt64():X}) freed and process handle closed automatically.");
                }
                else
                {
                    Console.WriteLine("[+] Unhook delay not specified or zero. Exiting without unhooking.");
                }
            }
        }
        finally
        {
            if (hThread != IntPtr.Zero && hThread != NativeMethods.INVALID_HANDLE_VALUE)
            {
                if (!NativeMethods.CloseHandle(hThread))
                {
                    Console.Error.WriteLine($"[!] Error: Failed to close hThread (0x{hThread.ToInt64():X}): {Marshal.GetLastWin32Error()}");
                }
            }
        }
    }
}
