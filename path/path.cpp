#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <locale>
#include <codecvt>
#include <algorithm>
#include <memory>
#include <winternl.h>

#include "stub_offsets.h"
#include "stub_bytes.h"

// Custom deleter for HANDLE to enable std::unique_ptr
struct HandleDeleter {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
};
using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

// Custom deleter for LPVOID (VirtualAllocEx memory)
struct VirtualFreeDeleter {
    HANDLE process;
    VirtualFreeDeleter(HANDLE p) : process(p) {}
    void operator()(LPVOID addr) const {
        if (addr) {
            VirtualFreeEx(process, addr, 0, MEM_RELEASE);
        }
    }
};
using UniqueVirtualAlloc = std::unique_ptr<void, VirtualFreeDeleter>;

// Helper for error reporting and exit
void FatalError(const std::wstring& msg, int code) {
    std::wcerr << L"[!] FATAL Error: " << msg << L" Error Code: " << GetLastError() << std::endl;
    exit(code);
}

// Helper to print bytes (can be removed for extreme brevity if not strictly needed)
void PrintBytes(const char* label, const BYTE* data, SIZE_T size) {
    printf("%s (Size: %zu bytes):\n", label, size);
    for (SIZE_T i = 0; i < size; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

// Function pointer type for LdrLoadDll
typedef NTSTATUS (NTAPI *pLdrLoadDll)(
    PWSTR SearchPath,
    PULONG DllCharacteristics,
    PUNICODE_STRING DllName,
    PVOID *BaseAddress
);

// Converts std::string to std::wstring
std::wstring s2ws(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len == 0) return L"";
    std::wstring ws(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    return ws;
}

// Reads blacklist DLLs from a file
std::vector<std::wstring> ReadBlacklistFromFile(const std::string& filename) {
    std::vector<std::wstring> blacklist_wstrings;
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::wcerr << L"[!] Error: Could not open blacklist file: " << s2ws(filename) << std::endl;
        return blacklist_wstrings;
    }

    std::string line;
    std::wcout << L"[+] Blacklist loaded from '" << s2ws(filename) << L"':\n";
    while (std::getline(file, line)) {
        size_t first = line.find_first_not_of(" \t\n\r");
        if (std::string::npos == first) continue;
        size_t last = line.find_last_not_of(" \t\n\r");
        line = line.substr(first, (last - first + 1));

        if (line.empty()) continue;

        std::wstring wline = s2ws(line);
        if (wline.empty()) {
            std::wcerr << L"[!] Warning: Failed to convert string to WCHAR for line: \"" << s2ws(line) << L"\" Error: " << GetLastError() << std::endl;
            continue;
        }
        blacklist_wstrings.push_back(wline);
        std::wcout << L"    - " << wline << std::endl;
    }
    file.close();
    return blacklist_wstrings;
}

// Macro for simplified error checking and cleanup
#define CHECK_WIN_API(api_call, error_msg, cleanup_lambda) \
    if (!(api_call)) {                                    \
        cleanup_lambda();                                 \
        FatalError(error_msg, __LINE__);                  \
    }

// Macro for simpler WriteProcessMemory
#define WRITE_REMOTE_MEM(proc_handle, addr, data, size, error_msg, cleanup_lambda) \
    CHECK_WIN_API(WriteProcessMemory(proc_handle, addr, data, size, nullptr), error_msg, cleanup_lambda)

int main(int argc, char* argv[]) {
    DWORD targetPid = 0;
    std::string targetPath_str;
    bool createNewProcess = false;
    int unhookDelay = 0; // Initialize unhookDelay to 0

    auto print_usage = [&argv]() {
        std::wcout << L"Usage: " << s2ws(argv[0]) << L" -pid <process_id> [-unhook <seconds>]" << std::endl;
        std::wcout << L"Or: " << s2ws(argv[0]) << L" -path <path_to_executable> [-unhook <seconds>]" << std::endl;
    };

    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "-pid") == 0) {
            if (++i < argc) targetPid = std::stoul(argv[i]);
            else { std::wcerr << L"[!] Error: -pid requires a process ID." << std::endl; print_usage(); return 1; }
        } else if (_stricmp(argv[i], "-path") == 0) {
            if (++i < argc) { targetPath_str = argv[i]; createNewProcess = true; }
            else { std::wcerr << L"[!] Error: -path requires an executable path." << std::endl; print_usage(); return 1; }
        } else if (_stricmp(argv[i], "-unhook") == 0) {
            if (++i < argc) {
                try { unhookDelay = std::stoi(argv[i]); if (unhookDelay <= 0) { std::wcerr << L"[!] Error: -unhook requires a positive integer for seconds." << std::endl; return 1; } }
                catch (const std::exception& e) { std::wcerr << L"[!] Error: Invalid unhook delay value: " << s2ws(argv[i]) << L" (" << s2ws(e.what()) << L")" << std::endl; return 1; }
            } else { std::wcerr << L"[!] Error: -unhook requires a time in seconds." << std::endl; print_usage(); return 1; }
        } else {
            std::wcerr << L"[!] Error: Unknown argument: " << s2ws(argv[i]) << std::endl; print_usage(); return 1;
        }
    }

    if ((targetPid != 0 && createNewProcess) || (targetPid == 0 && !createNewProcess)) {
        std::wcerr << L"[!] Error: Please specify either -pid or -path, but not both." << std::endl;
        print_usage(); return 1;
    }

    UniqueHandle proc;
    UniqueHandle hThread;
    std::wstring cmdLine;

    if (createNewProcess) {
        cmdLine = s2ws(targetPath_str);
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_SHOW;

        printf("[+] Creating process '%S' suspended in a new console window...\n", cmdLine.c_str());
        CHECK_WIN_API(CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi),
                      L"CreateProcessW failed", []{/* No handles to close yet on failure */});

        proc.reset(pi.hProcess);
        targetPid = pi.dwProcessId;
        hThread.reset(pi.hThread);
        printf("[+] Process '%S' created (PID: %u, TID: %u) in suspended state.\n", cmdLine.c_str(), targetPid, pi.dwThreadId);
    } else {
        printf("[+] Attempting to attach to existing process with PID: %u...\n", targetPid);
        proc.reset(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, targetPid));
        CHECK_WIN_API(proc.get(), L"OpenProcess failed", []{});
        printf("[+] Successfully attached to process with PID: %u.\n", targetPid);
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    CHECK_WIN_API(hNtdll, L"GetModuleHandleW failed for ntdll.dll", [&]{});

    LPVOID addrLdrLoadDllLocal = (LPVOID)GetProcAddress(hNtdll, "LdrLoadDll");
    CHECK_WIN_API(addrLdrLoadDllLocal, L"GetProcAddress failed for LdrLoadDll", [&]{});
    printf("[+] ntdll.dll base: 0x%p. LdrLoadDll entry: 0x%p.\n", (void*)hNtdll, (void*)addrLdrLoadDllLocal);

    BYTE originalLdrLoadDllPrologue[12];
    memcpy(originalLdrLoadDllPrologue, addrLdrLoadDllLocal, sizeof(originalLdrLoadDllPrologue));
    PrintBytes("Original LdrLoadDll Prologue", originalLdrLoadDllPrologue, sizeof(originalLdrLoadDllPrologue));

    BYTE c_original_bytes_data[12];
    memcpy(c_original_bytes_data, originalLdrLoadDllPrologue, sizeof(c_original_bytes_data));

    BYTE c_rehook_bytes_data[12] = { 0x48, 0xB8, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xE0 };

    std::vector<std::wstring> blacklist_wstrings_storage = ReadBlacklistFromFile("blacklist.txt");
    if (blacklist_wstrings_storage.empty()) {
        FatalError(L"No DLL names found in blacklist.txt or file could not be read. Exiting.", -50);
    }
    std::vector<ULONGLONG> remote_blacklist_ptrs_to_write;
    SIZE_T remote_blacklist_strings_size = 0;
    for (const auto& ws : blacklist_wstrings_storage) {
        remote_blacklist_ptrs_to_write.push_back(0); // Placeholder, will be updated later
        remote_blacklist_strings_size += (ws.length() + 1) * sizeof(WCHAR);
        remote_blacklist_strings_size = (remote_blacklist_strings_size + 7) & ~7; // Align to 8 bytes
    }
    remote_blacklist_ptrs_to_write.push_back(0); // Null terminator

    SIZE_T totalRemoteAllocSize = g_remoteStubSize + sizeof(c_original_bytes_data) + sizeof(c_rehook_bytes_data) + remote_blacklist_strings_size + (remote_blacklist_ptrs_to_write.size() * sizeof(ULONGLONG));

    printf("[+] Allocating remote memory (Total Size: 0x%zX) in PID %u...\n", totalRemoteAllocSize, targetPid);
    UniqueVirtualAlloc remoteAlloc(proc.get(), nullptr);
    remoteAlloc.reset(VirtualAllocEx(proc.get(), nullptr, totalRemoteAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    CHECK_WIN_API(remoteAlloc.get(), L"VirtualAllocEx failed", []{});
    printf("[+] Remote memory allocated at: 0x%p.\n", (void*)remoteAlloc.get());

    LPVOID remoteStubBaseAddr = remoteAlloc.get();
    LPVOID remoteOriginalBytesDataAddr = (LPVOID)((ULONG_PTR)remoteStubBaseAddr + g_remoteStubSize);
    LPVOID remoteRehookBytesDataAddr = (LPVOID)((ULONG_PTR)remoteOriginalBytesDataAddr + sizeof(c_original_bytes_data));
    LPVOID remoteBlacklistStringsDataBase = (LPVOID)((ULONG_PTR)remoteRehookBytesDataAddr + sizeof(c_rehook_bytes_data));
    LPVOID remoteBlacklistPtrsArrayAddr = (LPVOID)((ULONG_PTR)remoteBlacklistStringsDataBase + remote_blacklist_strings_size);

    printf("    Remote memory layout:\n");
    printf("      Stub base: 0x%p (Size: 0x%zX)\n", (void*)remoteStubBaseAddr, g_remoteStubSize);
    printf("      Original LdrLoadDll Bytes: 0x%p (Size: 0x%zX)\n", (void*)remoteOriginalBytesDataAddr, sizeof(c_original_bytes_data));
    printf("      Rehook Bytes: 0x%p (Size: 0x%zX)\n", (void*)remoteRehookBytesDataAddr, sizeof(c_rehook_bytes_data));
    printf("      Blacklist Strings Data Base: 0x%p (Size: 0x%zX)\n", (void*)remoteBlacklistStringsDataBase, remote_blacklist_strings_size);
    printf("      Blacklist Pointers Array: 0x%p (Size: 0x%zX)\n", (void*)remoteBlacklistPtrsArrayAddr, remote_blacklist_ptrs_to_write.size() * sizeof(ULONGLONG));

    std::vector<BYTE> stubBuf(g_remoteStubBytes, g_remoteStubBytes + g_remoteStubSize);
    *(UINT64*)&stubBuf[OFF_REALLOADLIBRARY_PTR] = (UINT64)addrLdrLoadDllLocal;
    *(UINT64*)&stubBuf[OFF_ADDRBLACKLISTSTR_PTR] = (UINT64)remoteBlacklistPtrsArrayAddr;
    *(UINT64*)&stubBuf[OFF_ORIGINALLDRLOADDLLBYTES_PTR] = (UINT64)remoteOriginalBytesDataAddr;
    *(UINT64*)&stubBuf[OFF_REHOOKBYTES_PTR] = (UINT64)remoteRehookBytesDataAddr;

    printf("[+] Writing patched stub (size %zu bytes) to remote address 0x%p.\n", stubBuf.size(), (void*)remoteStubBaseAddr);
    WRITE_REMOTE_MEM(proc.get(), remoteStubBaseAddr, stubBuf.data(), stubBuf.size(), L"Failed to write stub", [&]{});

    LPVOID remoteStubFunctionEntry = (LPVOID)((ULONG_PTR)remoteStubBaseAddr + OFF_REMOTESTUB);
    *(UINT64*)(c_rehook_bytes_data + 2) = (UINT64)remoteStubFunctionEntry;
    printf("[+] Rehook bytes patched with remote stub entry address (0x%p).\n", (void*)remoteStubFunctionEntry);

    printf("[+] Writing original LdrLoadDll bytes and rehook bytes to remote memory...\n");
    WRITE_REMOTE_MEM(proc.get(), remoteOriginalBytesDataAddr, c_original_bytes_data, sizeof(c_original_bytes_data), L"Failed to write original LdrLoadDll bytes", [&]{});
    WRITE_REMOTE_MEM(proc.get(), remoteRehookBytesDataAddr, c_rehook_bytes_data, sizeof(c_rehook_bytes_data), L"Failed to write rehook bytes", [&]{});

    LPVOID currentRemoteBlacklistStringWriteAddr = remoteBlacklistStringsDataBase;
    for (size_t i = 0; i < blacklist_wstrings_storage.size(); ++i) {
        const WCHAR* local_name = blacklist_wstrings_storage[i].c_str();
        SIZE_T name_len_bytes = (wcslen(local_name) + 1) * sizeof(WCHAR);
        printf("    Writing blacklist string '%S' (size %zu bytes) to 0x%p...\n", local_name, name_len_bytes, (void*)currentRemoteBlacklistStringWriteAddr); // Added printf here
        WRITE_REMOTE_MEM(proc.get(), currentRemoteBlacklistStringWriteAddr, (LPVOID)local_name, name_len_bytes, L"Failed to write blacklist DLL name", [&]{});
        remote_blacklist_ptrs_to_write[i] = (ULONGLONG)currentRemoteBlacklistStringWriteAddr;
        currentRemoteBlacklistStringWriteAddr = (LPVOID)(((ULONG_PTR)currentRemoteBlacklistStringWriteAddr + name_len_bytes + 7) & ~7);
    }
    printf("    Successfully wrote blacklist strings.\n"); // Added printf here

    printf("[+] Writing blacklist pointers array to remote memory...\n");
    WRITE_REMOTE_MEM(proc.get(), remoteBlacklistPtrsArrayAddr, remote_blacklist_ptrs_to_write.data(), remote_blacklist_ptrs_to_write.size() * sizeof(ULONGLONG), L"Failed to write blacklist pointers array", [&]{});
    printf("    Successfully wrote blacklist pointers array.\n"); // Added printf here
	
    DWORD oldProtectionStub = 0;
    printf("[+] Changing remote stub memory protection (0x%p) from RWX to RX...\n", (void*)remoteAlloc.get());
    CHECK_WIN_API(VirtualProtectEx(proc.get(), remoteAlloc.get(), totalRemoteAllocSize, PAGE_EXECUTE_READ, &oldProtectionStub),
                  L"Failed to change remote stub memory protection to RX", [&]{});

    BYTE hook[12] = { 0x48, 0xB8 };
    *(UINT64*)(hook + 2) = (ULONGLONG)remoteStubFunctionEntry;
    hook[10] = 0xFF; hook[11] = 0xE0;

    DWORD oldProtect = 0;
    printf("[+] Changing memory protection of LdrLoadDll (0x%p) to RWX...\n", (void*)addrLdrLoadDllLocal);
    CHECK_WIN_API(VirtualProtectEx(proc.get(), addrLdrLoadDllLocal, 12, PAGE_EXECUTE_READWRITE, &oldProtect),
                  L"VirtualProtectEx failed (pre-hook)", [&]{});
    printf("    Original protection was: 0x%lX.\n", oldProtect);

    printf("[+] Writing hook bytes to LdrLoadDll at 0x%p.\n", (void*)addrLdrLoadDllLocal);
    CHECK_WIN_API(WriteProcessMemory(proc.get(), addrLdrLoadDllLocal, hook, 12, nullptr),
                  L"Failed to write hook to LdrLoadDll",
                  [&]{ VirtualProtectEx(proc.get(), addrLdrLoadDllLocal, 12, oldProtect, &oldProtect); });
    printf("[+] Hook installed.\n");


    if (createNewProcess) {
        printf("[+] Resuming %S (PID %u, TID: %u)...\n", cmdLine.c_str(), targetPid, GetThreadId(hThread.get()));
        CHECK_WIN_API(ResumeThread(hThread.get()) != (DWORD)-1, L"ResumeThread failed", [&]{});
        printf("[+] Successfully resumed %S.\n", cmdLine.c_str());
    } else {
        printf("[+] Hook installed for PID %u.\n", targetPid);
    }


    if (unhookDelay > 0) {
        printf("[+] Unhooking in %d seconds...\n", unhookDelay);
        Sleep(unhookDelay * 1000);

        printf("[+] Initiating cleanup: Restoring LdrLoadDll, freeing injected memory, and closing handles...\n");

        // Unhooking LdrLoadDll
        if (!WriteProcessMemory(proc.get(), addrLdrLoadDllLocal, originalLdrLoadDllPrologue, sizeof(originalLdrLoadDllPrologue), nullptr)) {
            printf("[!] Error: Failed to unhook LdrLoadDll: %lu\n", GetLastError());
        } else {
            printf("[+] LdrLoadDll unhooked successfully.\n");
        }

        // Restoring original memory protection
        if (!VirtualProtectEx(proc.get(), addrLdrLoadDllLocal, 12, oldProtect, &oldProtect)) {
            printf("[!] Warning: Failed to restore original memory protection on LdrLoadDll: %lu\n", GetLastError());
        } else {
            printf("[+] Original memory protection restored on LdrLoadDll.\n");
        }

        // `proc` and `remoteAlloc` will be closed/freed automatically by `std::unique_ptr`
        // when they go out of scope.
        printf("[+] Injected memory (0x%p) freed and process handle closed automatically.\n", (void*)remoteAlloc.get());
    } else {
        printf("[+] Unhook delay not specified or zero. Exiting without unhooking.\n");
    }
   

    return 0;
}
