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

// Helper for error reporting and exit
void FatalError(const std::wstring& msg, int code) {
    std::wcerr << L"[!] FATAL Error: " << msg << L" Error Code: " << GetLastError() << std::endl;
    exit(code);
}

// Helper to print bytes
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
    // Using MultiByteToWideChar with CP_UTF8 for robust conversion
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len == 0) {
        // Handle error or empty string
        return L"";
    }
    std::wstring ws(len - 1, L'\0'); // len-1 because null terminator is included in len
    if (MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len) == 0) {
        // Conversion failed
        return L"";
    }
    return ws;
}

// Reads blacklist DLLs from a file
std::vector<std::wstring> ReadBlacklistFromFile(const std::string& filename) {
    std::vector<std::wstring> blacklist_wstrings;
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::wcerr << L"[!] Error: Could not open blacklist file: " << s2ws(filename) << L". Make sure it exists." << std::endl;
        return blacklist_wstrings;
    }

    std::string line;
    std::wcout << L"[+] Blacklist loaded from '" << s2ws(filename) << L"':\n";
    while (std::getline(file, line)) {
        // Trim leading/trailing whitespace
        size_t first = line.find_first_not_of(" \t\n\r");
        if (std::string::npos == first) continue; // Skip empty or all-whitespace lines
        size_t last = line.find_last_not_of(" \t\n\r");
        line = line.substr(first, (last - first + 1));

        if (line.empty()) continue; // Skip if it became empty after trimming

        std::wstring wline = s2ws(line);
        if (wline.empty()) {
            std::wcerr << L"[!] Warning: Failed to convert string to WCHAR for line: \"" << s2ws(line) << L"\"." << std::endl;
            continue;
        }
        blacklist_wstrings.push_back(wline);
        std::wcout << L"    - " << wline << std::endl;
    }
    file.close();
    if (blacklist_wstrings.empty()) {
        std::wcout << L"[+] Blacklist file was read, but no valid entries were found." << std::endl;
    }
    return blacklist_wstrings;
}

// Macro for simplified error checking and cleanup
#define CHECK_WIN_API(api_call, error_msg, cleanup_lambda) \
    if (!(api_call)) {                                      \
        cleanup_lambda();                                   \
        FatalError(error_msg, __LINE__);                    \
    }

// Macro for simpler WriteProcessMemory
#define WRITE_REMOTE_MEM(proc_handle, addr, data, size, error_msg, cleanup_lambda) \
    CHECK_WIN_API(WriteProcessMemory(proc_handle, addr, data, size, nullptr), error_msg, cleanup_lambda)

// Global variables to store original bytes for unhooking
BYTE g_originalLdrLoadDllPrologue[12];
BYTE g_originalDbgUiTargetPrologue[12]; // To restore the DbgUi function
LPVOID g_addrLdrLoadDllLocal = nullptr;
LPVOID g_addrDbgUiHookTarget = nullptr;
HANDLE g_proc_handle = nullptr; // To be set in main for cleanup lambda access



int main(int argc, char* argv[]) {
    DWORD targetPid = 0;
    int unhookDelay = 0; // Initialize unhookDelay to 0

    auto print_usage = [&argv]() {
        std::wcout << L"Usage: " << s2ws(argv[0]) << L" -pid <process_id> [-unhook <seconds>]" << std::endl;
    };

    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "-pid") == 0) {
            if (++i < argc) targetPid = std::stoul(argv[i]);
            else { std::wcerr << L"[!] Error: -pid requires a process ID." << std::endl; print_usage(); return 1; }
        } else if (_stricmp(argv[i], "-unhook") == 0) {
            if (++i < argc) {
                try { unhookDelay = std::stoi(argv[i]); if (unhookDelay <= 0) { std::wcerr << L"[!] Error: -unhook requires a positive integer for seconds." << std::endl; return 1; } }
                catch (const std::exception& e) { std::wcerr << L"[!] Error: Invalid unhook delay value: " << s2ws(argv[i]) << L" (" << s2ws(e.what()) << L")" << std::endl; return 1; }
            } else { std::wcerr << L"[!] Error: -unhook requires a time in seconds." << std::endl; print_usage(); return 1; }
        } else {
            std::wcerr << L"[!] Error: Unknown argument: " << s2ws(argv[i]) << std::endl; print_usage(); return 1;
        }
    }

    if (targetPid == 0) {
        std::wcerr << L"[!] Error: Please specify a target process ID using -pid." << std::endl;
        print_usage(); return 1;
    }

    UniqueHandle proc;

    printf("[+] Attempting to attach to existing process with PID: %u...\n", targetPid);
    // Request necessary permissions for memory manipulation and thread suspension/resumption
    proc.reset(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME, FALSE, targetPid));
    CHECK_WIN_API(proc.get(), L"OpenProcess failed. Ensure you have sufficient permissions (e.g., Run as Administrator).", []{});
    printf("[+] Successfully attached to process with PID: %u.\n", targetPid);

    g_proc_handle = proc.get(); // Store process handle globally for cleanup lambda

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    CHECK_WIN_API(hNtdll, L"GetModuleHandleW failed for ntdll.dll", [&]{});

    // Get LdrLoadDll address
    g_addrLdrLoadDllLocal = (LPVOID)GetProcAddress(hNtdll, "LdrLoadDll");
    CHECK_WIN_API(g_addrLdrLoadDllLocal, L"GetProcAddress failed for LdrLoadDll", [&]{});
    printf("[+] ntdll.dll base: 0x%p. LdrLoadDll entry: 0x%p.\n", (void*)hNtdll, (void*)g_addrLdrLoadDllLocal);


	// Get LdrLoadDll address
    g_addrDbgUiHookTarget = (LPVOID)GetProcAddress(hNtdll, "DbgUiConvertStateChangeStructureEx");
    CHECK_WIN_API(g_addrDbgUiHookTarget, L"GetProcAddress failed for DbgUiConvertStateChangeStructureEx", [&]{});
    printf("[+] ntdll.dll base: 0x%p. DbgUiConvertStateChangeStructureEx entry: 0x%p.\n", (void*)hNtdll, (void*)g_addrDbgUiHookTarget);


    // Read and store original LdrLoadDll prologue bytes
    CHECK_WIN_API(ReadProcessMemory(proc.get(), g_addrLdrLoadDllLocal, g_originalLdrLoadDllPrologue, sizeof(g_originalLdrLoadDllPrologue), nullptr),
                  L"Failed to read original LdrLoadDll prologue", [&]{});
    PrintBytes("Original LdrLoadDll Prologue", g_originalLdrLoadDllPrologue, sizeof(g_originalLdrLoadDllPrologue));

    // Read and store original DbgUi function prologue bytes (12 bytes for the hook)
    CHECK_WIN_API(ReadProcessMemory(proc.get(), g_addrDbgUiHookTarget, g_originalDbgUiTargetPrologue, sizeof(g_originalDbgUiTargetPrologue), nullptr),
                  L"Failed to read original DbgUi target prologue", [&]{});
    PrintBytes("Original DbgUi Target Prologue (first 12 bytes)", g_originalDbgUiTargetPrologue, sizeof(g_originalDbgUiTargetPrologue));

    // Prepare blacklist strings and their pointer array for injection
    std::vector<std::wstring> blacklist_wstrings_storage = ReadBlacklistFromFile("blacklist.txt");
    if (blacklist_wstrings_storage.empty()) {
		FatalError(L"No DLL names found in blacklist.txt or file could not be read. Exiting.", -50);
    }

    // Calculate total size needed for blacklist string data and the array of pointers
    // This will be appended *after* the fixed g_remoteStubBytes in memory.
    SIZE_T remote_blacklist_strings_data_size = 0;
    for (const auto& ws : blacklist_wstrings_storage) {
        remote_blacklist_strings_data_size += (ws.length() + 1) * sizeof(WCHAR); // String + Null Terminator
        remote_blacklist_strings_data_size = (remote_blacklist_strings_data_size + 7) & ~7; // Ensure 8-byte alignment
    }

    // The size for the array of pointers (QWORDs), plus one for the null terminator
    SIZE_T remote_blacklist_ptrs_array_size = (blacklist_wstrings_storage.size() + 1) * sizeof(ULONGLONG);
    // Ensure 8-byte alignment for the pointer array itself
    remote_blacklist_ptrs_array_size = (remote_blacklist_ptrs_array_size + 7) & ~7;

    SIZE_T total_dynamic_blacklist_data_size = remote_blacklist_ptrs_array_size + remote_blacklist_strings_data_size;
    SIZE_T total_injected_size = g_remoteStubSize + total_dynamic_blacklist_data_size;

    // Verify if the total injected size fits into the chosen DbgUi function's available space.
    // DbgUiConvertStateChangeStructureEx size is 0x29B (763 bytes)
    const SIZE_T DBG_UI_FUNCTION_MAX_SIZE = 0x6AB;
    if (total_injected_size > DBG_UI_FUNCTION_MAX_SIZE) {
        FatalError(L"Calculated total injected size (stub + dynamic blacklist) is too large for the chosen DbgUi function. "
                   L"Total size: 0x" + std::to_wstring(total_injected_size) + L" bytes. "
                   L"DbgUi function max size: 0x" + std::to_wstring(DBG_UI_FUNCTION_MAX_SIZE) + L" bytes.", -100);
    }
	
    printf("[+] Calculated total injected size (stub code+data + dynamic blacklist): 0x%zX bytes (Max DbgUi size: 0x%zX bytes).\n", total_injected_size, DBG_UI_FUNCTION_MAX_SIZE);


    // Create the full buffer to be written to the remote process.
    // This buffer contains: [g_remoteStubBytes (code + static data)] + [dynamic blacklist data]
    std::vector<BYTE> full_injected_stub(g_remoteStubBytes, g_remoteStubBytes + g_remoteStubSize);
    full_injected_stub.resize(total_injected_size); // Expand to fit dynamic blacklist data

    // Calculate absolute remote address where the blacklist pointer array will start.
    // This is immediately after the g_remoteStubBytes within the same allocated region.
    LPVOID remote_blacklist_ptrs_array_addr = (LPVOID)((ULONG_PTR)g_addrDbgUiHookTarget + g_remoteStubSize);
    
    // Calculate the remote address where the blacklist strings data will start.
    LPVOID remote_blacklist_strings_start_addr = (LPVOID)((ULONG_PTR)remote_blacklist_ptrs_array_addr + remote_blacklist_ptrs_array_size);

    // Populate the blacklist pointers and strings into the 'full_injected_stub' buffer
    // The blacklist pointer array starts at `g_remoteStubSize` offset in `full_injected_stub`.
    // The blacklist strings start after the pointer array.
    
    SIZE_T current_offset_for_ptrs_in_buffer = g_remoteStubSize;
    SIZE_T current_offset_for_strings_in_buffer = g_remoteStubSize + remote_blacklist_ptrs_array_size;

    std::vector<ULONGLONG> current_blacklist_ptrs_values; // Temporary local storage for pointers

    // Write strings into the buffer first, and collect their remote addresses
    for (const auto& ws : blacklist_wstrings_storage) {
        SIZE_T name_len_bytes = (ws.length() + 1) * sizeof(WCHAR);
        
        // Ensure there's enough space in the buffer for the string
        if (current_offset_for_strings_in_buffer + name_len_bytes > total_injected_size) {
            FatalError(L"Buffer overflow preparing blacklist strings. Blacklist is too large.", -102);
        }

        // Copy WCHAR string into the full_injected_stub buffer
        memcpy(&full_injected_stub[current_offset_for_strings_in_buffer], ws.c_str(), name_len_bytes);
        
        // Store the remote absolute address of this string
        current_blacklist_ptrs_values.push_back((ULONGLONG)((ULONG_PTR)g_addrDbgUiHookTarget + current_offset_for_strings_in_buffer));

        current_offset_for_strings_in_buffer += name_len_bytes;
        current_offset_for_strings_in_buffer = (current_offset_for_strings_in_buffer + 7) & ~7; // Maintain 8-byte alignment
    }
    current_blacklist_ptrs_values.push_back(0); // Null terminator for the pointer array

    // Now write the collected pointer values into the buffer
    // Ensure there's enough space in the buffer for the pointer array
    if (current_offset_for_ptrs_in_buffer + current_blacklist_ptrs_values.size() * sizeof(ULONGLONG) > total_injected_size) {
        FatalError(L"Buffer overflow preparing blacklist pointers. Blacklist is too large.", -103);
    }
    memcpy(&full_injected_stub[current_offset_for_ptrs_in_buffer], current_blacklist_ptrs_values.data(), current_blacklist_ptrs_values.size() * sizeof(ULONGLONG));


    // Patch the fixed part of the stub buffer (g_remoteStubBytes portion) with calculated remote addresses
    // realLoadLibrary_ptr gets the absolute address of LdrLoadDll
    *(UINT64*)&full_injected_stub[OFF_REALLOADLIBRARY_PTR] = (UINT64)g_addrLdrLoadDllLocal;
    
    // addrBlacklistStr_ptr points to the start of the dynamically allocated blacklist pointer array
    *(UINT64*)&full_injected_stub[OFF_ADDRBLACKLISTSTR_PTR] = (UINT64)remote_blacklist_ptrs_array_addr;
    
    // original_ldrloadDll_prologue location within the remote injected stub
    // This is already copied from local g_originalLdrLoadDllPrologue into full_injected_stub.
    // The stub itself uses a relative LEA to find this within its own body, so no absolute address patching is needed here.
    // However, for clarity and if the stub structure changes, keep the copy logic.
    memcpy(&full_injected_stub[OFF_ORIGINAL_LDRLOADDLL_PROLOGUE], g_originalLdrLoadDllPrologue, sizeof(g_originalLdrLoadDllPrologue));

    // rehook_jmp_to_remotestub location within the remote injected stub
    // Prepare the JMP instruction that rehooks LdrLoadDll to RemoteStub and write it into the stub's buffer
    BYTE rehook_jmp_template[12] = { 0x48, 0xB8, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xE0 }; // mov rax, addr; jmp rax
    *(UINT64*)(rehook_jmp_template + 2) = (UINT64)((ULONG_PTR)g_addrDbgUiHookTarget + OFF_REMOTESTUB); // Target is the stub's entry point
    memcpy(&full_injected_stub[OFF_REHOOK_JMP_TO_REMOTESTUB], rehook_jmp_template, sizeof(rehook_jmp_template));


    printf("[+] Writing patched stub and dynamic blacklist data (total size 0x%zX) to DbgUi target 0x%p.\n", total_injected_size, (void*)g_addrDbgUiHookTarget);
    DWORD oldProtectionDbgUi = 0;
    CHECK_WIN_API(VirtualProtectEx(proc.get(), g_addrDbgUiHookTarget, total_injected_size, PAGE_EXECUTE_READWRITE, &oldProtectionDbgUi),
                  L"Failed to change DbgUi target memory protection to RWX for stub and blacklist", [&]{});
    printf("    Original DbgUi protection was: 0x%lX.\n", oldProtectionDbgUi);

    WRITE_REMOTE_MEM(proc.get(), g_addrDbgUiHookTarget, full_injected_stub.data(), total_injected_size, L"Failed to write stub and blacklist data to DbgUi target", [&]{
        // Attempt to restore original protection if write fails, though memory content might be corrupted
        VirtualProtectEx(proc.get(), g_addrDbgUiHookTarget, total_injected_size, oldProtectionDbgUi, &oldProtectionDbgUi);
    });
    printf("[+] Stub and dynamic blacklist data written to DbgUi target.\n");

    printf("[+] Changing remote stub memory protection (0x%p) from RWX to RX...\n", (void*)g_addrDbgUiHookTarget);
    // Restore original protection, but ensure it's at least RX for the entire injected region
    CHECK_WIN_API(VirtualProtectEx(proc.get(), g_addrDbgUiHookTarget, total_injected_size, PAGE_EXECUTE_READ, &oldProtectionDbgUi),
                  L"Failed to change remote stub memory protection to RX", [&]{});
    printf("    Successfully changed remote stub memory protection to RX.\n");


    // Now, hook LdrLoadDll to jump to our injected stub
    BYTE hook_ldrloaddll[12] = { 0x48, 0xB8 }; // mov rax, <64-bit addr>
    *(UINT64*)(hook_ldrloaddll + 2) = (ULONGLONG)((ULONG_PTR)g_addrDbgUiHookTarget + OFF_REMOTESTUB);
    hook_ldrloaddll[10] = 0xFF; hook_ldrloaddll[11] = 0xE0; // jmp rax

    DWORD oldProtectLdrLoadDll = 0;
    printf("[+] Changing memory protection of LdrLoadDll (0x%p) to RWX...\n", (void*)g_addrLdrLoadDllLocal);
    CHECK_WIN_API(VirtualProtectEx(proc.get(), g_addrLdrLoadDllLocal, 12, PAGE_EXECUTE_READWRITE, &oldProtectLdrLoadDll),
                  L"VirtualProtectEx failed (pre-hook LdrLoadDll)", [&]{});
    printf("    Original LdrLoadDll protection was: 0x%lX.\n", oldProtectLdrLoadDll);

    printf("[+] Writing hook bytes to LdrLoadDll at 0x%p.\n", (void*)g_addrLdrLoadDllLocal);
    CHECK_WIN_API(WriteProcessMemory(proc.get(), g_addrLdrLoadDllLocal, hook_ldrloaddll, 12, nullptr),
                  L"Failed to write hook to LdrLoadDll",
                  [&]{ VirtualProtectEx(proc.get(), g_addrLdrLoadDllLocal, 12, oldProtectLdrLoadDll, &oldProtectLdrLoadDll); });
    printf("[+] LdrLoadDll hooked successfully to stub at 0x%p.\n", (void*)g_addrDbgUiHookTarget);
    
    printf("[+] Hook installed for PID %u.\n", targetPid);

    if (unhookDelay > 0) {
        printf("[+] Unhooking in %d seconds...\n", unhookDelay);
        Sleep(unhookDelay * 1000);

        printf("[+] Initiating cleanup: Restoring LdrLoadDll and DbgUi function, closing handles...\n");

        // Restore LdrLoadDll original bytes
        // Need to ensure the memory is writable first for the unhook operation
        DWORD temp_old_protect_ldrloaddll = 0;
        if (!VirtualProtectEx(proc.get(), g_addrLdrLoadDllLocal, 12, PAGE_EXECUTE_READWRITE, &temp_old_protect_ldrloaddll)) {
            printf("[!] Warning: Failed to change LdrLoadDll protection for unhook: %lu\n", GetLastError());
        }
        if (!WriteProcessMemory(proc.get(), g_addrLdrLoadDllLocal, g_originalLdrLoadDllPrologue, sizeof(g_originalLdrLoadDllPrologue), nullptr)) {
            printf("[!] Error: Failed to unhook LdrLoadDll: %lu\n", GetLastError());
        } else {
            printf("[+] LdrLoadDll unhooked successfully.\n");
        }
        // Restore original protection of LdrLoadDll
        if (!VirtualProtectEx(proc.get(), g_addrLdrLoadDllLocal, 12, oldProtectLdrLoadDll, &temp_old_protect_ldrloaddll)) {
            printf("[!] Warning: Failed to restore original protection on LdrLoadDll after unhook: %lu\n", GetLastError());
        } else {
            printf("[+] Original memory protection restored on LdrLoadDll.\n");
        }

        // Restore DbgUi target function original bytes
        // No explicit VirtualFreeEx needed as the memory was part of the original DLL's section,
        // and we are just restoring its original prologue bytes.
        DWORD temp_old_protect_dbguitarget = 0;
        // Make DbgUi target memory writable temporarily for restoration
        if (!VirtualProtectEx(proc.get(), g_addrDbgUiHookTarget, sizeof(g_originalDbgUiTargetPrologue), PAGE_EXECUTE_READWRITE, &temp_old_protect_dbguitarget)) {
            printf("[!] Warning: Failed to change DbgUi target protection for unhook: %lu\n", GetLastError());
        }
        if (!WriteProcessMemory(proc.get(), g_addrDbgUiHookTarget, g_originalDbgUiTargetPrologue, sizeof(g_originalDbgUiTargetPrologue), nullptr)) {
            printf("[!] Error: Failed to restore DbgUi target function: %lu\n", GetLastError());
        } else {
            printf("[+] DbgUi target function (0x%p) restored successfully.\n", (void*)g_addrDbgUiHookTarget);
        }
        // Restore original protection of DbgUi target function
        if (!VirtualProtectEx(proc.get(), g_addrDbgUiHookTarget, sizeof(g_originalDbgUiTargetPrologue), oldProtectionDbgUi, &temp_old_protect_dbguitarget)) {
            printf("[!] Warning: Failed to restore original protection on DbgUi target after unhook: %lu\n", GetLastError());
        } else {
            printf("[+] Original memory protection restored on DbgUi target.\n");
        }

        printf("[+] Process handle closed automatically.\n");
    } else {
        printf("[+] Unhook delay not specified or zero. Exiting without unhooking. Manual cleanup may be required.\n");
    }

    return 0;
}
