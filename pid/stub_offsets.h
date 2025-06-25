#ifndef STUB_OFFSETS_H
#define STUB_OFFSETS_H

#include <windows.h>

#define OFF_ADDRBLACKLISTSTR_PTR           0x00DB // RVA for ADDRBLACKLISTSTR_PTR
#define OFF_COMPAREWIDESTRINGS             0x0000 // RVA for COMPAREWIDESTRINGS
#define OFF_ORIGINAL_LDRLOADDLL_PROLOGUE   0x00E3 // RVA for ORIGINAL_LDRLOADDLL_PROLOGUE
#define OFF_REALLOADLIBRARY_PTR            0x00D3 // RVA for REALLOADLIBRARY_PTR
#define OFF_REHOOK_JMP_TO_REMOTESTUB       0x00EF // RVA for REHOOK_JMP_TO_REMOTESTUB
#define OFF_REMOTESTUB                     0x0026 // RVA for REMOTESTUB

#define STUB_FIXED_DATA_SIZE            0x28 // Size of the .data section (from ASM)
#define STUB_TOTAL_STATIC_SIZE          0xFB // Total size of .text$mn + .data sections (from ASM)

#endif // STUB_OFFSETS_H
