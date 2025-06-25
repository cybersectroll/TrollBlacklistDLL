# TrollBlacklistDLL
Reads blacklist.txt and blocks dlls from loading with option to unblock subsequently. Patches LdrLoadDll in local/remote process to return dll not found.
- path.exe
  - spawns new process suspended followed by VirtualAllocEx, VirtualProtectEx, WriteProcessMemory, ResumeThread
- pid.exe
  - injects into existing process using VirtualProtectEx and WriteProcessMemory **only**
 
  
## path.exe
usage: path.exe -path <path to file> [optional]-unhook <time in seconds>
![Image](https://github.com/user-attachments/assets/c90a01cc-85a5-4f53-a596-f773d6834d04)

## pid.exe
usage: pid.exe -pid <local/remote $PID> [optional]-unhook <time in seconds>
![Image](https://github.com/user-attachments/assets/da0cd08e-7260-4cef-9dc4-137622076cab)


## Hmm.. 
can it block av/edr dlls? Refer to table - obviously it depends how the av/edr dlls are loaded in the first place
![Image](https://github.com/user-attachments/assets/c14502a4-2833-43a6-8f82-2f66fdfdbc2b)

## Release
Refer to TrollBlacklistDLL.zip for the compiled binaries

## Upgrades (not pursuing)
- convert it to c#
- for pid.exe find other suitable ntdll functions to overwrite, now its hardcoded, may not always work
- get it to work with the problematic ones in truthtable

## Disclaimer
Should only be used for educational purposes!
