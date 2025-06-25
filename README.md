# TrollBlacklistDLL
Reads blacklist.txt and blocks dlls from loading with option to unblock subsequently
- path.exe
  - spawns new process suspended followed by VirtualAllocEx, VirtualProtectEx, WriteProcessMemory, ResumeThread
- pid.exe
  - injects into existing process using VirtualProtectEx and WriteProcessMemory **only**
 
  
## path.exe
usage: path.exe -path <path to file> [optional]-unhook <seconds>
![Image](https://github.com/user-attachments/assets/c90a01cc-85a5-4f53-a596-f773d6834d04)

## pid.exe
usage: pid.exe -pid <local/remote $PID> [optional]-unhook <seconds>
![Image](https://github.com/user-attachments/assets/da0cd08e-7260-4cef-9dc4-137622076cab)


## Hmm.. 
can it block av/edr dlls? Refer to table
![Image](https://github.com/user-attachments/assets/3956ce4b-658f-4aa7-93b2-06bd09343016)

## Disclaimer
Should only be used for educational purposes!
