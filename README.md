# TrollBlacklistDLL
Reads blacklist.txt and blocks dlls from loading with option to unblock subsequently
- path.exe
  - spawns new process suspended followed by VirtualAllocEx, WriteProcessMemory, ResumeThread
- pid.exe
  - injects into existing process using WriteProcessMemory **only**
  
## path.exe
<br>
![Image](https://github.com/user-attachments/assets/f92136a7-5504-47f8-8d1a-56be20aa4f19)
usage: path.exe -path <path to file> [optional]-unhook <seconds>

## pid.exe
<br>
![Image](https://github.com/user-attachments/assets/3aeb6440-9252-4165-96dd-73759480d2d7)
usage: pid.exe -pid <local/remote $PID> [optional]-unhook <seconds>

## Hmm.. 
<br>
can it block av/edr dlls? Refer to table
![Image](https://github.com/user-attachments/assets/7ce1f875-9613-435e-85f9-c34c3bb57840)

## Disclaimer
Should only be used for educational purposes!
