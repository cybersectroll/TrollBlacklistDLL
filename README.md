# TrollBlacklistDLL
```diff
! UPDATE 30/06/2025 
! Released c# version - refer to csharp folder
! Strongly advised to use cpp, if that fails, try c#
```
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

**note/correction: Edr #1 with pid.exe technique is successful in the sense it blocks dll from loading but later on, loading rubeus is still detected. likely, its doing a separate scan from (amsi) on the virtualalloc call for rubeus.**

**note: the process of injection (virtuallalocex, writeprocessmemory) also must respect the av/edr parent-child relationship for example Edr #1 detects injections to cmd.exe but powershell is ok**

**note: you need to find out if Dllname passed to LdrLoadDll whether its a full path or relative path when inserting into blacklist.txt**

```
Update!
For the AV #1 detection on path.exe - was able to evade detection (stop amsi.dll + run rubeus, av_edr.dll still loads) with the c# dll version
For the EDR #3 werfault on path.exe - was able to get it to work (stop amsi.dll + run rubeus, av_edr.dll still loads) on the c# exe/dll version <- I have no idea why it works
I re-emphasize that the AV/EDR might be bypassing LdrLoadDLL calls for the av_edr.dll 
```

## Release
Refer to TrollBlacklistDLL.zip for the compiled binaries

## Upgrades (not pursuing)
- there is a race condition, trying to resolve that
- for pid.exe find other suitable ntdll functions (technically you can try other dlls) to overwrite, now its hardcoded, may not always work
- get it to work with the problematic ones in table -> I believe the werfault is fixable, likely some sort of race condition   

## Disclaimer
Should only be used for educational purposes!
