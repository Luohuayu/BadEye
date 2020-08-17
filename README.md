# i am writing this atm so come back later

# badeye

<img src="https://imgur.com/5MjFoHg.png"/>


# lsass.exe/csrss.exe

This section will go into detail about what exactly is going on here. csrss.exe/lsass.exe have handles to all processes and since battleye strips the R/W access of the handle that these processes have
to the game it can cause system instability. Thus bedaisy writes two pages of shellcode to both processes and inline hooks `NtReadVirtualMemory` and `NtWriteVirtualMemory`.

If you run a battleye protected game, open cheat engine, attach to `lsass.exe`, and navigate to `NtReadVirtualMemory`/`NtWriteVirtualMemory` you will see this inline hook...