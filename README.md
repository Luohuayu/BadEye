# badeye

from ini file to kernel execution, BattlEye full privilege escalation.

# ini 2 lsass.exe

`BELauncher.ini` can specify which process it is going to protect and arguments to be passed to this process. For our use case we will want to protect `powershell.exe`. This will
allow us to JIT compile C# and call native windows functions (OpenProcess, WriteProcessMemory, etc...). All of the C# code/powershell code can be specified in `BEArg=""`.

# lsass.exe 2 ring 0

The reason why lsass.exe is a key program/context to be executing in, is because BattlEye inline hooks `NtReadVirtualMemory` and `NtWriteVirtualMemory`, this is well documented and has
been known for a while now (posted on UC even). BattlEye proxies the calls to these functions to their driver via `DeviceIoControl`.