# badeye

Its well known that battleye proxies calls to `NtReadVirtualMemory/NtWriteVirtualMemory` to their driver via DeviceIoControl in both `lsass.exe` and `csrss.exe`. Although csrss.exe
is not something you can inject from usermode, lsass.exe is (although it can be protected, depends on your system/hvci). 

The reason this proxy of a syscall is a vulnerability is simply because their is no validation of R/W access on the specified handle passed to `BEDaisy`. In other words: you can
open a handle with `PROCESS_QUERY_LIMITED_INFORMATION` and use that handle to read/write any usermode memory that is also read/writeable. The handle access is not important to bedaisy
rather they use the handle to get the EPROCESS of the process that the handle is opened on.

<img src="https://imgur.com/fdthCQb.png"/>

As you can see you can open any handle with any access and then pass it along to bedaisy and it will read/write for you...