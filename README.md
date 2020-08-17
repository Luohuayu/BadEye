# BadEye

BattlEye proxies NtReadVirtualMemory and NtWriteVirtualMemory in lsass.exe/csrss.exe but doesnt bother to check the handle privilage....

<img src="https://imgur.com/5MjFoHg.png"/>

you cannot use this to read/write the process that battleye is protecting but you can use
this to read/write any other process you can open a simple handle too. `Rust`, `Valorant`, you name it, just open a `PROCESS_QUERY_LIMITED_INFORMATION` handle and pass it to `BEDaisy`. The reason
this works is two fold, firstly BattlEye assumes that the handle already has this access, secondly BattlEye only uses the handle to get the `EPROCESS` so they can call `MmCopyVirtualMemory`. You can see
this in my runtime logs of `BEDaisy`.

```
01450790	126.99650574	[GoodEye]MmCopyVirtualMemory called from: 0xFFFFF804DEFE2E12	
01450791	126.99652100	[GoodEye]     - SourceProcess: upc.exe	
01450792	126.99652100	[GoodEye]     - SourceAddress: 0x00000000078EFBEC	
01450793	126.99652100	[GoodEye]     - TargetProcess: lsass.exe	
01450794	126.99652100	[GoodEye]     - TargetAddress: 0x000000B470EFE1F0	
01450795	126.99652100	[GoodEye]     - BufferSize: 0x000000000000001C	
01450796	126.99662018	[GoodEye]IofCompleteRequest called from: 0xFFFFF804DEFE2E3D	
01450797	126.99662018	[GoodEye]     - Request Called From: lsass.exe	
01450798	126.99662018	[GoodEye]     - IRP_MJ_DEVICE_CONTROL!	
01450799	126.99663544	[GoodEye]     - IoControlCode:  0x0000000000222000	// ioctl read
01450800	126.99663544	[GoodEye]     - InputBufferLength: 0x0000000000000030	
01450801	126.99663544	[GoodEye]     - OutputBufferLength: 0x0000000000000000	
01450802	126.99663544	[GoodEye]     - UserBuffer: 0x0000000000000000	
01450803	126.99663544	[GoodEye]     - MdlAddress: 0x0000000000000000	
01450804	126.99663544	[GoodEye]     - SystemBuffer: 0xFFFFB78765A0ECC0
```

# limitations

- you cannot read/write kernel addresses 
- you cannot write to readonly memory with this
- the `PULONG NumberOfBytesRead` pointer cannot be a kernel address (sorry tried lol)
- you cannot read/write to the process being protected by battleye
- bedaisy has to be loaded for this to work
- you must be inside of lsass.exe
- lsass.exe cannot be a protected process. (some systems protect lsass.exe)

# lsass.exe/csrss.exe

This section will go into detail about what exactly is going on here. csrss.exe/lsass.exe have handles to all processes and since battleye strips the R/W access of the handle that these processes have
to the game it can cause system instability. Thus bedaisy writes two pages of shellcode to both processes and inline hooks `NtReadVirtualMemory` and `NtWriteVirtualMemory`.

If you run a battleye protected game, open cheat engine, attach to `lsass.exe`, and navigate to `NtReadVirtualMemory`/`NtWriteVirtualMemory` you will see this inline hook...

<img src="https://imgur.com/E7KAeoV.png"/>

This inline hook jumps to shellcode that packages all of the parameter values passed to `NtReadVirtualMemory` into the stack and then jumps to `DeviceIoControl`...

<img src="https://imgur.com/DpFyC9p.png"/>

Now that you have a basic understanding of how this system works (and sorta why it is), lets look at what we can do!
To begin we need to extract the driver handle at runtime, this can be done simply by extracting the address of the shellcode out of the inline hook of `NtReadVirtualMemory`. Now that we have 
the handle to the driver we can start sending IOCTL's to BattlEye. The IOCTL data is not encrypted nor complicated... this is what it looks like:

```cpp
struct beioctl
{
	void*    ret_addr;
	HANDLE   handle;
	void*    base_addr;
	void*    buffer;
	size_t   buffer_size;
	size_t*  bytes_read;
};
```

In order to use this ioctl/functionality of bedaisy you need to put a valid return address into this structure. You can do that by sig scanning `lsasrv.dll` with this signature:
`0f 1f 44 00 ? 8b f0 48 8b 0d ? ? ? ? 49 3b cd` the address of this instruction is what you want to be your return address.


