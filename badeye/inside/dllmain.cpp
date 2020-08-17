#include <Windows.h>
#include <atomic>
#include <cstdint>

// would use std::pair but that requires #include <map> which causes unresolved externals...
using ioctl_data = struct { HANDLE drv_handle; void* return_addr; };
#define READ_IOCTL 0x0222000
#define WRITE_IOCTL 0x0222004

namespace bedaisy
{
	struct beioctl
	{
		void* ret_addr;
		void* handle;
		std::uintptr_t base_addr;
		void* buffer;
		size_t buffer_size;
		size_t* bytes_read;
	};

	inline ioctl_data get_ioctl_data()
	{
		const auto wpm =
			reinterpret_cast<std::uint8_t*>(
				GetProcAddress(GetModuleHandleA("ntdll.dll"),
					"NtWriteVirtualMemory"));

		// ensure inline jump is installed...
		if (*reinterpret_cast<std::uint8_t*>(wpm) == 0xFF)
		{
			const auto shellcode_ptr = *reinterpret_cast<std::uint8_t**>(wpm + 6);
			const auto ioctl_handle = *reinterpret_cast<HANDLE*>(shellcode_ptr + 0x50);

			const auto lsasrv =
				reinterpret_cast<std::uintptr_t>(
					GetModuleHandleA("lsasrv.dll"));

			// 0f 1f 44 00 ? 8b f0 48 8b 0d ? ? ? ? 49 3b cd (proper return)
			return { ioctl_handle, reinterpret_cast<void*>(lsasrv + 0x36E3B) }; // windows 10 2004 RVA you will need to update for your winver! :)
		}
		return { {}, {} };
	}

	template <class T>
	inline T read(HANDLE proc_handle, std::uintptr_t addr)
	{
		if (!addr || !proc_handle)
			return {};

		T buffer;
		const auto [daisy_handle, return_addr] = get_ioctl_data();
		const beioctl ioctl_data
		{
			return_addr,
			proc_handle,
			addr,
			&buffer, 
			sizeof(T),
			nullptr
		};

		DWORD bytes_read;
		DeviceIoControl
		(
			daisy_handle,
			READ_IOCTL,
			(void*)&ioctl_data,
			sizeof ioctl_data,
			nullptr, 
			NULL,
			&bytes_read,
			nullptr
		);
		return buffer;
	}

	template <class T>
	inline void write(HANDLE proc_handle, std::uintptr_t addr, const T& data)
	{
		if (!proc_handle || !addr)
			return;

		const auto [daisy_handle, return_addr] = get_ioctl_data();
		const beioctl ioctl_data
		{
			return_addr,
			proc_handle,
			addr,
			(void*)&data,
			sizeof(T),
			nullptr
		};

		DWORD bytes_read;
		DeviceIoControl
		(
			daisy_handle,
			WRITE_IOCTL,
			(void*)&ioctl_data,
			sizeof ioctl_data,
			nullptr,
			NULL,
			&bytes_read,
			nullptr
		);
	}
}

void read_demo()
{
	OutputDebugStringA("[lsass] main thread created!");

	// pid 4 is system process....
	const auto system_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4); 

	 // global mapped... gunna be the same addr in system proc....
	const auto ntdll = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("ntdll.dll"));

	if(bedaisy::read<std::uint16_t>(system_process, ntdll) == 0x5A4D)
		OutputDebugStringA("[lsass] read MZ!");
	else
		OutputDebugStringA("[lsass] didnt read MZ!");
}

std::atomic<bool> init = false;
extern "C" NTSTATUS nt_close(void* handle)
{
	if (!init.exchange(true))
	{
		OutputDebugStringA("[lsass] creating thread!");
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&read_demo, NULL, NULL, NULL);
	}
	return NULL;
}