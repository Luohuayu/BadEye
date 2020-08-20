#pragma once
#include <Windows.h>
#include <cstdint>
#include <atomic>

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
			// + 6 into jump code is the address of where the jump goes to.
			const auto shellcode_ptr = *reinterpret_cast<std::uint8_t**>(wpm + 6); 
			// + 50 into the shellcode is the HARDCODED file handle used for DeviceIoControl...
			const auto ioctl_handle = *reinterpret_cast<HANDLE*>(shellcode_ptr + 0x50);

			// return address should be landing in this module
			// (its not actually spoofing return address, just informational, used in ioctl data...)
			const auto lsasrv =
				reinterpret_cast<std::uintptr_t>(
					GetModuleHandleA("lsasrv.dll"));

			// 0f 1f 44 00 ? 8b f0 48 8b 0d ? ? ? ? 49 3b cd (proper return)
			return { ioctl_handle, reinterpret_cast<void*>(lsasrv + 0x3B2AD) }; // windows 10 2004 RVA you will need to update for your winver! :)
		}
		return { {}, {} };
	}

	inline void read(HANDLE proc_handle, std::uintptr_t addr, void* buffer, std::size_t size)
	{
		if (!addr || !buffer || !size)
			return;

		const auto [daisy_handle, return_addr] = get_ioctl_data();
		const beioctl ioctl_data
		{
			return_addr,
			proc_handle,
			addr,
			buffer,
			size,
			(size_t*)0xFFFFFFF3423424
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
	}

	void write(HANDLE proc_handle, std::uintptr_t addr, void* buffer, std::size_t size)
	{
		if (!proc_handle || !addr)
			return;

		const auto [daisy_handle, return_addr] = get_ioctl_data();
		const beioctl ioctl_data
		{
			return_addr,
			proc_handle,
			addr,
			buffer,
			size,
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

	template <class T>
	inline T read(HANDLE proc_handle, std::uintptr_t addr)
	{
		if (!addr || !proc_handle)
			return {};

		T buffer{};
		read(proc_handle, addr, (void*)&buffer, sizeof(T));
		return buffer;
	}

	template <class T>
	inline void write(HANDLE proc_handle, std::uintptr_t addr, const T& data)
	{
		if (!proc_handle || !addr)
			return;

		write(proc_handle, addr, (void*)&data, sizeof(T));
	}
}