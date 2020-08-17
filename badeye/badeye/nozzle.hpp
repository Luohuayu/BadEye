/*
    MIT License
    
    Copyright (c) 2020 xerox
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cassert>
#include <DbgHelp.h>
#include <functional>

#pragma comment(lib, "Dbghelp.lib")
#define FIND_NT_HEADER(x) reinterpret_cast<PIMAGE_NT_HEADERS>( uint64_t(x) + reinterpret_cast<PIMAGE_DOS_HEADER>(x)->e_lfanew )
#define RET_CHK(x)\
if (!x)\
{\
LOG_LAST_ERROR();\
return false;\
}\

//
// coded by paracord.
// see: https://github.com/haram/splendid_implanter/blob/master/splendid_implanter/win_utils.hpp
//
namespace util
{
	using uq_handle = std::unique_ptr<void, decltype(&CloseHandle)>;
	inline void open_binary_file(const std::string& file, std::vector<uint8_t>& data)
	{
		std::ifstream fstr(file, std::ios::binary);
		fstr.unsetf(std::ios::skipws);
		fstr.seekg(0, std::ios::end);

		const auto file_size = fstr.tellg();

		fstr.seekg(NULL, std::ios::beg);
		data.reserve(static_cast<uint32_t>(file_size));
		data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr), std::istream_iterator<uint8_t>());
	}

	inline uint32_t get_process_id(const std::wstring_view process_name)
	{
		// open a system snapshot of all loaded processes
		uq_handle snap_shot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle };

		if (snap_shot.get() == INVALID_HANDLE_VALUE)
			return NULL;

		PROCESSENTRY32W process_entry{ sizeof(PROCESSENTRY32W) };

		// enumerate through processes
		for (Process32FirstW(snap_shot.get(), &process_entry); Process32NextW(snap_shot.get(), &process_entry); )
			if (std::wcscmp(process_name.data(), process_entry.szExeFile) == NULL)
				return process_entry.th32ProcessID;

		return NULL;
	}

	inline std::pair<void*, std::wstring> get_module_data(HANDLE process_handle, const std::wstring_view module_name)
	{
		auto loaded_modules = std::make_unique<HMODULE[]>(64);
		DWORD loaded_module_sz = 0;

		// enumerate all modules by handle, using size of 512 since the required size is in bytes, and an HMODULE is 8 bytes large.
		if (!EnumProcessModules(process_handle, loaded_modules.get(), 512, &loaded_module_sz))
			return {};

		for (auto i = 0u; i < loaded_module_sz / 8u; i++)
		{
			wchar_t file_name[MAX_PATH] = L"";

			// get the full working path for the current module
			if (!GetModuleFileNameExW(process_handle, loaded_modules.get()[i], file_name, _countof(file_name)))
				continue;

			// module name returned will be a full path, check only for file name sub string.
			if (std::wcsstr(file_name, module_name.data()) != nullptr)
				return { loaded_modules.get()[i], file_name };
		}

		return {};
	}

	inline std::vector<uint8_t> get_file_data(const HANDLE file_handle, const std::wstring_view file_path)
	{
		const auto file_size = std::filesystem::file_size(file_path);
		std::vector<uint8_t> file_bytes{};
		file_bytes.resize(file_size);

		DWORD bytes_read = 0;
		if (!ReadFile(file_handle, file_bytes.data(), static_cast<DWORD>(file_size), &bytes_read, nullptr))
			return {};

		return file_bytes;
	}

	inline bool enable_privilege(const std::wstring_view privilege_name)
	{
		HANDLE token_handle = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
			return false;

		LUID luid{};
		if (!LookupPrivilegeValueW(nullptr, privilege_name.data(), &luid))
			return false;

		TOKEN_PRIVILEGES token_state{};
		token_state.PrivilegeCount = 1;
		token_state.Privileges[0].Luid = luid;
		token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(token_handle, FALSE, &token_state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
			return false;

		CloseHandle(token_handle);
		return true;
	}
}

namespace nozzle
{
	//
	// class programmed by wlan
	// link: https://github.com/not-wlan/drvmap/blob/master/drvmap/drv_image.hpp
	//
	class pe_image
	{
		std::vector<uint8_t> m_image;
		std::vector<uint8_t> m_image_mapped;
		PIMAGE_DOS_HEADER m_dos_header = nullptr;
		PIMAGE_NT_HEADERS64 m_nt_headers = nullptr;
		PIMAGE_SECTION_HEADER m_section_header = nullptr;

	public:
		pe_image() {};
		pe_image(std::uint8_t* image, std::size_t size);
		pe_image(std::vector<uint8_t> image);
		size_t size() const;
		uintptr_t entry_point() const;
		void map();
		static bool process_relocation(size_t image_base_delta, uint16_t data, uint8_t* relocation_base);
		void relocate(uintptr_t base) const;

		template<typename T>
		__forceinline T* get_rva(const unsigned long offset)
		{
			return (T*)::ImageRvaToVa(m_nt_headers, m_image.data(), offset, nullptr);
		}

		void fix_imports(const std::function<uintptr_t(std::string_view)> get_module, const std::function<uintptr_t(uintptr_t, const char*)> get_function);
		void* data();
		size_t header_size();
	};

	pe_image::pe_image(std::uint8_t* image, std::size_t size)
	{
		m_image = std::vector<std::uint8_t>(image, image + size);
		m_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
		m_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>((uintptr_t)m_dos_header + m_dos_header->e_lfanew);
		m_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>((uintptr_t)(&m_nt_headers->OptionalHeader) + m_nt_headers->FileHeader.SizeOfOptionalHeader);
	}

	pe_image::pe_image(std::vector<uint8_t> image)
		: m_image(std::move(image))
	{
		m_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
		m_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>((uintptr_t)m_dos_header + m_dos_header->e_lfanew);
		m_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>((uintptr_t)(&m_nt_headers->OptionalHeader) + m_nt_headers->FileHeader.SizeOfOptionalHeader);
	}

	size_t pe_image::size() const
	{
		return m_nt_headers->OptionalHeader.SizeOfImage;
	}

	uintptr_t pe_image::entry_point() const
	{
		return m_nt_headers->OptionalHeader.AddressOfEntryPoint;
	}

	void pe_image::map()
	{

		m_image_mapped.clear();
		m_image_mapped.resize(m_nt_headers->OptionalHeader.SizeOfImage);
		std::copy_n(m_image.begin(), m_nt_headers->OptionalHeader.SizeOfHeaders, m_image_mapped.begin());

		for (size_t i = 0; i < m_nt_headers->FileHeader.NumberOfSections; ++i)
		{
			const auto& section = m_section_header[i];
			const auto target = (uintptr_t)m_image_mapped.data() + section.VirtualAddress;
			const auto source = (uintptr_t)m_dos_header + section.PointerToRawData;
			std::copy_n(m_image.begin() + section.PointerToRawData, section.SizeOfRawData, m_image_mapped.begin() + section.VirtualAddress);
		}
	}

	bool pe_image::process_relocation(uintptr_t image_base_delta, uint16_t data, uint8_t* relocation_base)
	{
#define IMR_RELOFFSET(x)			(x & 0xFFF)

		switch (data >> 12 & 0xF)
		{
		case IMAGE_REL_BASED_HIGH:
		{
			const auto raw_address = reinterpret_cast<int16_t*>(relocation_base + IMR_RELOFFSET(data));
			*raw_address += static_cast<unsigned long>(HIWORD(image_base_delta));
			break;
		}
		case IMAGE_REL_BASED_LOW:
		{
			const auto raw_address = reinterpret_cast<int16_t*>(relocation_base + IMR_RELOFFSET(data));
			*raw_address += static_cast<unsigned long>(LOWORD(image_base_delta));
			break;
		}
		case IMAGE_REL_BASED_HIGHLOW:
		{
			const auto raw_address = reinterpret_cast<size_t*>(relocation_base + IMR_RELOFFSET(data));
			*raw_address += static_cast<size_t>(image_base_delta);
			break;
		}
		case IMAGE_REL_BASED_DIR64:
		{
			auto UNALIGNED raw_address = reinterpret_cast<DWORD_PTR UNALIGNED*>(relocation_base + IMR_RELOFFSET(data));
			*raw_address += image_base_delta;
			break;
		}
		case IMAGE_REL_BASED_ABSOLUTE: // No action required
		case IMAGE_REL_BASED_HIGHADJ: // no action required
		{
			break;
		}
		default:
		{
			throw std::runtime_error("gay relocation!");
			return false;
		}

		}
#undef IMR_RELOFFSET

		return true;
	}

	void pe_image::relocate(uintptr_t base) const
	{
		if (m_nt_headers->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
			return;

		ULONG total_count_bytes;
		const auto nt_headers = ImageNtHeader((void*)m_image_mapped.data());
		auto relocation_directory = (PIMAGE_BASE_RELOCATION)::ImageDirectoryEntryToData(nt_headers, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &total_count_bytes);
		auto image_base_delta = static_cast<uintptr_t>(static_cast<uintptr_t>(base) - (nt_headers->OptionalHeader.ImageBase));
		auto relocation_size = total_count_bytes;

		void* relocation_end = reinterpret_cast<uint8_t*>(relocation_directory) + relocation_size;
		while (relocation_directory < relocation_end)
		{
			auto relocation_base = ::ImageRvaToVa(nt_headers, (void*)m_image_mapped.data(), relocation_directory->VirtualAddress, nullptr);
			auto num_relocs = (relocation_directory->SizeOfBlock - 8) >> 1;
			auto relocation_data = reinterpret_cast<PWORD>(relocation_directory + 1);

			for (unsigned long i = 0; i < num_relocs; ++i, ++relocation_data)
			{
				if (process_relocation(image_base_delta, *relocation_data, (uint8_t*)relocation_base) == FALSE)
					return;
			}
			relocation_directory = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocation_data);
		}
	}

	template<typename T>
	__forceinline T* ptr_add(void* base, uintptr_t offset)
	{
		return (T*)(uintptr_t)base + offset;
	}

	void pe_image::fix_imports(const std::function<std::uintptr_t(std::string_view)> get_module, const std::function<uintptr_t(uintptr_t, const char*)> get_function)
	{

		ULONG size;
		auto import_descriptors = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(::ImageDirectoryEntryToData(m_image.data(), FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size));

		if (!import_descriptors)
			return;

		for (; import_descriptors->Name; import_descriptors++)
		{
			IMAGE_THUNK_DATA* image_thunk_data;
			const auto module_name = get_rva<char>(import_descriptors->Name);
			const auto module_base = get_module(module_name);

			if (import_descriptors->OriginalFirstThunk)
				image_thunk_data = get_rva<IMAGE_THUNK_DATA>(import_descriptors->OriginalFirstThunk);
			else
				image_thunk_data = get_rva<IMAGE_THUNK_DATA>(import_descriptors->FirstThunk);

			auto image_func_data = get_rva<IMAGE_THUNK_DATA64>(import_descriptors->FirstThunk);
			for (; image_thunk_data->u1.AddressOfData; image_thunk_data++, image_func_data++)
			{
				uintptr_t function_address;
				const auto image_import_by_name = get_rva<IMAGE_IMPORT_BY_NAME>(*(DWORD*)image_thunk_data);
				const auto name_of_import = static_cast<char*>(image_import_by_name->Name);
				function_address = get_function(module_base, name_of_import);
				image_func_data->u1.Function = function_address;
			}
		}
	}

	void* pe_image::data()
	{
		return m_image_mapped.data();
	}

	size_t pe_image::header_size()
	{
		return m_nt_headers->OptionalHeader.SizeOfHeaders;
	}

	class injector
	{
	public:
		injector() {};
		injector(void* pe_image, std::size_t size, unsigned pid);
		injector(std::vector<std::uint8_t> image_buffer, unsigned pid);
		injector(const char* path, unsigned pid);

		void* inject();
		void hook_entry();
		void set_target(unsigned pid);
		void set_target(std::wstring proc_name);

		void* get_pe_image() const;
		void* get_allocated_base() const;
		unsigned get_target() const;
	private:
		pe_image image;
		unsigned target_pid;
		std::vector<std::uint8_t> image_buffer;
		HANDLE target_handle;
		void* alloc_base;

		void write(void* addr, void* buffer, std::size_t size);
		void read(void* addr, void* buffer, std::size_t size);

		template <class T>
		T read(void* addr)
		{
			if (!addr)
				return {};
			T buffer;
			read(addr, &buffer, sizeof(T));
			return buffer;
		}

		template <class T>
		void write(void* addr, const T& data)
		{
			if (!addr)
				return;
			write(addr, (void*)&data, sizeof(T));
		}
	};

	injector::injector(void* pe_image, std::size_t size, unsigned pid)
		:
		target_pid(pid),
		target_handle(::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid))
	{}

	injector::injector(const char* path, unsigned pid)
		:
		target_pid(pid)
	{
		std::vector<std::uint8_t> image_buffer;
		util::open_binary_file(path, image_buffer);
		this->image_buffer = image_buffer;
		std::printf("[+] enabled debug priv => %d\n", util::enable_privilege(L"SeDebugPrivilege"));
		this->target_handle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		std::printf("[+] target handle => %p\n", target_handle);
	}

	injector::injector(std::vector<std::uint8_t> image_buffer, unsigned pid)
		:
		image_buffer(image_buffer),
		target_pid(pid),
		target_handle(::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid))
	{}

	void* injector::inject()
	{
		image = pe_image(image_buffer);

		//
		// only resolves globally mapped dll imports.
		//
		static const auto _get_module = [](std::string_view module_name) -> std::uintptr_t
		{
			return reinterpret_cast<std::uintptr_t>(LoadLibraryA(module_name.data()));
		};

		//
		// only resolves ntdll.dll, kernel32.dll, and user32.dll imports
		//
		static const auto _get_function = [](std::uintptr_t module_base, const char* module_name) -> std::uintptr_t
		{
			return reinterpret_cast<std::uintptr_t>(GetProcAddress(reinterpret_cast<HMODULE>(module_base), module_name));
		};

		alloc_base = VirtualAllocEx(
			target_handle,
			NULL,
			image.size(),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!alloc_base)
			return NULL;

		image.fix_imports(_get_module, _get_function);
		image.map();
		image.relocate(reinterpret_cast<std::uintptr_t>(alloc_base));
		write(alloc_base, image.data(), image.size());
		return alloc_base;
	}

	void injector::hook_entry()
	{
		// jmp [rip]
		// 0xaddress of entry...
		std::uint8_t jmp_rip[14] = { 0xff, 0x25, 0x0, 0x0, 0x0, 0x0 };
		*reinterpret_cast<std::uintptr_t*>(jmp_rip + 6) = reinterpret_cast<std::uintptr_t>(alloc_base) + image.entry_point();
		static const auto rtl_alloc_heap = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtClose");
		write(rtl_alloc_heap, jmp_rip, sizeof(jmp_rip));
	}

	void* injector::get_allocated_base() const
	{
		return alloc_base;
	}

	void injector::set_target(unsigned pid)
	{
		target_pid = pid;
	}

	void injector::set_target(std::wstring proc_name)
	{
		target_pid = util::get_process_id(proc_name);
	}

	void* injector::get_pe_image() const
	{
		return (void*)image_buffer.data();
	}

	unsigned injector::get_target() const
	{
		return target_pid;
	}

	void injector::write(void* addr, void* buffer, std::size_t size)
	{
		SIZE_T bytes_written;
		::WriteProcessMemory(
			target_handle,
			addr,
			buffer,
			size,
			&bytes_written
		);
	}

	void injector::read(void* addr, void* buffer, std::size_t size)
	{
		SIZE_T bytes_read;
		::ReadProcessMemory(
			target_handle,
			addr,
			buffer,
			size,
			&bytes_read
		);
	}
}