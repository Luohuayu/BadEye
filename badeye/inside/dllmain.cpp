#include "bedaisy.hpp"
#include "utils.hpp"

void read_demo()
{
	OutputDebugStringA("[lsass] main thread created!");
	const auto rust_handle =
		OpenProcess(
			PROCESS_QUERY_INFORMATION, FALSE,
			utils::get_pid(L"RustClient.exe")
		);

	if (rust_handle)
	{
		const auto game_base = utils::get_proc_base(rust_handle);
		if (bedaisy::read<std::uint16_t>(rust_handle, game_base) == 0x5A4D)
			OutputDebugStringA("[lsass] read rust MZ!");
		else
			OutputDebugStringA("[lsass] didnt read rust MZ!");

		const auto asm_base = utils::get_module_base(rust_handle, L"GameAssembly.dll");
		if (bedaisy::read<std::uint16_t>(rust_handle, asm_base) == 0x5A4D)
			OutputDebugStringA("[lsass] read game assembly MZ!");
		else
			OutputDebugStringA("[lsass] didnt game assembly MZ!");
	}
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