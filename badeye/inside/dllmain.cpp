#include "rust.hpp"

void example()
{
	OutputDebugStringA("[lsass] main thread created!");
	const auto proc_handle =
		OpenProcess(
			PROCESS_QUERY_INFORMATION, FALSE,
			utils::get_pid(L"RustClient.exe")
		);

	if (proc_handle)
	{
		rust::set_fov(proc_handle, 120.f);
		OutputDebugStringA("[lsass] set fov!");
	}
}

std::atomic<bool> init = false;
extern "C" NTSTATUS nt_close(void* handle)
{
	if (!init.exchange(true))
	{
		OutputDebugStringA("[lsass] creating thread!");
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&example, NULL, NULL, NULL);
	}
	return NULL;
}