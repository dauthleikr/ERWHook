
#include <iostream>
#include <Windows.h>
#include "erw_hook_event.h"
#include "erw_hook.h"
#include "function_arguments.h"

static int MessageBoxHook(HWND hwnd, LPCWSTR text, LPCWSTR caption, UINT type)
{
	std::wcout << "MessageBoxW(" << hwnd << ", " << text << ", " << caption << ", " << type << ")" << std::endl;
	return 0;
}

static void MessageBoxHookEvent(const function_arguments& args)
{
	std::wcout << "MessageBoxW(...)" << std::endl;
	args[argument_number::arg4] = 16;
}

int main()
{
	DWORD oldProtect;
	const auto addr = reinterpret_cast<void*>(MessageBoxW);
	const auto hook = reinterpret_cast<void*>(MessageBoxHook);
	VirtualProtect(addr, 0x1000, 0x40, &oldProtect);

	erw_hook_event erw(addr, MessageBoxHookEvent);
	
	MessageBoxW(nullptr, L"Howdy", L"Test", 0);
	MessageBoxW(nullptr, L"Howdy", L"Test123", 0);
}