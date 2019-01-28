
#include <iostream>
#include <Windows.h>
#include "ERWHook.h"
#include "ERWHookEvent.h"

static int MessageBoxHook(HWND hwnd, LPCWSTR text, LPCWSTR caption, UINT type)
{
	std::wcout << "MessageBoxW(" << hwnd << ", " << text << ", " << caption << ", " << type << ")" << std::endl;
	return 0;
}

static void MessageBoxHookEvent(const FunctionArguments& args)
{
	std::wcout << "MessageBoxW(...)" << std::endl;
	args[ArgumentNumber::arg4] = 16;
}

int main()
{
	DWORD oldProtect;
	const auto addr = reinterpret_cast<void*>(MessageBoxW);
	const auto hook = reinterpret_cast<void*>(MessageBoxHook);
	VirtualProtect(addr, 0x1000, 0x40, &oldProtect);

	ERWHookEvent erw(addr, MessageBoxHookEvent);
	
	MessageBoxW(nullptr, L"Howdy", L"Test", 0);
	MessageBoxW(nullptr, L"Howdy", L"Test123", 0);
}