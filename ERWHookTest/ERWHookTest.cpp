
#include <iostream>
#include <Windows.h>
#include "ERWHook.h"

static int MessageBoxHook(HWND hwnd, LPCWSTR text, LPCWSTR caption, UINT type)
{
	std::wcout << "MessageBoxW(" << hwnd << ", " << text << ", " << caption << ", " << type << ")" << std::endl;
	return 0;
}

int main()
{
	DWORD oldProtect;
	const auto addr = reinterpret_cast<void*>(MessageBoxW);
	const auto hook = reinterpret_cast<void*>(MessageBoxHook);
	VirtualProtect(addr, 0x1000, 0x40, &oldProtect);

	ERWHook erw(addr, hook);
	
	MessageBoxW(nullptr, L"Howdy", L"Test", 0);
	MessageBoxW(nullptr, L"Howdy", L"Test123", 0);
}