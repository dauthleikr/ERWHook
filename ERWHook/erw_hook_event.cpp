#include <iostream>
#include <Windows.h>
#include "erw_hook_event.h"
#include "function_arguments.h"

static void hook(uint64_t* stackptr, const execute_dlg exec)
{
	const function_arguments args{ stackptr };
	exec(args);
}

erw_hook_event::erw_hook_event(void* target, execute_dlg redirect)
{
	hook_swap_ = new byte[0x10];
	return_to_ = new byte[0x8];
	trampoline_ = reinterpret_cast<byte*>(VirtualAlloc(nullptr, 0x1000, 0x00001000, 0x4));
	restore_trampoline_ = reinterpret_cast<byte*>(VirtualAlloc(nullptr, 0x1000, 0x00001000, 0x4));

	auto hook_addr = reinterpret_cast<void*>(hook);

	const auto hook_swap_addr_bytes = reinterpret_cast<byte*>(&hook_swap_);
	const auto return_to_addr_bytes = reinterpret_cast<byte*>(&return_to_);
	const auto target_addr_bytes = reinterpret_cast<byte*>(&target);
	const auto restore_addr_bytes = reinterpret_cast<byte*>(&restore_trampoline_);
	const auto hook_addr_bytes = reinterpret_cast<byte*>(&hook_addr);
	const auto redirect_addr_bytes = reinterpret_cast<byte*>(&redirect);
	const auto trampoline_addr_bytes = reinterpret_cast<byte*>(&trampoline_);

	byte restore_hook[] =
	{
		// swapping hook with original bytes again
		// mov rax, target_addr
		0x48,
		0xB8,
		target_addr_bytes[0],
		target_addr_bytes[1],
		target_addr_bytes[2],
		target_addr_bytes[3],
		target_addr_bytes[4],
		target_addr_bytes[5],
		target_addr_bytes[6],
		target_addr_bytes[7],
		// mov rbx, hook_swap_addr
		0x48,
		0xBB,
		hook_swap_addr_bytes[0],
		hook_swap_addr_bytes[1],
		hook_swap_addr_bytes[2],
		hook_swap_addr_bytes[3],
		hook_swap_addr_bytes[4],
		hook_swap_addr_bytes[5],
		hook_swap_addr_bytes[6],
		hook_swap_addr_bytes[7],
		// swap first 8 bytes
		// mov rcx,qword ptr ds:[rax]
		0x48, 0x8B, 0x08,
		// mov rdx,qword ptr ds:[rbx]
		0x48, 0x8B, 0x13,
		// mov qword ptr ds:[rbx], rcx
		0x48, 0x89, 0x0B,
		// mov qword ptr ds:[rax], rdx
		0x48, 0x89, 0x10,
		// move onto the next 8 bytes
		// add rax, 8
		0x48, 0x83, 0xC0, 0x08,
		// add rbx, 8
		0x48, 0x83, 0xC3, 0x08,
		// swap second 8 bytes
		// mov rcx,qword ptr ds:[rax]
		0x48, 0x8B, 0x08,
		// mov rdx,qword ptr ds:[rbx]
		0x48, 0x8B, 0x13,
		// mov qword ptr ds:[rbx], rcx
		0x48, 0x89, 0x0B,
		// mov qword ptr ds:[rax], rdx
		0x48, 0x89, 0x10,

		// return to caller of hooked function
		// mov rax,qword ptr ds:[return_to_]
		0x48,
		0xA1,
		return_to_addr_bytes[0],
		return_to_addr_bytes[1],
		return_to_addr_bytes[2],
		return_to_addr_bytes[3],
		return_to_addr_bytes[4],
		return_to_addr_bytes[5],
		return_to_addr_bytes[6],
		return_to_addr_bytes[7],
		// push rax
		0x50,
		// ret
		0xC3
	};

	byte trampoline[] =
	{
		// restoring original function
		// preserving registers, they are used for restoring the original function
		// push rcx
		0x51,
		// push rdx
		0x52,
		// push rbx
		0x53,
		// mov rax, target_addr
		0x48,
		0xB8,
		target_addr_bytes[0],
		target_addr_bytes[1],
		target_addr_bytes[2],
		target_addr_bytes[3],
		target_addr_bytes[4],
		target_addr_bytes[5],
		target_addr_bytes[6],
		target_addr_bytes[7],
		// mov rbx, hook_swap_addr
		0x48,
		0xBB,
		hook_swap_addr_bytes[0],
		hook_swap_addr_bytes[1],
		hook_swap_addr_bytes[2],
		hook_swap_addr_bytes[3],
		hook_swap_addr_bytes[4],
		hook_swap_addr_bytes[5],
		hook_swap_addr_bytes[6],
		hook_swap_addr_bytes[7],
		// swap first 8 bytes
		// mov rcx,qword ptr ds:[rax]
		0x48, 0x8B, 0x08,
		// mov rdx,qword ptr ds:[rbx]
		0x48, 0x8B, 0x13,
		// mov qword ptr ds:[rbx], rcx
		0x48, 0x89, 0x0B,
		// mov qword ptr ds:[rax], rdx
		0x48, 0x89, 0x10,
		// move onto the next 8 bytes
		// add rax, 8
		0x48, 0x83, 0xC0, 0x08,
		// add rbx, 8
		0x48, 0x83, 0xC3, 0x08,
		// swap second 8 bytes
		// mov rcx,qword ptr ds:[rax]
		0x48, 0x8B, 0x08,
		// mov rdx,qword ptr ds:[rbx]
		0x48, 0x8B, 0x13,
		// mov qword ptr ds:[rbx], rcx
		0x48, 0x89, 0x0B,
		// mov qword ptr ds:[rax], rdx
		0x48, 0x89, 0x10,
		// pop rbx
		0x5B,
		// pop rdx,
		0x5A,
		// pop 59
		0x59,



		// preserving args for original function
		// push rcx
		0x51,
		// push rdx
		0x52,
		// push r8
		0x41, 0x50,
		// push r9
		0x41, 0x51,

		// mov rcx, rsp
		0x48, 0x89, 0xE1,
		// mov rdx, redirect
		0x48, 0xBA,
		redirect_addr_bytes[0],
		redirect_addr_bytes[1],
		redirect_addr_bytes[2],
		redirect_addr_bytes[3],
		redirect_addr_bytes[4],
		redirect_addr_bytes[5],
		redirect_addr_bytes[6],
		redirect_addr_bytes[7],


		// push rbx
		0x53,
		// hook call preparation
		// sub rsp, 0x20	(x64 shadow space)
		0x48, 0x83, 0xEC, 0x20,
		// mov rax, target_addr
		0x48,
		0xB8,
		hook_addr_bytes[0],
		hook_addr_bytes[1],
		hook_addr_bytes[2],
		hook_addr_bytes[3],
		hook_addr_bytes[4],
		hook_addr_bytes[5],
		hook_addr_bytes[6],
		hook_addr_bytes[7],
		// calling hook
		// call rax
		0xff, 0xd0,
		// restoring original args
		// add rsp, 0x20
		0x48, 0x83, 0xC4, 0x20,
		// pop rbx
		0x5B,
		// pop r9
		0x41, 0x59,
		// pop r8
		0x41, 0x58,
		// pop rdx
		0x5A,
		// pop rcx
		0x59,

		// saving caller return to return_to
		// pop rax
		0x58,
		// mov qword ptr ds:[return_to_],rax
		0x48, 0xA3,
		return_to_addr_bytes[0],
		return_to_addr_bytes[1],
		return_to_addr_bytes[2],
		return_to_addr_bytes[3],
		return_to_addr_bytes[4],
		return_to_addr_bytes[5],
		return_to_addr_bytes[6],
		return_to_addr_bytes[7],

		// planting restore function on stack
		// mov rax, restore_trampoline_addr
		0x48,
		0xB8,
		restore_addr_bytes[0],
		restore_addr_bytes[1],
		restore_addr_bytes[2],
		restore_addr_bytes[3],
		restore_addr_bytes[4],
		restore_addr_bytes[5],
		restore_addr_bytes[6],
		restore_addr_bytes[7],
		// push rax
		0x50,
		// calling original function
		// mov rax, target_addr
		0x48,
		0xB8,
		target_addr_bytes[0],
		target_addr_bytes[1],
		target_addr_bytes[2],
		target_addr_bytes[3],
		target_addr_bytes[4],
		target_addr_bytes[5],
		target_addr_bytes[6],
		target_addr_bytes[7],
		// push rax
		0x50,
		// ret
		0xC3
	};

	byte hook[] =
	{
		0x48,
		0xB8,
		trampoline_addr_bytes[0],
		trampoline_addr_bytes[1],
		trampoline_addr_bytes[2],
		trampoline_addr_bytes[3],
		trampoline_addr_bytes[4],
		trampoline_addr_bytes[5],
		trampoline_addr_bytes[6],
		trampoline_addr_bytes[7],
		// push rax
		0x50,
		// ret
		0xC3,
		0x90,
		0x90,
		0x90,
		0x90,
	};

	memcpy(hook_swap_, hook, sizeof(hook));
	memcpy(trampoline_, trampoline, sizeof(trampoline));
	memcpy(restore_trampoline_, restore_hook, sizeof(restore_hook));

	DWORD old_protect;
	VirtualProtect(trampoline_, 0x1000, 0x20, &old_protect);
	VirtualProtect(restore_trampoline_, 0x1000, 0x40, &old_protect);

	restore_trampoline_[52] = 0xC3;
	const auto hook_swap_fx = reinterpret_cast<void(*)()>(restore_trampoline_);
	hook_swap_fx();
	restore_trampoline_[52] = 0x48;

	VirtualProtect(restore_trampoline_, 0x1000, 0x20, &old_protect);
}

erw_hook_event::~erw_hook_event()
{
	delete[] hook_swap_;
	delete[] return_to_;
	VirtualFree(trampoline_, 0, 0x00008000);
	VirtualFree(restore_trampoline_, 0, 0x00008000);
}
