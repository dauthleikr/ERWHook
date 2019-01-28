#pragma once
#include <memory>
#include "byte.h"

class ERWHook
{
private:
	byte* trampoline_;
	byte* restore_trampoline_;
	byte* hook_swap_;
	byte* return_to_;

public:
	ERWHook(void* target, void* redirect);
	ERWHook(const ERWHook& copy) = delete;
	~ERWHook();
};
