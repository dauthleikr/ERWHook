#pragma once
#include <memory>
#include "byte.h"

class erw_hook
{
private:
	byte* trampoline_;
	byte* restore_trampoline_;
	byte* hook_swap_;
	byte* return_to_;

public:
	erw_hook(void* target, void* redirect);
	erw_hook(const erw_hook& copy) = delete;
	~erw_hook();
};
