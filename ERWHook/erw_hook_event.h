#pragma once
#include <memory>
#include "byte.h"
#include "function_arguments.h"

typedef void (*execute_dlg)(const function_arguments& args);

class erw_hook_event
{
private:
	byte* trampoline_;
	byte* restore_trampoline_;
	byte* hook_swap_;
	byte* return_to_;

public:
	erw_hook_event(void* target, execute_dlg redirect);
	erw_hook_event(const erw_hook_event& copy) = delete;
	~erw_hook_event();
};
