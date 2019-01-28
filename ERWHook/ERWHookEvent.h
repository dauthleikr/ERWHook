#pragma once
#include <memory>
#include "byte.h"
#include "FunctionArguments.h"

typedef void (*ExecuteDlg)(const FunctionArguments& args);

class ERWHookEvent
{
private:
	byte* trampoline_;
	byte* restore_trampoline_;
	byte* hook_swap_;
	byte* return_to_;

public:
	ERWHookEvent(void* target, ExecuteDlg redirect);
	ERWHookEvent(const ERWHookEvent& copy) = delete;
	~ERWHookEvent();
};
