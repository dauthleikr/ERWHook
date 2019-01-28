#include "function_arguments.h"

function_arguments::function_arguments(uint64_t* stackptr) : stackptr_{ stackptr }
{
}

uint64_t& function_arguments::operator[](argument_number index) const
{
	return stackptr_[static_cast<int>(index)];
}
