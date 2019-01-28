#include "FunctionArguments.h"

FunctionArguments::FunctionArguments(uint64_t* stackptr) : stackptr_{ stackptr }
{
}

uint64_t& FunctionArguments::operator[](ArgumentNumber index) const
{
	return stackptr_[static_cast<int>(index)];
}
