#pragma once
#include <cstdint>

enum class ArgumentNumber
{
	arg1 = 3,
	arg2 = 2,
	arg3 = 1,
	arg4 = 0
};

class FunctionArguments
{
private:
	uint64_t* stackptr_;

public:
	explicit FunctionArguments(uint64_t* stackptr);

	uint64_t& operator[](ArgumentNumber index) const;
};