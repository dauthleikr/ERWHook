#pragma once
#include <cstdint>

enum class argument_number
{
	arg1 = 3,
	arg2 = 2,
	arg3 = 1,
	arg4 = 0
};

class function_arguments
{
private:
	uint64_t* stackptr_;

public:
	explicit function_arguments(uint64_t* stackptr);

	uint64_t& operator[](argument_number index) const;
};