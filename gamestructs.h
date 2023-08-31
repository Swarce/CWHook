#pragma once
#include <string.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <string_view>
#include <iostream>

struct cvar_t {
	uint64_t hash;
	uint64_t padding;
	uint64_t* ptr;
	uint64_t* ptr2;
	uint32_t type;
	uint32_t protection;
};
