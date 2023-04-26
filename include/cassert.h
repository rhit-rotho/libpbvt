#pragma once

void custom_assert(char *file, const char *function, int line, char *str,
                   int condition);

#ifndef NDEBUG
#define assert(x) custom_assert(__FILE__, __FUNCTION__, __LINE__, #x, x)
#else
#define assert(x)
#endif