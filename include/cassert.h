#pragma once

void custom_assert(char *file, char *function, int line, char *str,
                   int condition);

#ifndef NDEBUG
#define assert(x)                                                              \
  do {                                                                         \
    custom_assert(__FILE__, __FUNCTION__, __LINE__, #x, x)\                        \
  } while (0);
#else
#define assert(x)
#endif