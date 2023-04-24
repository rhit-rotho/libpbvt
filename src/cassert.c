
#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>

void custom_assert(char *file, char *function, int line, char *str,
                   int condition) {
  if (!condition) {
    unw_cursor_t cursor;
    unw_context_t context;

    unw_getcontext(&context);
    unw_init_local(&cursor, &context);

    fprintf(stderr, "%s:%d: %s '%s' failed! Stack trace:\n", file, line,
            function, str);

    while (unw_step(&cursor) > 0) {
      unw_word_t offset, pc;
      char fname[64];

      unw_get_reg(&cursor, UNW_REG_IP, &pc);
      fname[0] = '\0';
      unw_get_proc_name(&cursor, fname, sizeof(fname), &offset);

      fprintf(stderr, "%p : (%s+0x%lx)\n", (void *)pc, fname, (long)offset);
    }

    exit(EXIT_FAILURE);
  }
}
