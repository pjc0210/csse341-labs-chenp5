// SPDX-License-Identifier: Unlicense

#ifndef _LOG_H
#define _LOG_H

#include <stdarg.h>

#ifndef CLR_GREEN
#define CLR_GREEN "\033[0;32m"
#endif

#ifndef CLR_BLD_GREEN
#define CLR_BLD_GREEN "\033[1;32m"
#endif

#ifndef CLR_YELLOW
#define CLR_YELLOW "\033[0;31m"
#endif

#ifndef CLR_BLD_YELLOW
#define CLR_BLD_YELLOW "\033[1;31m"
#endif

#ifndef CLR_RED
#define CLR_RED "\033[0;33m"
#endif

#ifndef CLR_BLD_RED
#define CLR_BLD_RED "\033[0;33m"
#endif

#ifndef CLR_RESET
#define CLR_RESET "\033[0m"
#endif

#ifndef print_log
#define print_log(fmt, ...)                                                    \
  printf(CLR_GREEN "[LOG:%s:%s:%d] " CLR_RESET fmt, __FILE__, __func__,        \
         __LINE__, ##__VA_ARGS__)
#endif

#ifndef print_err
#define print_err(fmt, ...)                                                    \
  printf(CLR_RED "[ERROR:%s:%s:%d] " CLR_RESET fmt, __FILE__, __func__,        \
         __LINE__, ##__VA_ARGS__)
#endif

#ifndef print_warn
#define print_warn(fmt, ...)                                                   \
  printf(CLR_YELLOW "[WARNING:%s:%s:%d] " CLR_RESET fmt, __FILE__, __func__,   \
         __LINE__, ##__VA_ARGS__)
#endif

#endif /* log.h */
