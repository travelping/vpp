/*
 * trap.h - "trap" debugging mechanism
 *
 * Copyright (c) 2020 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __included_trap_h__
#define __included_trap_h__

#include <vppinfra/clib.h>

typedef struct {
  uword callers[32];
  uword n_callers;
} trap_t;

/* TODO: disable traps by default */

#define TRAP(x) trap_t *x
#define SET_TRAP(x) x = _make_trap()
#define CHECK_TRAP(x)                                           \
    do {                                                        \
        trap_t *__trap = x;                                     \
        if (__trap)                                             \
            {                                                   \
                _print_trap_backtrace (__trap);                 \
                _clib_error (CLIB_ERROR_ABORT, 0, 0,            \
                             "%s:%d (%s) trap `%s' hit",        \
                             __FILE__,                          \
                             (uword) __LINE__,                  \
                             clib_error_function,               \
                             # x);                              \
            }                                                   \
    } while (0)

trap_t *_make_trap();
void _print_trap_backtrace(trap_t *t);

#endif
