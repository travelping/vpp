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

#include <vppinfra/trap.h>
#include <vppinfra/error.h>
#include <vlib/vlib.h>

trap_t *
_make_trap()
{
  trap_t *t = clib_mem_alloc(sizeof(trap_t));
  t->n_callers = clib_backtrace (t->callers, ARRAY_LEN (t->callers), 0);
  return t;
}

void
_print_trap_backtrace(trap_t *t)
{
  int i;
  clib_warning("Trap backtrace:");
  for (i = 0; i < t->n_callers; i++) {
    clib_warning("#%-2d 0x%016lx %U%c", i, t->callers[i],
      format_clib_elf_symbol_with_address, t->callers[i], 0);
  }
}
