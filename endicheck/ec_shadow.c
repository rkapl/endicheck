/*--------------------------------------------------------------------*/
/*--- Shadow memory table handling                       ec_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Endicheck, a tool for detecting data with wrong
   endianity leaving the program.

   Copyright (C) 2002-2017 Roman Kapl
      code@rkapl.cz

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

/* The shadow table is currently a simpler version of the table in mc_main.c. In future the table
   manipulation code should be merged (not the leaf data, just the management)
*/

#include "ec_shadow.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_machine.h"
#include "pub_tool_libcprint.h"
#include <stdbool.h>

#define EC_SHADOW_HEAPID "ec_shadow"

#if VG_WORDSIZE == 4
/* cover the entire address space */
#  define EC_PRIMARY_BITS  16
#else
/* Just handle the first 128G. */
/* TODO: add auxiliary tables like memcheck */
#  define EC_PRIMARY_BITS  21
#endif

#define EC_PRIMARY_SIZE (1 << EC_PRIMARY_BITS)
#define EC_PRIMARY_MASK (EC_PRIMARY_SIZE - 1)

#define EC_SECONDARY_BITS 16
#define EC_SECONDARY_SIZE (1 << EC_SECONDARY_BITS)
#define EC_SECONDARY_MASK (EC_SECONDARY_SIZE - 1)

typedef struct {
   uint8_t ebits[EC_SECONDARY_SIZE];
} Ec_Secondary;

typedef struct Ec_Primary {
   Ec_Secondary *entries[EC_PRIMARY_SIZE];
} Ec_Primary;

Ec_Primary shadow_table;

static Ec_Secondary* get_secodary(ec_addr addr)
{
   addr >>= EC_SECONDARY_BITS;
   tl_assert((addr & ~EC_PRIMARY_MASK) == 0);
   Ec_Secondary *sec = shadow_table.entries[addr];
   if (!sec) {
      sec = VG_(calloc)(EC_SHADOW_HEAPID, 1, sizeof(*sec));
      shadow_table.entries[addr] = sec;
   }
   return sec;
}

void EC_(set_shadow)(ec_addr addr, Ec_Endianity endianity)
{
   Ec_Secondary *s = get_secodary(addr);
   s->ebits[addr & EC_SECONDARY_MASK] = endianity;
}

Ec_Endianity EC_(get_shadow)(ec_addr addr)
{
   Ec_Secondary *s = get_secodary(addr);
   return s->ebits[addr & EC_SECONDARY_MASK];
}

static uint8_t* get_shadow_ptr(ec_addr addr)
{
   Ec_Secondary *s = get_secodary(addr);
   return &s->ebits[addr & EC_SECONDARY_MASK];
}

static IRType word_type(void)
{
   switch (sizeof(ec_addr)) {
      case 4:
         return Ity_I32;
      case 8:
         return Ity_I64;
      default:
         VG_(tool_panic)("invalid ec_addr_size");
   }
}

static VG_REGPARM(1) uint8_t* helper_get_shadow_ptr(ec_addr addr)
{
   // VG_(message)(Vg_UserMsg, "Accessing shadow memory at %p\n", (void*)addr);
   return get_shadow_ptr(addr);
}

void EC_(gen_shadow_store)(IRSB* out, IREndness endness, IRExpr* addr, IRExpr* shadow_data)
{
   tl_assert(addr);
   tl_assert(shadow_data);
   // TODO: unaligned writes that may cross boundaries
   IRTemp shadow_ptr_tmp = newIRTemp(out->tyenv, word_type());
   IRDirty* shadow_ptr = unsafeIRDirty_1_N(
            shadow_ptr_tmp, 1, "ec_secondary", VG_(fnptr_to_fnentry)(helper_get_shadow_ptr),
            mkIRExprVec_1(addr));
   /* TODO: should we mark any memory as read by the dirty helper? MC does not seem to do that */
   addStmtToIRSB(out, IRStmt_Dirty(shadow_ptr));
   addStmtToIRSB(out, IRStmt_Store(endness, IRExpr_RdTmp(shadow_ptr_tmp), shadow_data));
}
