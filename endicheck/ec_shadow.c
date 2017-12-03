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

#define EC_OTAG_GRANULARITY_BITS 1
#define EC_OTAG_MASK ((1 << EC_OTAG_GRANULARITY_BITS) - 1)

typedef struct {
   uint8_t ebits[EC_SECONDARY_SIZE];
} Ec_Secondary;

typedef struct {
   Ec_Secondary ebits;
   Ec_Otag otags[EC_SECONDARY_SIZE >> EC_OTAG_GRANULARITY_BITS];
} Ec_SecondaryOtag;

typedef struct Ec_Primary {
   Ec_Secondary *entries[EC_PRIMARY_SIZE];
} Ec_Primary;

Ec_Primary shadow_table;

static Ec_Secondary* get_secondary(Addr addr)
{
   addr >>= EC_SECONDARY_BITS;
   tl_assert((addr & ~EC_PRIMARY_MASK) == 0);
   Ec_Secondary *sec = shadow_table.entries[addr];
   if (!sec) {
      SizeT secondary_size = EC_(opt_track_origins) ? sizeof(Ec_SecondaryOtag) : sizeof(Ec_Secondary);
      sec = VG_(calloc)(EC_SHADOW_HEAPID, 1, secondary_size);
      shadow_table.entries[addr] = sec;
   }
   return sec;
}

void EC_(set_shadow)(Addr addr, Ec_Shadow endianity)
{
   Ec_Secondary *s = get_secondary(addr);
   s->ebits[addr & EC_SECONDARY_MASK] = endianity;
}

Ec_Shadow EC_(get_shadow)(Addr addr)
{
   Ec_Secondary *s = get_secondary(addr);
   return s->ebits[addr & EC_SECONDARY_MASK];
}

Ec_Otag EC_(get_shadow_otag)(Addr addr)
{
   tl_assert(EC_(opt_track_origins));
   Ec_SecondaryOtag *s = (Ec_SecondaryOtag*) get_secondary(addr);
   return s->otags[(addr & EC_SECONDARY_MASK) >> EC_OTAG_GRANULARITY_BITS];
}

static uint8_t* get_ebit_ptr(Addr addr)
{
   Ec_Secondary *s = get_secondary(addr);
   return &s->ebits[addr & EC_SECONDARY_MASK];
}

void EC_(set_shadow_otag)(Addr addr, Ec_Shadow endianity, Ec_Otag tag)
{
   tl_assert(EC_(opt_track_origins));
   Ec_SecondaryOtag *s = (Ec_SecondaryOtag*) get_secondary(addr);
   s->ebits.ebits[addr & EC_SECONDARY_MASK] = endianity;
   s->otags[(addr & EC_SECONDARY_MASK) >> EC_OTAG_GRANULARITY_BITS] = tag;
}

static IRType word_type(void)
{
   switch (sizeof(Addr)) {
      case 4:
         return Ity_I32;
      case 8:
         return Ity_I64;
      default:
         VG_(tool_panic)("invalid Addr_size");
   }
}

static VG_REGPARM(1) uint8_t* helper_get_shadow_ptr(Addr addr)
{
   /* VG_(message)(Vg_UserMsg, "Before accessing shadow memory at %p\n", (void*)addr);
   EC_(dump_mem)(addr, 4); */
   return get_ebit_ptr(addr);
}

static VG_REGPARM(1) Ec_Otag helper_get_otag(Addr addr)
{
   return EC_(get_shadow_otag)(addr);
}

static VG_REGPARM(3) void helper_set_otag(Addr addr, SizeT size, Ec_Otag origin)
{
   tl_assert(EC_(opt_track_origins));
   // VG_(printf)("set otag to %u at %p, size %lu\n", origin, (void*)addr, size);
   if (((addr & EC_OTAG_MASK) == 0) && ((size & EC_OTAG_MASK) == 0)) {
      /* aligned case */
      Ec_SecondaryOtag *s = (Ec_SecondaryOtag*) get_secondary(addr);
      for (SizeT i = 0; i<size; i += (1 << EC_OTAG_GRANULARITY_BITS))
         s->otags[((addr + i) & EC_SECONDARY_MASK) >> EC_OTAG_GRANULARITY_BITS] = origin;
   } else {
      for (SizeT i = 0; i<size; i++)
         EC_(set_shadow_otag)(addr, size + i, origin);
   }
}

void EC_(gen_shadow_store)(IRSB* out, IREndness endness, IRExpr* addr, Ec_ShadowExpr shadow)
{
   EC_(gen_shadow_store_guarded)(out, endness, addr, shadow, NULL);
}

void EC_(gen_shadow_store_guarded)(
      IRSB* out, IREndness endness, IRExpr* addr, Ec_ShadowExpr shadow, IRExpr* guard)
{
   tl_assert(addr);
   tl_assert(shadow.ebits);
   /* Request memory for ebits shadow */
   // TODO: unaligned writes that may cross boundaries
   IRTemp shadow_ptr_tmp = newIRTemp(out->tyenv, word_type());
   IRDirty* shadow_ptr = unsafeIRDirty_1_N(
            shadow_ptr_tmp, 1, "ec_get_shadow_ptr", VG_(fnptr_to_fnentry)(helper_get_shadow_ptr),
            mkIRExprVec_1(addr));
   if (guard)
      shadow_ptr->guard = guard;

   /* Store the ebits to the provided place */
   /* TODO: should we mark any memory as read by the dirty helper? MC does not seem to do that */
   addStmtToIRSB(out, IRStmt_Dirty(shadow_ptr));
   if (guard)
      addStmtToIRSB(out, IRStmt_StoreG(endness, IRExpr_RdTmp(shadow_ptr_tmp), shadow.ebits, guard));
   else
      addStmtToIRSB(out, IRStmt_Store(endness, IRExpr_RdTmp(shadow_ptr_tmp), shadow.ebits));

   /* And store the origin (separate helper), if provided */
   if (EC_(opt_track_origins)) {
      IRExpr *widened_otag = NULL;
      if (sizeof (void*) == 4) {
         widened_otag = shadow.origin;
      } else {
         IRTemp widen_otag_tmp = newIRTemp(out->tyenv, Ity_I64);
         addStmtToIRSB(out, IRStmt_WrTmp(widen_otag_tmp, IRExpr_Unop(Iop_32Uto64, shadow.origin)));
         widened_otag = IRExpr_RdTmp(widen_otag_tmp);
      }

      tl_assert(shadow.origin);
      SizeT data_size = sizeofIRType(typeOfIRExpr(out->tyenv, shadow.ebits));
      IRDirty *store_origin = unsafeIRDirty_0_N(
            3, "ec_set_otag", VG_(fnptr_to_fnentry)(helper_set_otag),
            mkIRExprVec_3(addr, EC_(const_sizet)(data_size), widened_otag));
      if (guard)
         store_origin->guard = guard;
      addStmtToIRSB(out, IRStmt_Dirty(store_origin));
   }
}

Ec_ShadowExpr EC_(gen_shadow_load)(
      IRSB* out, IREndness endness, IRType type, IRExpr* addr)
{
   Ec_ShadowExpr no_alt = {NULL, EC_NO_OTAG};
   return EC_(gen_shadow_load_guarded)(out, endness, type, addr, ILGop_INVALID, NULL, no_alt);
}

Ec_ShadowExpr EC_(gen_shadow_load_guarded)(
      IRSB* out, IREndness endness, IRType type, IRExpr* addr,
      IRLoadGOp cvt, IRExpr* guard, Ec_ShadowExpr alt)
{
   tl_assert(addr);
   Ec_ShadowExpr r = {NULL, NULL};
   // TODO: unaligned writes that may cross boundaries
   /* Request memory for ebits shadow */
   IRTemp shadow_ptr_tmp = newIRTemp(out->tyenv, word_type());
   IRDirty* shadow_ptr = unsafeIRDirty_1_N(
            shadow_ptr_tmp, 1, "ec_get_shadow_ptr", VG_(fnptr_to_fnentry)(helper_get_shadow_ptr),
            mkIRExprVec_1(addr));
   if (guard)
      shadow_ptr->guard = guard;
   /* TODO: should we mark any memory as read by the dirty helper? MC does not seem to do that */
   addStmtToIRSB(out, IRStmt_Dirty(shadow_ptr));
   IRTemp result_tmp = newIRTemp(out->tyenv, type);

   /* And load the ebits from the provided ptr */
   if (cvt != ILGop_INVALID) {
      tl_assert(guard);
      IRStmt* load = IRStmt_LoadG(endness, cvt, result_tmp, IRExpr_RdTmp(shadow_ptr_tmp), alt.ebits, guard);
      addStmtToIRSB(out, load);
      r.ebits = IRExpr_RdTmp(result_tmp);
   } else {
      IRExpr* load = IRExpr_Load(endness, type, IRExpr_RdTmp(shadow_ptr_tmp));
      addStmtToIRSB(out, IRStmt_WrTmp(result_tmp, load));
      r.ebits = IRExpr_RdTmp(result_tmp);
   }

   if (EC_(opt_track_origins)) {
      /* Load the otag. Because of dirt call limitations, we get native size otag back */
      IRTemp origin_tmp = newIRTemp(out->tyenv, word_type());
      IRDirty* load_origin = unsafeIRDirty_1_N(
               origin_tmp, 1, "ec_get_otag", VG_(fnptr_to_fnentry)(helper_get_otag),
               mkIRExprVec_1(addr));
      addStmtToIRSB(out, IRStmt_Dirty(load_origin));
      IRExpr *narrowed_origin = NULL;
      /* Narrow it if needed */
      if (sizeof(void*) == 4) {
         narrowed_origin = IRExpr_RdTmp(origin_tmp);
      } else {
         IRTemp widened_origin_tmp = newIRTemp(out->tyenv, Ity_I32);
         addStmtToIRSB(out, IRStmt_WrTmp(widened_origin_tmp, IRExpr_Unop(Iop_64to32, IRExpr_RdTmp(origin_tmp))));
         narrowed_origin = IRExpr_RdTmp(widened_origin_tmp);
      }

      /* And provide correct guarded behaviour using ternary operator, if needed */
      if (guard) {
         load_origin->guard = guard;
         IRTemp alt_origin_tmp = newIRTemp(out->tyenv, Ity_I32);
         addStmtToIRSB(out, IRStmt_WrTmp(alt_origin_tmp, IRExpr_ITE(guard, narrowed_origin, alt.origin)));
         r.origin = IRExpr_RdTmp(alt_origin_tmp);
      } else {
         r.origin = narrowed_origin;
      }
   }
   return r;
}
