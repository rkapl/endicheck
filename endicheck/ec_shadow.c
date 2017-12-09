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
#include "ec_util.h"
#include "ec_errors.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_machine.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_oset.h"
#include <stdbool.h>

#define EC_SHADOW_HEAPID "ec_shadow"

#if VG_WORDSIZE == 4
/* cover the entire address space */
#  define EC_PRIMARY_BITS  16
#else
/* Just handle the first 128G. */
/* TODO: add auxiliary tables like memcheck */
#  define EC_PRIMARY_BITS  21
#  define EC_HAS_AUXMAP
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

static Ec_Primary shadow_table;

#ifdef EC_HAS_AUXMAP
typedef struct {
   Addr base;
   Ec_Secondary* secondary;
} Ec_AuxEntry;
/* For simplicity, we don't yet have the L1 and L2 maps like MC does.
 * Otherwise, this is simply duplicated from MC */
static OSet* shadow_aux_table = NULL;
#endif

void EC_(shadow_init)(void)
{
#ifdef EC_HAS_AUXMAP
   shadow_aux_table = VG_(OSetGen_Create)(
            offsetof(Ec_AuxEntry, base), NULL,
            VG_(malloc), "ec_shadow_auxmap", VG_(free));
#endif
}

static Ec_Secondary* alloc_secondary(void)
{
   SizeT secondary_size = EC_(opt_track_origins) ? sizeof(Ec_SecondaryOtag) : sizeof(Ec_Secondary);
   return VG_(calloc)(EC_SHADOW_HEAPID, 1, secondary_size);
}

static Ec_Secondary* get_secondary(Addr orig_addr)
{
   Addr addr = orig_addr >> EC_SECONDARY_BITS;
#ifdef EC_HAS_AUXMAP
   if ((addr & ~EC_PRIMARY_MASK) != 0) {
      Ec_AuxEntry key;
      key.base = addr;
      key.secondary = NULL;
      Ec_AuxEntry* aux = VG_(OSetGen_Lookup)(shadow_aux_table, &key);
      if (!aux) {
         aux = (Ec_AuxEntry*) VG_(OSetGen_AllocNode)(shadow_aux_table, sizeof(Ec_AuxEntry));
         aux->base = addr;
         aux->secondary = alloc_secondary();
         VG_(OSetGen_Insert)(shadow_aux_table, aux);
      }
      return aux->secondary;
   }
#else
   tl_assert((addr & ~EC_PRIMARY_MASK) == 0);
#endif
   Ec_Secondary *sec = shadow_table.entries[addr];
   if (!sec) {
      sec = alloc_secondary();
      shadow_table.entries[addr] = sec;
   }
   return sec;
}

void EC_(set_shadow)(Addr addr, Ec_Shadow endianity)
{
   Ec_Secondary *map = get_secondary(addr);
   Ec_Shadow *s = &map->ebits[addr & EC_SECONDARY_MASK];
   *s &= EC_PROTECTED_TAG;
   *s |= endianity;
}

Ec_Shadow EC_(get_shadow)(Addr addr)
{
   Ec_Secondary *s = get_secondary(addr);
   return s->ebits[addr & EC_SECONDARY_MASK] & ~EC_PROTECTED_TAG;
}

Ec_Shadow EC_(get_shadow_with_protection)(Addr addr)
{
   Ec_Secondary *s = get_secondary(addr);
   return s->ebits[addr & EC_SECONDARY_MASK];
}

Bool EC_(is_protected)(Addr addr)
{
   Ec_Secondary *s = get_secondary(addr);
   return s->ebits[addr & EC_SECONDARY_MASK] & EC_PROTECTED_TAG;
}

void EC_(set_protected)(Addr addr, SizeT size, Bool protected)
{
   Ec_Secondary* map = get_secondary(addr);
   for(SizeT i = 0; i<size; i++, addr++) {
      if ((addr & EC_SECONDARY_MASK) == 0)
         map = get_secondary(addr);
      Ec_Shadow* shadow = &map->ebits[addr & EC_SECONDARY_MASK];
      *shadow &= ~EC_PROTECTED_TAG;
      if (protected)
         *shadow |= EC_PROTECTED_TAG;
   }
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

void EC_(set_shadow_otag)(Addr addr, Ec_Otag tag)
{
   tl_assert(EC_(opt_track_origins));
   Ec_SecondaryOtag *s = (Ec_SecondaryOtag*) get_secondary(addr);
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

/* Does a value fit into a single shadow page, so that we can use single load/store?
 * The value has size (1 << amask).
 */
static Bool fits_map(Addr addr, SizeT size)
{
   Addr diff = addr ^ (addr + size);
   return (diff >> EC_SECONDARY_BITS) == 0;
}

/* A slow byte-by byte version that supports crossing map boundaries */
static void helper_store_slow(Addr addr, SizeT size, Ec_Shadow* value)
{
   tl_assert(size < EC_MAX_STORE);
   Bool protected = False;
   for(SizeT i = 0; i<size; i++) {
      Ec_Shadow s = EC_(get_shadow_with_protection)(addr + i) & EC_PROTECTED_TAG;
      if (s)
         protected = True;
      EC_(set_shadow)(addr + i, value[i]);
   }

   if (EC_(opt_protection) && protected)
      EC_(check_store)(addr, size, value);
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
         EC_(set_shadow_otag)(addr, origin);
   }
}

void EC_(gen_shadow_store)(IRSB* out, IREndness endness, IRExpr* addr, Ec_ShadowExpr shadow)
{
   EC_(gen_shadow_store_guarded)(out, endness, addr, shadow, NULL);
}

typedef VG_REGPARM(2) void (*store_helper_fn)(Addr addr, SizeT ebits);
typedef struct {
   const char* store_fn_name;
   store_helper_fn store_fn;
   const char* store_protected_fn_name;
   store_helper_fn store_protected_fn;
} helper_descriptor;

static VG_REGPARM(2) void helper_store_ebit_8(Addr addr, SizeT ebits)
{
   Ec_Shadow* s = get_ebit_ptr(addr);
   *s = ebits;
}

static VG_REGPARM(2) void helper_store_ebit_8_protected(Addr addr, SizeT ebits)
{
   Ec_Shadow* s = get_ebit_ptr(addr);
   if (*s & EC_(mk_byte_vector)(1, EC_PROTECTED_TAG)) {
      /* do the costly processing if any part of dst is marked protected */
      UChar narrowed_ebits = ebits;
      EC_(check_store)(addr, 1, &narrowed_ebits);
   }
   *s &= EC_PROTECTED_TAG;
   *s |= ebits;
}

static const helper_descriptor helper_desc_8 = {
   "ec_store_ebit_8", helper_store_ebit_8,
   "ec_store_ebit_8_protected", helper_store_ebit_8_protected,
};

static VG_REGPARM(2) void helper_store_ebit_16(Addr addr, SizeT ebits)
{
   UShort narrowed_ebits = ebits;
   if (fits_map(addr, 2)) {
      UShort* s = (UShort*) get_ebit_ptr(addr);
      *s = ebits;
   } else {
      helper_store_slow(addr, 2, (Ec_Shadow*)&narrowed_ebits);
   }
}

static VG_REGPARM(2) void helper_store_ebit_16_protected(Addr addr, SizeT ebits)
{
   UShort narrowed_ebits = ebits;
   if (fits_map(addr, 2)) {
      UShort* s = (UShort*) get_ebit_ptr(addr);
      *s &= EC_(mk_byte_vector)(2, EC_PROTECTED_TAG);
      if (*s)
         EC_(check_store)(addr, 2, (Ec_Shadow*)&narrowed_ebits);
      *s |= ebits;
   } else {
      helper_store_slow(addr, 2, (Ec_Shadow*)&narrowed_ebits);
   }
}

static const helper_descriptor helper_desc_16 = {
   "ec_store_ebit_16", helper_store_ebit_16,
   "ec_store_ebit_16_protected", helper_store_ebit_16_protected,
};

static VG_REGPARM(2) void helper_store_ebit_32(Addr addr, SizeT ebits)
{
   UWord narrowed_ebits = ebits;
   if (fits_map(addr, 4)) {
      UWord* s = (UWord*) get_ebit_ptr(addr);
      *s = ebits;
   } else {
      helper_store_slow(addr, 4, (Ec_Shadow*)&narrowed_ebits);
   }
}

static VG_REGPARM(2) void helper_store_ebit_32_protected(Addr addr, SizeT ebits)
{
   UWord narrowed_ebits = ebits;
   if (fits_map(addr, 4)) {
      UWord* s = (UWord*) get_ebit_ptr(addr);
      *s &= EC_(mk_byte_vector)(4, EC_PROTECTED_TAG);
      if (*s)
         EC_(check_store)(addr, 4, (Ec_Shadow*)&narrowed_ebits);
      *s |= ebits;
   } else {
      helper_store_slow(addr, 4, (Ec_Shadow*)&narrowed_ebits);
   }
}

static const helper_descriptor helper_desc_32 = {
   "ec_store_ebit_32", helper_store_ebit_32,
   "ec_store_ebit_32_protected", helper_store_ebit_32_protected,
};

static VG_REGPARM(2) void helper_store_ebit_64(Addr addr, SizeT ebits)
{
   ULong narrowed_ebits = ebits;
   if (fits_map(addr, 8)) {
      ULong* s = (ULong*) get_ebit_ptr(addr);
      *s = ebits;
   } else {
      helper_store_slow(addr, 8, (Ec_Shadow*)&narrowed_ebits);
   }
}

static VG_REGPARM(2) void helper_store_ebit_64_protected(Addr addr, SizeT ebits)
{
   ULong narrowed_ebits = ebits;
   if (fits_map(addr, 8)) {
      ULong* s = (ULong*) get_ebit_ptr(addr);
      *s &= EC_(mk_byte_vector)(8, EC_PROTECTED_TAG);
      if (*s)
         EC_(check_store)(addr, 8, (Ec_Shadow*)&narrowed_ebits);
      *s |= ebits;
   } else {
      helper_store_slow(addr, 8, (Ec_Shadow*)&narrowed_ebits);
   }
}

static const helper_descriptor helper_desc_64 = {
   "ec_store_ebit_64", helper_store_ebit_64,
   "ec_store_ebit_64_protected", helper_store_ebit_64_protected,
};

static void gen_ebit_store_part(
      IRSB* out, IRExpr* addr, IRExpr* value, SizeT value_size, SizeT offset,
      IREndness e, IRExpr* guard, const helper_descriptor* d)
{
   SizeT part_size = sizeofIRType(typeOfIRExpr(out->tyenv, value));
   if (e == Iend_LE)
      offset = value_size - (offset + part_size);

   if (offset != 0) {
      IRTemp addr_offset_tmp = newIRTemp(out->tyenv, EC_NATIVE_IRTYPE);
      IRExpr* addr_offset = IRExpr_Binop(
               EC_(op_for_type)(Iop_Add8, EC_NATIVE_IRTYPE),
               addr, EC_(const_sizet)(offset));
      addStmtToIRSB(out, IRStmt_WrTmp(addr_offset_tmp, addr_offset));
      addr = IRExpr_RdTmp(addr_offset_tmp);
   }

   {
      IRTemp value_widened_tmp = newIRTemp(out->tyenv, EC_NATIVE_IRTYPE);
      addStmtToIRSB(out, IRStmt_WrTmp(value_widened_tmp, EC_(change_width)(out->tyenv, value, EC_NATIVE_IRTYPE)));
      value = IRExpr_RdTmp(value_widened_tmp);
   }

   IRStmt* store_stmt = NULL;
   if (EC_(opt_protection)) {
      store_stmt = IRStmt_Dirty(unsafeIRDirty_0_N(
               2, d->store_protected_fn_name, VG_(fnptr_to_fnentry)(d->store_protected_fn),
               mkIRExprVec_2(addr, value)));
   } else {
      store_stmt = IRStmt_Dirty(unsafeIRDirty_0_N(
               2, d->store_fn_name, VG_(fnptr_to_fnentry)(d->store_fn),
               mkIRExprVec_2(addr, value)));
   }
   if (guard)
      store_stmt->Ist.Dirty.details->guard = guard;
   addStmtToIRSB(out, store_stmt);
}

void EC_(gen_shadow_store_guarded)(
      IRSB* out, IREndness endness, IRExpr* addr, Ec_ShadowExpr shadow, IRExpr* guard)
{
   tl_assert(addr);
   tl_assert(shadow.ebits);
   /* TODO: handling endianity swapping */
#ifdef VG_BIGENDIAN
   tl_assert(endness == Iend_BE);
#else
   tl_assert(endness == Iend_LE);
#endif

   IRType shadow_type = typeOfIRExpr(out->tyenv, shadow.ebits);
   switch (shadow_type) {
      case Ity_I8:
         gen_ebit_store_part(out, addr, shadow.ebits, 1, 0, endness, guard, &helper_desc_8);
      break;
      case Ity_I16:
         gen_ebit_store_part(out, addr, shadow.ebits, 2, 0, endness, guard, &helper_desc_16);
      break;
      case Ity_I32:
         gen_ebit_store_part(out, addr, shadow.ebits, 4, 0, endness, guard, &helper_desc_32);
      break;
      case Ity_I64:
         gen_ebit_store_part(out, addr, shadow.ebits, 8, 0, endness, guard, &helper_desc_64);
      break;
      case Ity_I128:
         gen_ebit_store_part(
            out, addr, IRExpr_Unop(Iop_128to64, shadow.ebits), 16, 0, endness, guard, &helper_desc_64);
         gen_ebit_store_part(
            out, addr, IRExpr_Unop(Iop_128HIto64, shadow.ebits), 16, 8, endness, guard, &helper_desc_64);
      break;
      case Ity_V128:
         gen_ebit_store_part(
             out, addr, IRExpr_Unop(Iop_V128to64, shadow.ebits), 16, 0, endness, guard, &helper_desc_64);
         gen_ebit_store_part(
             out, addr, IRExpr_Unop(Iop_V128HIto64, shadow.ebits), 16, 8, endness, guard, &helper_desc_64);
      break;
      case Ity_V256:
         gen_ebit_store_part(
             out, addr, IRExpr_Unop(Iop_V256to64_0, shadow.ebits), 32, 0, endness, guard, &helper_desc_64);
         gen_ebit_store_part(
             out, addr, IRExpr_Unop(Iop_V256to64_1, shadow.ebits), 32, 8, endness, guard, &helper_desc_64);
         gen_ebit_store_part(
             out, addr, IRExpr_Unop(Iop_V256to64_2, shadow.ebits), 32, 16, endness, guard, &helper_desc_64);
         gen_ebit_store_part(
             out, addr, IRExpr_Unop(Iop_V256to64_3, shadow.ebits), 32, 24, endness, guard, &helper_desc_64);
      break;
      default:
         VG_(tool_panic)("Unsupported ebit shadow type");
   }

   /* And store the origin (separate helper), if enabled */
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
