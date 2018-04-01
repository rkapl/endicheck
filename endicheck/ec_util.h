/*--------------------------------------------------------------------*/
/*--- A header file for inline helpers function for EC.          ---*/
/*---                                                 ec_util.h ---*/
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

#ifndef __EC_UTIL_H
#define __EC_UTIL_H

#include "ec_include.h"

#if VG_WORDSIZE == 4
#define EC_NATIVE_IRTYPE Ity_I32
#else
#define EC_NATIVE_IRTYPE Ity_I64
#endif

/* LARGEINT is te largest integer supported by the platform */
#if VGA_ppc32
#define EC_LARGEINT Ity_I32
typedef uint32_t Ec_LargeInt;
#else
typedef uint64_t Ec_LargeInt;
#define EC_LARGEINT Ity_I64
#define EC_64INT
#endif

static inline ULong EC_(mk_byte_vector)(int length,  UChar first, UChar rest)
{
   tl_assert(length > 0 && length <= sizeof(ULong));
   Ec_LargeInt acc = rest;
   for (int i = 1; i<length; i++) {
      acc <<= 8;
      acc |= rest;
   }
   return acc;
}

static inline IRExpr* EC_(const_sizet)(SizeT size)
{
   if (sizeof(SizeT) == 4)
      return IRExpr_Const(IRConst_U32(size));
   else if (sizeof(SizeT) == 8)
      return IRExpr_Const(IRConst_U64(size));
   else
      VG_(tool_panic)("unknown sizeof(SizeT)");
}

/* Return and IROp of correct argument size. Assume the `base` irop is the byte-sized
 * and followed with its 16,32,64 versions, as common in VEX IR */
static inline IROp EC_(op_for_type)(IROp base, IRType type)
{
   switch(type) {
      case Ity_I8:
         return base + 0;
      case Ity_I16:
         return base + 1;
      case Ity_I32:
         return base + 2;
      case Ity_I64:
         return base + 3;
      default:
         VG_(tool_panic)("op_for_type unsupported type");
   }
}

static inline IRExpr* EC_(change_width)(IRTypeEnv* env, IRExpr* value, IRType to)
{
   IRType from = typeOfIRExpr(env, value);
   if (from == to)
      return value;

   switch (from) {
      case Ity_I8:
         switch (to) {
         case Ity_I16:
            return IRExpr_Unop(Iop_8Uto16, value);
         case Ity_I32:
            return IRExpr_Unop(Iop_8Uto32, value);
         case Ity_I64:
            return IRExpr_Unop(Iop_8Uto64, value);
         default:
            VG_(tool_panic)("change_width unsupported combination");
         }
      case Ity_I16:
         switch (to) {
         case Ity_I8:
            return IRExpr_Unop(Iop_16to8, value);
         case Ity_I32:
            return IRExpr_Unop(Iop_16Uto32, value);
         case Ity_I64:
            return IRExpr_Unop(Iop_16Uto64, value);
         default:
            VG_(tool_panic)("change_width unsupported combination");
         }
      case Ity_I32:
         switch (to) {
         case Ity_I8:
            return IRExpr_Unop(Iop_32to8, value);
         case Ity_I16:
            return IRExpr_Unop(Iop_32to16, value);
         case Ity_I64:
            return IRExpr_Unop(Iop_32Uto64, value);
         default:
            VG_(tool_panic)("change_width unsupported combination");
         }
      case Ity_I64:
         switch (to) {
         case Ity_I8:
            return IRExpr_Unop(Iop_64to8, value);
         case Ity_I16:
            return IRExpr_Unop(Iop_64to16, value);
         case Ity_I32:
            return IRExpr_Unop(Iop_64to32, value);
         default:
            VG_(tool_panic)("change_width unsupported combination");
         }
   default:
      VG_(tool_panic)("change_width unsupported combination");
   }
}

#endif
