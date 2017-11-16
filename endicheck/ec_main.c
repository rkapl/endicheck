
/*--------------------------------------------------------------------*/
/*--- Endicheck: Wrong endianityn checker                ec_main.c ---*/
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

#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"
#include "ec_include.h"
#include "ec_shadow.h"
#include "ec_errors.h"
#include <stddef.h>

#define EC_INSTRUMENT_HEAPID "ec_instrument"

typedef struct {
      IRSB* out_sb;
      IRTypeEnv* tyenv;
      IRType word_type;
      IRTemp shadow_temp_base;
      IRTemp shadow_state_base;
} Ec_Env;

static void EC_(post_clo_init)(void)
{
}

static Bool has_endianity(IRType ty)
{
   switch(ty) {
      case Ity_I1:
      case Ity_F128:
      case Ity_F64:
      case Ity_F32:
      case Ity_F16:
      case Ity_D64:
      case Ity_D128:
      case Ity_D32:
         return False;

      case Ity_I8: /* yes, it can have endianess attached, although by default it is ANY */
      case Ity_I16:
      case Ity_I32:
      case Ity_I64:
      case Ity_I128:
      case Ity_V128:
      case Ity_V256:
         return True;

      default:
         VG_(tool_panic)("endicheck unsupported IRType");
   }
}

static Ec_Shadow default_endianity(IRType ty)
{
   tl_assert(has_endianity(ty));
   return (ty == Ity_I8) ? EC_ANY : EC_NATIVE;
}

Ec_Endianity EC_(endianity_for_shadow)(Ec_Shadow shadow) {
   return shadow & 0x3;
}

Bool EC_(is_empty_for_shadow) (Ec_Shadow shadow) {
   return shadow & EC_EMPTY_TAG;
}

/* Get a type of a temp's shadow */
static IRType type2shadow(IRType ty)
{
   switch(ty) {
      case Ity_I1:
      case Ity_F128:
      case Ity_F64:
      case Ity_F32:
      case Ity_F16:
      case Ity_D64:
      case Ity_D128:
      case Ity_D32:
         /* We assume these types must always be of native endianity, so use a dummy shadow */
         return Ity_I1;

      case Ity_I8:
      case Ity_I16:
      case Ity_I32:
      case Ity_I64:
      case Ity_I128:
      case Ity_V128:
      case Ity_V256:
         /* We could try to make these types smaller (we don't need 8 bits per byte),
          * but for simplicity we don't pack them */
         return ty;

      default:
         VG_(tool_panic)("endicheck unsupported IRType");
   }
}

/* Return and IROp of correct argument size. Assume the `base` irop is the byte-sized
 * and followed with its 16,32,64 versions, as common in VEX IR */
static IROp op_for_type(IROp base, IRType type)
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

/* Get a shadow temp variable corresponding to a temp */
static IRTemp temp2shadow(Ec_Env* env, IRTemp temp)
{
   return temp + env->shadow_temp_base;
}

/*  Get a shadow state offset corresonding to a given state offset */
static Int state2shadow(Ec_Env* env, Int offset)
{
   return offset + env->shadow_state_base;
}

static void stmt(Ec_Env* env, IRStmt* stmt) {
   addStmtToIRSB(env->out_sb, stmt);
}

/* The same as MC assignNew. Assigns the expression to new temporary and
 * returns reference to that temporary, if needed.
 *
 * We use this function every time when an expression (which was previously flat)
 * is expanded to a non-flat one or when we make a composite constant.
 */
static IRExpr* assignNew(Ec_Env* env, IRExpr* expr)
{
   if (isIRAtom(expr))
      return expr;

   IRType type = typeOfIRExpr(env->tyenv, expr);
   IRTemp tmp = newIRTemp(env->tyenv, type);
   IRStmt* assignment = IRStmt_WrTmp(tmp, expr);
   tl_assert(isFlatIRStmt(assignment));
   stmt(env, assignment);
   return IRExpr_RdTmp(tmp);
}

static inline ULong mk_shadow(Ec_Env* env,int length, Ec_Shadow e)
{
   tl_assert(length > 0 && length <= 8);
   ULong acc = 0;
   for (int i = 0; i<length; i++) {
      acc <<= 8;
      acc |= e;
   }
   return acc;
}

static IRExpr* mk_shadow_i128(Ec_Env* env,Ec_Shadow endianity)
{
   IRExpr* part = IRExpr_Const(IRConst_U64(mk_shadow(env, 8, endianity)));
   return assignNew(env, IRExpr_Binop(Iop_64HLto128, part, part));
}

static IRExpr* mk_shadow_v128(Ec_Env* env,Ec_Shadow endianity)
{
   IRExpr* part = IRExpr_Const(IRConst_U64(mk_shadow(env, 8, endianity)));
   return assignNew(env, IRExpr_Binop(Iop_64HLtoV128, part, part));
}

static IRExpr* mk_shadow_v256(Ec_Env* env,Ec_Shadow endianity)
{
   IRExpr* part = assignNew(env, mk_shadow_v128(env, endianity));
   return assignNew(env, IRExpr_Binop(Iop_V128HLtoV256, part, part));
}

static IRExpr* mk_shadow_vector(Ec_Env* env,IRType ty, Ec_Shadow endianity)
{
   switch(ty) {      
      case Ity_I8:
         return IRExpr_Const(IRConst_U8(mk_shadow(env, 1, endianity)));
      case Ity_I16:
         return IRExpr_Const(IRConst_U16(mk_shadow(env, 2, endianity)));
      case Ity_I32:
         return IRExpr_Const(IRConst_U32(mk_shadow(env, 4, endianity)));
      case Ity_I64:
         return IRExpr_Const(IRConst_U64(mk_shadow(env, 8, endianity)));
      case Ity_D128:
      case Ity_F128:
      case Ity_I128:
         return mk_shadow_i128(env, endianity);
      case Ity_V128:
         return mk_shadow_v128(env, endianity);
      case Ity_V256:
         return mk_shadow_v256(env, endianity);
      default:
         VG_(tool_panic)("unhandled IrType");
   }
}

static IRExpr* widen64(Ec_Env* env, IRExpr* from)
{
   IRType type = typeOfIRExpr(env->tyenv, from);
   switch(type) {
      case Ity_I8:
         return IRExpr_Unop(Iop_8Uto64, from);
      case Ity_I16:
         return IRExpr_Unop(Iop_16Uto64, from);
      case Ity_I32:
         return IRExpr_Unop(Iop_32Uto64, from);
      case Ity_I64:
         return from;
      default:
         VG_(tool_panic)("widen64 not given integer");
   }
}
static IRExpr* narrow64(Ec_Env* env, IRExpr* from, IRType dst) {
   IRType type = typeOfIRExpr(env->tyenv, from);
   tl_assert(type == Ity_I64);
   switch(dst) {
      case Ity_I8:
         return IRExpr_Unop(Iop_64to8, from);
      case Ity_I16:
         return IRExpr_Unop(Iop_64to16, from);
      case Ity_I32:
         return IRExpr_Unop(Iop_64to32, from);
      case Ity_I64:
         return from;
      default:
         VG_(tool_panic)("narrow64 not given integer");
   }
}

static IRExpr* default_shadow_for_type(Ec_Env* env, IRType expr_type)
{
   tl_assert(has_endianity(expr_type));
   return mk_shadow_vector(env, type2shadow(expr_type), default_endianity(expr_type));
}

/* Returns a default shadow value (usually EC_NATIVE) for the given
 * type of expression
 */
static IRExpr* default_shadow(Ec_Env* env, IRExpr* expr)
{
   IRType expr_type = typeOfIRExpr(env->tyenv, expr);
   return default_shadow_for_type(env, expr_type);
}

static IRExpr* expr2shadow(Ec_Env* env, IRExpr* expr);

/*
 * Default handler for IR ops that just move around bytes. In that case we
 * simply apply the same operation to the shadow data. An example of these
 * are narrowing conversions.
 */
static IRExpr* same_for_shadow(Ec_Env* env, IRExpr* expr)
{
   switch (expr->tag) {
   case Iex_Unop:
      return IRExpr_Unop(expr->Iex.Unop.op, expr2shadow(env, expr->Iex.Unop.arg));
   case Iex_Binop:
      return IRExpr_Binop(expr->Iex.Binop.op,
            expr2shadow(env, expr->Iex.Binop.arg1),
            expr2shadow(env, expr->Iex.Binop.arg2));
   case Iex_Triop:
      return IRExpr_Triop(expr->Iex.Triop.details->op,
            expr2shadow(env, expr->Iex.Triop.details->arg1),
            expr2shadow(env, expr->Iex.Triop.details->arg2),
            expr2shadow(env, expr->Iex.Triop.details->arg3));
   default:
      VG_(tool_panic)("expr is not an op");
   }
}

static IRExpr* unop2shadow(Ec_Env* env, IRExpr* expr)
{
   switch (expr->Iex.Unop.op) {
      // for widening, mark the new bytes as NATIVE_EMPTY
      case Iop_8Uto64:
         return IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(mk_shadow(env, 8, EC_NATIVE_EMPTY) & 0xFFFFFFFFFFFFFF00)),
            assignNew(env, same_for_shadow(env, expr)));
      case Iop_16Uto64:
         return IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(mk_shadow(env, 8, EC_NATIVE_EMPTY) & 0xFFFFFFFFFFFF0000)),
            assignNew(env, same_for_shadow(env, expr)));
      case Iop_32Uto64:
         return IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(mk_shadow(env, 8, EC_NATIVE_EMPTY) & 0xFFFFFFFF00000000)),
            assignNew(env, same_for_shadow(env, expr)));
         break;
      case Iop_8Uto32:
         return IRExpr_Binop(Iop_Or32,
            IRExpr_Const(IRConst_U32(mk_shadow(env, 4, EC_NATIVE_EMPTY) & 0xFFFFFF00)),
            assignNew(env, same_for_shadow(env, expr)));
      case Iop_16Uto32:
         return IRExpr_Binop(Iop_Or32,
            IRExpr_Const(IRConst_U32(mk_shadow(env, 4, EC_NATIVE_EMPTY) & 0xFFFF0000)),
            assignNew(env, same_for_shadow(env, expr)));
      case Iop_8Uto16:
         return IRExpr_Binop(Iop_Or16,
            IRExpr_Const(IRConst_U16(mk_shadow(env, 2, EC_NATIVE_EMPTY) & 0xFF00)),
            assignNew(env, same_for_shadow(env, expr)));
      // narrowing is just a byte shuffle
      case Iop_64to16:
      case Iop_64to32:
      case Iop_64to8:
      case Iop_32to16:
      case Iop_32to8:
      case Iop_16to8:
      case Iop_64HIto32:
      case Iop_32HIto16:
      case Iop_16HIto8:
         return same_for_shadow(env, expr);


      default:
         return default_shadow(env, expr);
   }
}

static void split_empty_tags(Ec_Env* env, IRExpr* from, IRExpr** endianess, IRExpr** tags)
{
   IRType type = typeOfIRExpr(env->tyenv, from);
   *endianess = assignNew(env, IRExpr_Binop(op_for_type(Iop_And8, type), mk_shadow_vector(env, type, ~EC_EMPTY_TAG), from));
   *tags = assignNew(env, IRExpr_Binop(op_for_type(Iop_And8, type), mk_shadow_vector(env, type, EC_EMPTY_TAG), from));
}

typedef UChar shadow_vector __attribute__ ((vector_size (8)));
static VG_REGPARM(2) ULong helper_combine_or_shadow(ULong a_shadow, ULong b_shadow)
{
   /* hopefully the compiler will recognize these are constants */
   ULong tag_mask = mk_shadow(NULL, 8, EC_EMPTY_TAG);
   ULong native = mk_shadow(NULL, 8, EC_EMPTY_TAG);

   /* True if both cells are not empty */
   ULong nempty_intersection = (~a_shadow & ~b_shadow) & tag_mask;
   /* True if both cells are mpty */
   ULong empty_union = (a_shadow | b_shadow) & tag_mask;
   if ((a_shadow & ~tag_mask) == (b_shadow & ~tag_mask)) {
      /* the shadows are the same, do the regular stuff for bitops */
      return a_shadow | empty_union;
   } else if (nempty_intersection) {
      /* the interesection is non-empty, do the regular stuff for bitops */
      return native | empty_union;
   } else {
      /* we use SIMD for parallel comparison */
      shadow_vector va_tags = (shadow_vector) (a_shadow & tag_mask);
      shadow_vector vb_tags = (shadow_vector) (b_shadow & tag_mask);

      shadow_vector va_filtered_shadow = (va_tags == 0) & ((shadow_vector)a_shadow);
      shadow_vector vb_filtered_shadow = (vb_tags == 0) & ((shadow_vector)b_shadow);
      shadow_vector empty_shadow = (((shadow_vector)empty_union) != 0) & ((shadow_vector) native);

      ULong shadow = ((ULong)va_filtered_shadow) | ((ULong)vb_filtered_shadow) | ((ULong)empty_shadow);
      return (shadow & ~tag_mask) | empty_union;
   }
}

static IRExpr* or2shadow(Ec_Env* env, IRExpr* expr)
{
   IRExpr* arg1 = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg1));
   IRExpr* arg2 = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg2));
   /* Call a helper for doing the OR */
   IRExpr* v = IRExpr_CCall(mkIRCallee(2, "combine_or_shadow", VG_(fnptr_to_fnentry)(helper_combine_or_shadow)),
      Ity_I64, mkIRExprVec_2(
             assignNew(env, widen64(env, arg1)),
             assignNew(env, widen64(env, arg2))));
   return narrow64(env, assignNew(env, v), typeOfIRExpr(env->tyenv, expr));
}

static IRExpr* bitop2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(expr->tag == Iex_Binop);
   /* Bitwise operations do not care about the order of bytes.
    * If the two argument shadows are the same (modulo the empty tag), propagate them.
    * If they are not, return NATIVE.
    *
    * However, for OR, we want a special behaviour, if we are merging disjoint data
    * (based on empty tags).
    */
   IRType type = typeOfIRExpr(env->tyenv, expr->Iex.Binop.arg1);
   IRExpr *arg1se, *arg1st, *arg2se, *arg2st;
   IRExpr* arg1s = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg1));
   split_empty_tags(env, arg1s, &arg1se, &arg1st);
   IRExpr* arg2s = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg2));
   split_empty_tags(env, arg2s, &arg2se, &arg2st);
   IRExpr* are_equal = assignNew(env, IRExpr_Binop(op_for_type(Iop_CmpEQ8, type), arg1st, arg2st));

   if (expr->Iex.Binop.op >= Iop_Xor8 && expr->Iex.Binop.op <= Iop_Xor64) {
      /* There is no simple tag rule for XOR */
      return IRExpr_ITE(are_equal, arg1s, default_shadow(env, expr));
   } else if (expr->Iex.Binop.op >= Iop_And8 && expr->Iex.Binop.op <= Iop_And64) {
      /* The empty tags are ORed together */
      IRExpr* result_tags = assignNew(env, IRExpr_Binop(op_for_type(Iop_Or8, type), arg1st, arg2st));
      IRExpr* shadow = assignNew(env, IRExpr_ITE(are_equal, arg1s, default_shadow(env, expr)));
      return IRExpr_Binop(op_for_type(Iop_Or8, type), shadow, result_tags);
   } else {
      VG_(tool_panic)("Not a bitop");
   }
}

static int shift_type_size(IRType type) {
   switch (type) {
      case Ity_I8:
         return 8;
      case Ity_I16:
         return 16;
      case Ity_I32:
         return 32;
      case Ity_I64:
         return 64;
      default:
         VG_(tool_panic)("Unsupported shift size");
   }
}

static IROp reverse_shift(IROp shift)
{
   if (shift >= Iop_Shl8 && shift <= Iop_Shl64) {
      return Iop_Shr8 + (shift - Iop_Shl8);
   } else if (shift >= Iop_Shr8 && shift <= Iop_Shr64) {
      return Iop_Shl8 + (shift - Iop_Shr8);
   } else {
      VG_(tool_panic)("Unknown shift instruction in reverse_shift");
   }

}

static IRExpr* shift2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(expr->tag == Iex_Binop);
   IRType type = typeOfIRExpr(env->tyenv, expr);
   int value_size = shift_type_size(type);
   if (value_size == 8)
      return default_shadow(env, expr);

   /* Note: arg1 is the value, arg2 is the shift amount (8bit) */
   IRExpr* mod_8 = assignNew(env, IRExpr_Binop(
            Iop_And8, expr->Iex.Binop.arg2, IRExpr_Const(IRConst_U8(7))));
   IRExpr* is_byte_sized = assignNew(env, IRExpr_Binop(Iop_CmpEQ8, mod_8, IRExpr_Const(IRConst_U8(0))));

   /* these are the new bytes that will appear in empty areas and get empty endianess */
   IRExpr* new_bytes = assignNew(env,
      IRExpr_Binop(reverse_shift(expr->Iex.Binop.op),
         mk_shadow_vector(env, type, EC_NATIVE_EMPTY),
         assignNew(env, IRExpr_Binop(Iop_Sub8,
            IRExpr_Const(IRConst_U8(value_size)),
            expr->Iex.Binop.arg2))));

   /* merge the shifted shadow with the new bytes */
   IRExpr* shifted_shadow = assignNew(env,
      IRExpr_Binop(op_for_type(Iop_Or8, type),
         new_bytes,
         assignNew(env, IRExpr_Binop(expr->Iex.Binop.op,
            expr2shadow(env, expr->Iex.Binop.arg1),
            expr->Iex.Binop.arg2))));
   //return IRExpr_ITE(is_byte_sized, shifted_shadow, default_shadow(env, expr));
   return IRExpr_ITE(is_byte_sized, shifted_shadow, default_shadow(env, expr));
}

static IRExpr* binop2shadow(Ec_Env* env, IRExpr* expr)
{
   switch (expr->Iex.Binop.op) {
      case Iop_Or8:
      case Iop_Or16:
      case Iop_Or32:
      case Iop_Or64:
         return or2shadow(env, expr);
      case Iop_And8:
      case Iop_And16:
      case Iop_And32:
      case Iop_And64:
      case Iop_Xor8:
      case Iop_Xor16:
      case Iop_Xor32:
      case Iop_Xor64:
         return bitop2shadow(env, expr);

      /* arithmetic shift is not endian agnostic */
      case Iop_Shl8:
      case Iop_Shl16:
      case Iop_Shl32:
      case Iop_Shl64:
      case Iop_Shr8:
      case Iop_Shr16:
      case Iop_Shr32:
      case Iop_Shr64:
         return shift2shadow(env, expr);

   default:
      return default_shadow(env, expr);
   }
}

static IRExpr* triop2shadow(Ec_Env* env, IRExpr* expr)
{
   IRTriop* op = expr->Iex.Triop.details;
   switch (op->op) {
   default:
      return default_shadow(env, expr);
   }
}

static IRExpr* qop2shadow(Ec_Env* env, IRExpr* expr)
{
   IRQop* op = expr->Iex.Qop.details;
   switch (op->op) {
   default:
      return default_shadow(env, expr);
   }
}

static IRExpr* ite2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(expr->tag == Iex_ITE);
   return IRExpr_ITE(
            expr->Iex.ITE.cond,
            expr2shadow(env, expr->Iex.ITE.iftrue), expr2shadow(env, expr->Iex.ITE.iffalse));
}

static IRExpr* expr2shadow(Ec_Env* env, IRExpr* expr)
{
   switch (expr->tag) {
      case Iex_Get:
         return IRExpr_Get(state2shadow(env, expr->Iex.Get.offset), type2shadow(expr->Iex.Get.ty));
      case Iex_Load:
         return EC_(gen_shadow_load)(env->out_sb, expr->Iex.Load.end, expr->Iex.Load.ty, expr->Iex.Load.addr);
      case Iex_RdTmp:
         return IRExpr_RdTmp(temp2shadow(env, expr->Iex.RdTmp.tmp));
      case Iex_Unop:
         return unop2shadow(env, expr);
      case Iex_Binop:
         return binop2shadow(env, expr);
      case Iex_Triop:
         return triop2shadow(env, expr);
      case Iex_Qop:
         return qop2shadow(env, expr);
      case Iex_ITE:
         return ite2shadow(env, expr);
      case Iex_Const:
      default:
         return default_shadow(env, expr);
   }
}

static void shadow_wrtmp(Ec_Env *env, IRTemp to, IRExpr* from)
{
   if (has_endianity(typeOfIRTemp(env->tyenv, to))) {
      stmt(env, IRStmt_WrTmp(temp2shadow(env, to), expr2shadow(env, from)));
   }
}

static void shadow_put(Ec_Env *env, Int to, IRExpr* from)
{
   if (has_endianity(typeOfIRExpr(env->tyenv, from))) {
      stmt(env, IRStmt_Put(state2shadow(env, to), expr2shadow(env, from)));
   }
}

static void shadow_puti(Ec_Env *env, IRPutI* puti)
{
   IRRegArray* descr = puti->descr;
   if (has_endianity(puti->descr->elemTy)) {
      IRType shadow_type = type2shadow(puti->descr->elemTy);
      IRExpr* shadow_value = expr2shadow(env, puti->data);
      IRRegArray* new_descr = mkIRRegArray(descr->base + env->shadow_state_base, shadow_type, descr->nElems);
      stmt(env, IRStmt_PutI(mkIRPutI(new_descr, puti->ix, puti->bias, shadow_value)));
   }
}

static void shadow_store(Ec_Env *env, IREndness endianess, IRExpr* addr, IRExpr* value, IRExpr* guard)
{
   IRType type = typeOfIRExpr(env->tyenv, value);
   IRExpr* shadow_value;
   if (has_endianity(type))
      shadow_value = expr2shadow(env, value);
   else
      shadow_value = mk_shadow_vector(env, type, EC_ANY);

   /* TODO: handle endianess swapping, this is not the correct way */
   if (!guard) {
      EC_(gen_shadow_store)(env->out_sb, endianess, addr, shadow_value);
   } else {
      EC_(gen_shadow_store_guarded)(env->out_sb, endianess, addr, shadow_value, guard);
   }
}

static void shadow_load_guarded(Ec_Env *env, IRLoadG* load_op)
{
   IRExpr* loaded;
   IRType type, arg;
   typeOfIRLoadGOp(load_op->cvt, &type, &arg);
   if (has_endianity(type)) {
      IRExpr* alt = expr2shadow(env, load_op->alt);
      loaded = EC_(gen_shadow_load_guarded)(
            env->out_sb, load_op->end, type, load_op->addr, load_op->cvt, load_op->guard, alt);
   } else {
      loaded = mk_shadow_vector(env, type, EC_ANY);
   }
   stmt(env, IRStmt_WrTmp(temp2shadow(env, load_op->dst), loaded));
}

static void shadow_dirty(Ec_Env* env, IRDirty* dirty)
{
   if (dirty->tmp == IRTemp_INVALID)
      return;

   IRType type = typeOfIRTemp(env->tyenv, dirty->tmp);
   stmt(env, IRStmt_WrTmp(temp2shadow(env, dirty->tmp), default_shadow_for_type(env, type)));
}

static IRSB* EC_(instrument) (
   VgCallbackClosure* closure,
   IRSB* sb,
   const VexGuestLayout* layout,
   const VexGuestExtents* vge,
   const VexArchInfo* archinfo_host,
   IRType gWordTy, IRType hWordTy )
{
   Ec_Env env;

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }

   env.out_sb = deepCopyIRSBExceptStmts(sb);
   env.word_type = gWordTy;
   env.shadow_state_base = layout->total_sizeB;
   env.tyenv = env.out_sb->tyenv;

   /* Unlike memcheck, we try to get off with having direct mapping between temporaries and their
    * shadow values. They are placed directly after the regular variables */
   int temp_count = sb->tyenv->types_used;
   env.shadow_temp_base = temp_count;
   for(int i = 0; i<temp_count; i++) {
      IRType shadow_type = type2shadow(typeOfIRTemp(env.out_sb->tyenv, i));
      IRTemp temp_index = newIRTemp(env.out_sb->tyenv, shadow_type);
      tl_assert(temp_index == temp2shadow(&env, i));
   }

   /* Copy verbatim any IR preamble preceding the first IMark */
   int i;
   for (i = 0; i < sb->stmts_used && sb->stmts[i]->tag != Ist_IMark; i++) {
      IRStmt* st = sb->stmts[i];
      tl_assert(st);
      tl_assert(isFlatIRStmt(st));
      /* TODO: mark temporaries defined in preamble as native endianity */
      stmt(&env, sb->stmts[i] );
   }

   for(; i < sb->stmts_used; i++) {
      IRStmt* st = sb->stmts[i];
      switch (st->tag) {
         case Ist_Put:
            shadow_put(&env, st->Ist.Put.offset, st->Ist.Put.data);
         break;
         case Ist_PutI:
            shadow_puti(&env, st->Ist.PutI.details);
         break;
         case Ist_WrTmp:
            shadow_wrtmp(&env, st->Ist.WrTmp.tmp, st->Ist.WrTmp.data);
         break;
         case Ist_Store:
            shadow_store(&env, st->Ist.Store.end, st->Ist.Store.addr, st->Ist.Store.data, NULL);
         break;

         case Ist_Dirty: /* TODO: not yet implemented */
            shadow_dirty(&env, st->Ist.Dirty.details);
         break;

         case Ist_LoadG: /* TODO: convert to non-guarded case */
            shadow_load_guarded(&env, st->Ist.LoadG.details);
         break;
         case Ist_StoreG:/* TODO: convert to non-guarded case */
            shadow_store(
                  &env, st->Ist.StoreG.details->end, st->Ist.StoreG.details->addr,
                  st->Ist.StoreG.details->data, st->Ist.StoreG.details->guard);
         break;

         case Ist_CAS:   /* TODO: not yet implemented */
         case Ist_LLSC:  /* TODO: not yet implemented */
         case Ist_Exit:  /* consider checking endianity of the guard expression*/
         break;


         case Ist_AbiHint: /* we don't care */
         case Ist_IMark:
         case Ist_NoOp:
         case Ist_MBE:
         break;

         default:
            ppIRStmt(st);
            VG_(printf)("\n");
            VG_(tool_panic)("endicheck: unhandled IRStmt");
      }
      stmt(&env, st);
   }

   return env.out_sb;
}

static void EC_(fini)(Int exitcode)
{
}

#define ECRQ_DUMP_ROW_SIZE 40
static void ecrq_dump_mem(UWord* arg)
{
   Addr start = arg[1];
   size_t size = arg[2];
   VG_(message)(Vg_UserMsg, "Memory endianity dump (legend: Undefined, Native, Target, Any, - Empty):\n");
   for(size_t i = 0; i<size; i += ECRQ_DUMP_ROW_SIZE) {
      char row[ECRQ_DUMP_ROW_SIZE*2 + 1];
      size_t row_size = size - i;
      if (row_size > ECRQ_DUMP_ROW_SIZE)
         row_size = ECRQ_DUMP_ROW_SIZE;
      for (size_t c = 0; c<row_size; c++) {
         Ec_Shadow e = EC_(get_shadow)(start + i + c);
         row[c*2] = EC_(endianity_codes)[EC_(endianity_for_shadow)(e)];
         row[c*2 + 1] = EC_(is_empty_for_shadow)(e) ? '-' : ' ';
      }
      row[row_size*2] = 0;

      VG_(message)(Vg_UserMsg, "%p: %s\n", (void*)(start + i), row);
   }
   VG_(message)(Vg_UserMsg, "\n");
}

static void ecrq_mark_endian(UWord* arg)
{
   Addr start = arg[1];
   SizeT size = arg[2];
   Ec_Shadow endianity = arg[3];
   for(SizeT i = 0; i<size; i++) {
      EC_(set_shadow)(start + i, endianity);
   }
}

static int ecrq_assert_endian(ThreadId tid, UWord* arg)
{
   Addr start = arg[1];
   SizeT size = arg[2];
   Ec_Shadow endianity = arg[3];
   const char* msg = (const char*) arg[4];

   return EC_(check_memory_endianity)(tid, start, size, endianity, msg);
}

static Bool EC_(client_request) ( ThreadId tid, UWord* arg, UWord* ret )
{
   UWord req = arg[0];
   if (VG_IS_TOOL_USERREQ('E', 'C', req)) {
      switch (req) {
         case EC_USERREQ__DUMP_MEM:
            ecrq_dump_mem(arg);
            *ret = 1;
         break;
         case EC_USERREQ__MARK_ENDIANITY:
            ecrq_mark_endian(arg);
            *ret = 1;
         break;
         case EC_USERREQ__CHECK_ENDIANITY:
	    *ret = ecrq_assert_endian(tid, arg);
         break;
         default:
            VG_(message)(Vg_UserMsg, "Warning: unknown endicheck client request code %llx\n",(ULong)arg[0]);
         return False;
            return False;
      }
   }
   return False;
}

static Bool ec_process_cmd_line_options(const char* arg)
{
   if VG_BOOL_CLO(arg, "--alow-unknown", EC_(allow_unknown)) {}
   else return False;
   return True;
}

static void ec_print_usage(void) {
   VG_(printf)(
"    --allow-unknown=yes|no      report unknown endianess as error?\n"
   );
}

static void ec_print_debug_usage(void) {

}

const char EC_(endianity_codes)[] = "UNTA";
const char* EC_(endianity_names)[] = {
   "Undefined",
   "Native",
   "Target",
   "Any"
};

static void EC_(pre_clo_init)(void)
{
   VG_(details_name)            ("endicheck");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("wrong endianity detector");
   VG_(details_copyright_author)(
      "Copyright (C) 2002-2017, and GNU GPL'd, by Roman Kapl.");
   VG_(details_bug_reports_to)  ("code@rkapl.cz");

   VG_(basic_tool_funcs)(
            EC_(post_clo_init),
            EC_(instrument),
            EC_(fini));
   VG_(needs_tool_errors)(
            EC_(eq_Error),
            EC_(before_pp_Error),
            EC_(pp_Error),
            True,/*show TIDs for errors*/
            EC_(update_Error_extra),
            EC_(is_recognised_suppression),
            EC_(read_extra_suppression_info),
            EC_(error_matches_suppression),
            EC_(get_error_name),
            EC_(get_extra_suppression_info),
            EC_(print_extra_suppression_use),
            EC_(update_extra_suppression_use));
   VG_(needs_command_line_options)(
            ec_process_cmd_line_options,
            ec_print_usage,
            ec_print_debug_usage);
   VG_(needs_client_requests)(
            EC_(client_request));
   VG_(needs_xml_output)();
}

VG_DETERMINE_INTERFACE_VERSION(EC_(pre_clo_init))

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
