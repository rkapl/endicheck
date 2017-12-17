
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
#include "pub_tool_otrack.h"
#include "pub_tool_execontext.h"
#include "pub_tool_threadstate.h"
#include "ec_include.h"
#include "ec_shadow.h"
#include "ec_errors.h"
#include "ec_util.h"
#include <stddef.h>

#define EC_INSTRUMENT_HEAPID "ec_instrument"

typedef struct {
      IRSB* out_sb;
      IRTypeEnv* tyenv;
      IRType word_type;
      IRTemp shadow_ebit_temp_base;
      IRTemp shadow_otag_temp_base;

      IRTemp shadow_ebit_state_base;
      IRTemp shadow_otag_state_base;
} Ec_Env;

static void EC_(post_clo_init)(void)
{
}

static void stmt(Ec_Env* env, IRStmt* stmt) {
   addStmtToIRSB(env->out_sb, stmt);
}

static Bool has_endianity(IRType ty)
{
   switch(ty) {
      case Ity_F128: /* We always known the endianity is native */
      case Ity_F64:
      case Ity_F32:
      case Ity_F16:
      case Ity_D64:
      case Ity_D128:
      case Ity_D32:
      case Ity_I1:   /* We don't really care */
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
static IRType type2ebit(IRType ty)
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

static VG_REGPARM(0) ULong helper_gen_exectx(void)
{
   ThreadId tid = VG_(get_running_tid)();
   ExeContext* here = VG_(record_ExeContext)(tid, 0);
   tl_assert(here);
   Ec_Otag otag = VG_(get_ECU_from_ExeContext)(here);
   tl_assert(VG_(is_plausible_ECU)(otag));
   return otag;
}

static IRExpr* current_otag(Ec_Env *env)
{
   tl_assert(EC_(opt_track_origins));
   IRTemp otag = newIRTemp(env->tyenv, Ity_I32);
   IRCallee* call = mkIRCallee(0, "ec_gen_exectx", VG_(fnptr_to_fnentry)(helper_gen_exectx));
   stmt(env, IRStmt_WrTmp(otag, IRExpr_CCall(call, Ity_I32, mkIRExprVec_0())));
   IRExpr* expr = IRExpr_RdTmp(otag);
   return expr;
}

static Ec_ShadowExpr add_current_otag(Ec_Env *env, IRExpr *expr)
{
   Ec_ShadowExpr r;
   r.ebits = expr;
   r.origin = NULL;
   if (EC_(opt_track_origins))
      r.origin = current_otag(env);
   return r;
}

/* Get a shadow ebit temp variable corresponding to a temp */
static IRTemp temp2ebits(Ec_Env* env, IRTemp temp)
{
   return temp + env->shadow_ebit_temp_base;
}

/* Get a otag temp variable corresponding to a temp */
static IRTemp temp2otag(Ec_Env* env, IRTemp temp)
{
   tl_assert(EC_(opt_track_origins));
   return temp + env->shadow_otag_temp_base;
}

/*  Get a shadow state ebit offset corresonding to a given state offset */
static Int state2ebits(Ec_Env* env, Int offset)
{
   return offset + env->shadow_ebit_state_base;
}

/*  Get a shadow state origin trackings offset corresonding to a given state offset.
 *  A simple wrapper around get_otrack_shadow_offset.
 */
static Int state2otag(Ec_Env* env, Int offset, IRType type)
{
   tl_assert(EC_(opt_track_origins));
   Int new = VG_(get_otrack_shadow_offset) (offset, sizeofIRType(type));
   if (new != -1)
      new += env->shadow_otag_state_base;
   // VG_(message)(Vg_UserMsg, "Offset mapped %x -> %x\n", offset, new);
   return new;
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

static IRExpr* mk_shadow_i128(Ec_Env* env,Ec_Shadow endianity)
{
   IRExpr* part = IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, endianity)));
   return assignNew(env, IRExpr_Binop(Iop_64HLto128, part, part));
}

static IRExpr* mk_shadow_v128(Ec_Env* env,Ec_Shadow endianity)
{
   IRExpr* part = IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, endianity)));
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
         return IRExpr_Const(IRConst_U8(EC_(mk_byte_vector)(1, endianity)));
      case Ity_I16:
         return IRExpr_Const(IRConst_U16(EC_(mk_byte_vector)(2, endianity)));
      case Ity_I32:
         return IRExpr_Const(IRConst_U32(EC_(mk_byte_vector)(4, endianity)));
      case Ity_I64:
         return IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, endianity)));
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

static IRExpr* widen_to_64(Ec_Env* env, IRExpr* from)
{
   return assignNew(env, EC_(change_width)(env->tyenv, from, Ity_I64));
}
static IRExpr* narrow_from_64(Ec_Env* env, IRExpr* from, IRType dst) {
   IRType type = typeOfIRExpr(env->tyenv, from);
   tl_assert(type == Ity_I64);
   return assignNew(env, EC_(change_width)(env->tyenv, from, dst));
}

static IRExpr* widen_from_32(Ec_Env* env, IRExpr* from, IRType dst)
{
   IRType type = typeOfIRExpr(env->tyenv, from);
   tl_assert(type == Ity_I32);
   return assignNew(env, EC_(change_width)(env->tyenv, from, dst));
}

static IRExpr* narrow_to_32(Ec_Env* env, IRExpr* from) {
   return assignNew(env, EC_(change_width)(env->tyenv, from, Ity_I32));
}

static void helper_check_ebits(ULong ebits)
{
    if (ebits & ~EC_(mk_byte_vector)(8, 0x7)) {
        VG_(message)(Vg_UserMsg, "Invalid ebits 0x%llx\n", ebits);
        VG_(tool_panic)("helper_check_ebits failure");
    }
}

static void check_part(Ec_Env* env, IRExpr* ebits)
{
    stmt(env, IRStmt_Dirty(unsafeIRDirty_0_N(
                0, "ec_check_ebits", VG_(fnptr_to_fnentry)(helper_check_ebits), 
                mkIRExprVec_1(ebits))));
}

/* Will place an assertion on the ebits -- it will check if any invalid bits are set */
static void check_ebits(Ec_Env* env, IRExpr* ebits)
{
    IRType type = typeOfIRExpr(env->tyenv, ebits);
    switch (type) {
        case Ity_I8:
        case Ity_I16:
        case Ity_I32:
        case Ity_I64:
            check_part(env, widen_to_64(env, ebits));
            break;
        case Ity_I128:
            check_part(env, assignNew(env, IRExpr_Unop(Iop_128to64, ebits)));
            check_part(env, assignNew(env, IRExpr_Unop(Iop_128HIto64, ebits)));
            break;
        case Ity_V128:
            check_part(env, assignNew(env, IRExpr_Unop(Iop_V128to64, ebits)));
            check_part(env, assignNew(env, IRExpr_Unop(Iop_V128HIto64, ebits)));
            break;
        case Ity_V256:
            check_part(env, assignNew(env, IRExpr_Unop(Iop_V256to64_0, ebits)));
            check_part(env, assignNew(env, IRExpr_Unop(Iop_V256to64_1, ebits)));
            check_part(env, assignNew(env, IRExpr_Unop(Iop_V256to64_2, ebits)));
            check_part(env, assignNew(env, IRExpr_Unop(Iop_V256to64_3, ebits)));
            break;
        default:
            VG_(tool_panic)("check_ebits unsupported shadow type");
    }
}

static Ec_ShadowExpr default_shadow_for_type(Ec_Env* env, IRType expr_type)
{
   tl_assert(has_endianity(expr_type));
   return add_current_otag(env, mk_shadow_vector(env, type2ebit(expr_type), default_endianity(expr_type)));
}

/* Returns a default shadow value (usually EC_NATIVE) for the given
 * type of expression.
 */
static Ec_ShadowExpr default_shadow(Ec_Env* env, IRExpr* expr)
{
   IRType expr_type = typeOfIRExpr(env->tyenv, expr);
   return default_shadow_for_type(env, expr_type);
}

static Ec_ShadowExpr expr2shadow(Ec_Env* env, IRExpr* expr);

/*
 * Default handler for IR ops that just move around bytes. In that case we
 * simply apply the same operation to the ebit shadow data. An example of these
 * are narrowing conversions. The origin tags are passed-through for unary operation,
 * otherwise a new one is appended.
 */
static Ec_ShadowExpr same_for_shadow(Ec_Env* env, IRExpr* expr)
{
   Ec_ShadowExpr r;
   r.origin = NULL;
   switch (expr->tag) {
   case Iex_Unop: {
      Ec_ShadowExpr inner = expr2shadow(env, expr->Iex.Unop.arg);
      r.ebits = IRExpr_Unop(expr->Iex.Unop.op, inner.ebits);
      r.origin = inner.origin;
   }; break;
   case Iex_Binop:
      r.ebits = IRExpr_Binop(expr->Iex.Binop.op,
            expr2shadow(env, expr->Iex.Binop.arg1).ebits,
            expr2shadow(env, expr->Iex.Binop.arg2).ebits);
      if (EC_(opt_track_origins)) {
         r.origin = current_otag(env);
      }
   break;
   case Iex_Triop:
      r.ebits = IRExpr_Triop(expr->Iex.Triop.details->op,
            expr2shadow(env, expr->Iex.Triop.details->arg1).ebits,
            expr2shadow(env, expr->Iex.Triop.details->arg2).ebits,
            expr2shadow(env, expr->Iex.Triop.details->arg3).ebits);
      if (EC_(opt_track_origins)) {
         r.origin = current_otag(env);
      }
   break;
   default:
      VG_(tool_panic)("expr is not an op");
   }
   return r;
}

/* Prepare the shadow of inner expression and the result with the otag copied */
static void unop2shadow_inner_helper(
      Ec_Env* env, Ec_ShadowExpr* result, Ec_ShadowExpr* inner,
      IRExpr* expr)
{
   *inner = same_for_shadow(env, expr);
   inner->ebits = assignNew(env, inner->ebits);
   result->origin = inner->origin;
   result->ebits = NULL;
}

static Ec_ShadowExpr vector_get2shadow(Ec_Env* env, IRExpr* expr)
{
   /* first argument is the vector, second index */
   tl_assert(expr->tag == Iex_Binop);
   Ec_ShadowExpr vector_shadow = expr2shadow(env, expr->Iex.Binop.arg1);

   Ec_ShadowExpr r;
   r.ebits = IRExpr_Binop(expr->Iex.Binop.op, vector_shadow.ebits, expr->Iex.Binop.arg2);
   r.origin = vector_shadow.origin;
   return r;
}

static Ec_ShadowExpr unop2shadow(Ec_Env* env, IRExpr* expr)
{

   Ec_ShadowExpr r, inner;

   switch (expr->Iex.Unop.op) {
      // for widening, mark the new bytes as NATIVE_EMPTY
      case Iop_8Uto64:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_NATIVE_EMPTY) & 0xFFFFFFFFFFFFFF00)),
            inner.ebits);
         return r;

      case Iop_16Uto64:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_NATIVE_EMPTY) & 0xFFFFFFFFFFFF0000)),
            inner.ebits);
         return r;

      case Iop_32Uto64:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_NATIVE_EMPTY) & 0xFFFFFFFF00000000)),
            inner.ebits);
         return r;

      case Iop_8Uto32:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or32,
            IRExpr_Const(IRConst_U32(EC_(mk_byte_vector)(4, EC_NATIVE_EMPTY) & 0xFFFFFF00)),
            inner.ebits);
         return r;

      case Iop_16Uto32:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or32,
            IRExpr_Const(IRConst_U32(EC_(mk_byte_vector)(4, EC_NATIVE_EMPTY) & 0xFFFF0000)),
            inner.ebits);
         return r;

      case Iop_8Uto16:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or16,
            IRExpr_Const(IRConst_U16(EC_(mk_byte_vector)(2, EC_NATIVE_EMPTY) & 0xFF00)),
            inner.ebits);
         return r;

      /* narrowing is just a byte shuffle */
      case Iop_64to16:
      case Iop_64to32:
      case Iop_64to8:
      case Iop_32to16:
      case Iop_32to8:
      case Iop_16to8:
      case Iop_64HIto32:
      case Iop_32HIto16:
      case Iop_16HIto8:
      case Iop_V128to64:
      case Iop_V128HIto64:
         return same_for_shadow(env, expr);

      case Iop_Dup8x8:
      case Iop_Dup16x4:
      case Iop_Dup32x2:
      case Iop_Dup8x16:
      case Iop_Dup16x8:
      case Iop_Dup32x4:
      case Iop_ZeroHI64ofV128:
      case Iop_ZeroHI96ofV128:
      case Iop_ZeroHI112ofV128:
      case Iop_ZeroHI120ofV128:
      case Iop_Reverse8sIn16_x4:
      case Iop_Reverse8sIn32_x2:
      case Iop_Reverse16sIn32_x2:
      case Iop_Reverse8sIn64_x1:
      case Iop_Reverse16sIn64_x1:
      case Iop_Reverse32sIn64_x1:
      case Iop_Reverse8sIn16_x8:
      case Iop_Reverse8sIn32_x4:
      case Iop_Reverse16sIn32_x4:
      case Iop_Reverse8sIn64_x2:
      case Iop_Reverse16sIn64_x2:
      case Iop_Reverse32sIn64_x2:
      case Iop_Reverse1sIn8_x16:
         return same_for_shadow(env, expr);

      case Iop_GetElem8x8:
      case Iop_GetElem16x4:
      case Iop_GetElem32x2:
      case Iop_GetElem8x16:
      case Iop_GetElem16x8:
      case Iop_GetElem32x4:
      case Iop_GetElem64x2:
         return vector_get2shadow(env, expr);

      /* There are no shadow information for bits, we must create a new one */
      case Iop_1Uto8:
      case Iop_1Uto32:
      case Iop_1Uto64:
      default:
         return default_shadow(env, expr);
   }
   VG_(tool_panic)("Unhandled case unop2shadow");
}

static void split_empty_tags(Ec_Env* env, IRExpr* from, IRExpr** endianess, IRExpr** tags)
{
   IRType type = typeOfIRExpr(env->tyenv, from);
   *endianess = assignNew(env, IRExpr_Binop(EC_(op_for_type)(Iop_And8, type), mk_shadow_vector(env, type, ~EC_EMPTY_TAG), from));
   *tags = assignNew(env, IRExpr_Binop(EC_(op_for_type)(Iop_And8, type), mk_shadow_vector(env, type, EC_EMPTY_TAG), from));
}

typedef UChar shadow_vector __attribute__ ((vector_size (8)));
static VG_REGPARM(2) ULong helper_combine_or_shadow(ULong a_shadow, ULong b_shadow)
{
   /* hopefully the compiler will recognize these are constants */
   ULong tag_mask = EC_(mk_byte_vector)(8, EC_EMPTY_TAG);
   ULong native = EC_(mk_byte_vector)(8, EC_NATIVE);

   /* True if both cells are full */
   ULong nempty_intersection = (~a_shadow & ~b_shadow) & tag_mask;
   /* True if both cells are empty */
   ULong empty_union = (a_shadow & b_shadow) & tag_mask;
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

static Ec_ShadowExpr or2shadow(Ec_Env* env, IRExpr* expr)
{
   IRExpr* arg1 = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg1).ebits);
   IRExpr* arg2 = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg2).ebits);
   /* Call a helper for doing the OR */
   IRExpr* v = IRExpr_CCall(mkIRCallee(2, "combine_or_shadow", VG_(fnptr_to_fnentry)(helper_combine_or_shadow)),
      Ity_I64, mkIRExprVec_2(
             assignNew(env, widen_to_64(env, arg1)),
             assignNew(env, widen_to_64(env, arg2))));
   return add_current_otag(env, narrow_from_64(env, assignNew(env, v), typeOfIRExpr(env->tyenv, expr)));
}

static Ec_ShadowExpr bitop2shadow(Ec_Env* env, IRExpr* expr)
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
   IRExpr* arg1s = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg1).ebits);
   split_empty_tags(env, arg1s, &arg1se, &arg1st);
   IRExpr* arg2s = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg2).ebits);
   split_empty_tags(env, arg2s, &arg2se, &arg2st);
   IRExpr* are_equal = assignNew(env, IRExpr_Binop(EC_(op_for_type)(Iop_CmpEQ8, type), arg1st, arg2st));

   if (expr->Iex.Binop.op >= Iop_Xor8 && expr->Iex.Binop.op <= Iop_Xor64) {
      /* There is no sensible ebit combination rule for for XOR */
      return add_current_otag(env, IRExpr_ITE(are_equal, arg1s, default_shadow(env, expr).ebits));
   } else if (expr->Iex.Binop.op >= Iop_And8 && expr->Iex.Binop.op <= Iop_And64) {
      /* The empty tags are ORed together */
      IRExpr* result_tags = assignNew(env, IRExpr_Binop(EC_(op_for_type)(Iop_Or8, type), arg1st, arg2st));
      IRExpr* shadow = assignNew(env, IRExpr_ITE(are_equal, arg1s, default_shadow(env, expr).ebits));
      return add_current_otag(env, IRExpr_Binop(EC_(op_for_type)(Iop_Or8, type), shadow, result_tags));
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

static Ec_ShadowExpr shift2shadow(Ec_Env* env, IRExpr* expr)
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

   Ec_ShadowExpr value_shadow = expr2shadow(env, expr->Iex.Binop.arg1);
   Ec_ShadowExpr fallback_shadow = default_shadow(env, expr);

   /* merge the shifted shadow with the new bytes */
   IRExpr* shifted_shadow = assignNew(env,
      IRExpr_Binop(EC_(op_for_type)(Iop_Or8, type),
         new_bytes,
         assignNew(env, IRExpr_Binop(expr->Iex.Binop.op,
            value_shadow.ebits,
            expr->Iex.Binop.arg2))));

   Ec_ShadowExpr r;
   r.ebits = IRExpr_ITE(is_byte_sized, shifted_shadow, fallback_shadow.ebits);
   r.origin = NULL;
   if (EC_(opt_track_origins))
      r.origin = IRExpr_ITE(is_byte_sized, value_shadow.origin, fallback_shadow.origin);
   return r;
}

static Ec_ShadowExpr binop2shadow(Ec_Env* env, IRExpr* expr)
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

      /* 64 bit SIMD */
      case Iop_InterleaveHI8x8:
      case Iop_InterleaveHI16x4:
      case Iop_InterleaveHI32x2:
      case Iop_InterleaveLO8x8:
      case Iop_InterleaveLO16x4:
      case Iop_InterleaveLO32x2:
      case Iop_InterleaveOddLanes8x8:
      case Iop_InterleaveEvenLanes8x8:
      case Iop_InterleaveOddLanes16x4:
      case Iop_InterleaveEvenLanes16x4:
      case Iop_CatOddLanes8x8:
      case Iop_CatOddLanes16x4:
      case Iop_CatEvenLanes8x8:
      case Iop_CatEvenLanes16x4:
      /* 128-bit SIMD */
      case Iop_InterleaveHI8x16:
      case Iop_InterleaveHI16x8:
      case Iop_InterleaveHI32x4:
      case Iop_InterleaveHI64x2:
      case Iop_InterleaveLO8x16:
      case Iop_InterleaveLO16x8:
      case Iop_InterleaveLO32x4:
      case Iop_InterleaveLO64x2:
      case Iop_InterleaveOddLanes8x16:
      case Iop_InterleaveEvenLanes8x16:
      case Iop_InterleaveOddLanes16x8:
      case Iop_InterleaveEvenLanes16x8:
      case Iop_InterleaveOddLanes32x4:
      case Iop_InterleaveEvenLanes32x4:
      case Iop_PackOddLanes8x16:
      case Iop_PackEvenLanes8x16:
      case Iop_PackOddLanes16x8:
      case Iop_PackEvenLanes16x8:
      case Iop_PackOddLanes32x4:
      case Iop_PackEvenLanes32x4:
      case Iop_CatOddLanes8x16:
      case Iop_CatOddLanes16x8:
      case Iop_CatOddLanes32x4:
      case Iop_CatEvenLanes8x16:
      case Iop_CatEvenLanes16x8:
      case Iop_CatEvenLanes32x4:
         return same_for_shadow(env, expr);

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

static Ec_ShadowExpr triop2shadow(Ec_Env* env, IRExpr* expr)
{
   IRTriop* op = expr->Iex.Triop.details;
   switch (op->op) {
   default:
      return default_shadow(env, expr);
   }
}

static Ec_ShadowExpr qop2shadow(Ec_Env* env, IRExpr* expr)
{
   IRQop* op = expr->Iex.Qop.details;
   switch (op->op) {
   default:
      return default_shadow(env, expr);
   }
}

static ULong guess_constant(ULong value) {
   Bool still_zero = True;
   ULong acc = 0;
   for(int i = 7; i >= 0; i--) {
      acc = acc << 8;
      Bool was_zero = still_zero;
      ULong leading = (value >> i*8);
      if (leading != 0)
         still_zero = False;

      if (still_zero)
         acc |= EC_EMPTY_TAG;

      acc |= (was_zero && i == 0) ? EC_ANY : EC_NATIVE;
   }
   // VG_(message)(Vg_UserMsg, "guessed shadow %llx for constant %llx\n", acc, value);
   return acc;
}

static Ec_ShadowExpr const_guess2shadow(Ec_Env* env, IRExpr* expr)
{
   IRType type = typeOfIRExpr(env->tyenv, expr);
   Ec_ShadowExpr r;
   r.origin = NULL;
   switch(type) {
      case Ity_I8:
         r.ebits = IRExpr_Const(IRConst_U8(guess_constant(expr->Iex.Const.con->Ico.U8)));
      break;
      case Ity_I16:
         r.ebits = IRExpr_Const(IRConst_U16(guess_constant(expr->Iex.Const.con->Ico.U16)));
      break;
      case Ity_I32:
         r.ebits = IRExpr_Const(IRConst_U32(guess_constant(expr->Iex.Const.con->Ico.U32)));
      break;
      case Ity_I64:
         r.ebits = IRExpr_Const(IRConst_U64(guess_constant(expr->Iex.Const.con->Ico.U64)));
      break;
      default:
         return default_shadow(env, expr);
   }
   if (EC_(opt_track_origins)) {
      r.origin = current_otag(env);
   }
   return r;
}

static Ec_ShadowExpr ite2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(expr->tag == Iex_ITE);
   Ec_ShadowExpr true_case = expr2shadow(env, expr->Iex.ITE.iftrue);
   Ec_ShadowExpr false_case = expr2shadow(env, expr->Iex.ITE.iffalse);
   Ec_ShadowExpr r;
   r.ebits = IRExpr_ITE(expr->Iex.ITE.cond, true_case.ebits, false_case.ebits);
   r.origin = NULL;
   if (EC_(opt_track_origins)) {
      r.origin = IRExpr_ITE(expr->Iex.ITE.cond, true_case.origin, false_case.origin);
   }
   return r;
}

static Ec_ShadowExpr get2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(has_endianity(typeOfIRExpr(env->tyenv, expr)));
   Ec_ShadowExpr r;
   r.ebits = IRExpr_Get(state2ebits(env, expr->Iex.Get.offset), type2ebit(expr->Iex.Get.ty));
   r.origin = NULL;
   if (EC_(opt_track_origins)) {
      Int otagOffset = state2otag(env, expr->Iex.Get.offset, expr->Iex.Get.ty);
      if (otagOffset == -1 ) {
         r.origin = IRExpr_Const(IRConst_U32(EC_NO_OTAG));
      } else {
         r.origin = IRExpr_Get(otagOffset, Ity_I32);
      }
   }
   return r;
}

static Ec_ShadowExpr geti2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(has_endianity(typeOfIRExpr(env->tyenv, expr)));
   Ec_ShadowExpr r;
   r.origin = EC_NO_OTAG;
   IRRegArray* orig_array = expr->Iex.GetI.descr;
   IRExpr* ix = expr->Iex.GetI.ix;
   Int bias = expr->Iex.GetI.bias;
   IRType ebit_type = orig_array->elemTy;
   IRRegArray* ebit_array = mkIRRegArray(orig_array->base + env->shadow_ebit_temp_base, ebit_type, orig_array->nElems);
   r.ebits = IRExpr_GetI(ebit_array, ix, bias);
   if (EC_(opt_track_origins)) {
      /* See the storei for comments */
      IRType otag_type = VG_(get_otrack_reg_array_equiv_int_type)(orig_array);
      Int otag_base = VG_(get_otrack_shadow_offset)(orig_array->base, sizeofIRType(orig_array->elemTy));
      if (otag_base >= 0) {
         otag_base += env->shadow_otag_state_base;
         IRRegArray* otag_array = mkIRRegArray(otag_base, otag_type, orig_array->nElems);
         IRExpr* otag_expr = assignNew(env, IRExpr_GetI(otag_array, ix, bias));
         r.origin = assignNew(env, narrow_to_32(env, otag_expr));
      }
   }
   return r;
}

static Ec_ShadowExpr rdtmp2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(has_endianity(typeOfIRExpr(env->tyenv, expr)));
   Ec_ShadowExpr r;
   r.ebits = IRExpr_RdTmp(temp2ebits(env, expr->Iex.RdTmp.tmp));
   r.origin = NULL;
   if (EC_(opt_track_origins)) {
      r.origin = IRExpr_RdTmp(temp2otag(env, expr->Iex.RdTmp.tmp));
   }
   return r;
}

static Ec_ShadowExpr expr2shadow(Ec_Env* env, IRExpr* expr)
{
   // ppIRExpr(expr); VG_(printf)("\n");
   switch (expr->tag) {
      case Iex_Get:
         return get2shadow(env, expr);
      case Iex_GetI:
         return geti2shadow(env, expr);
      case Iex_Load:
         return EC_(gen_shadow_load)(env->out_sb, expr->Iex.Load.end, expr->Iex.Load.ty, expr->Iex.Load.addr);
      case Iex_RdTmp:
         return rdtmp2shadow(env, expr);
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
         if (EC_(opt_guess_const_size))
            return const_guess2shadow(env, expr);
         else
            return default_shadow(env, expr);
      default:
         return default_shadow(env, expr);
   }
}

static void shadow_wrtmp(Ec_Env *env, IRTemp to, IRExpr* from)
{
   if (has_endianity(typeOfIRTemp(env->tyenv, to))) {
      Ec_ShadowExpr e = expr2shadow(env, from);
      stmt(env, IRStmt_WrTmp(temp2ebits(env, to), e.ebits));
      if (EC_(opt_track_origins))
         stmt(env, IRStmt_WrTmp(temp2otag(env, to), e.origin));
   }
}

static void shadow_put(Ec_Env *env, Int to, IRExpr* from)
{
   IRType type = typeOfIRExpr(env->tyenv, from);
   if (has_endianity(type)) {
      Ec_ShadowExpr e = expr2shadow(env, from);
      stmt(env, IRStmt_Put(state2ebits(env, to), e.ebits));
      if (EC_(opt_track_origins)) {
         Int otag_offset = state2otag(env, to, type);
         if (otag_offset >= 0)
            stmt(env, IRStmt_Put(otag_offset, e.origin));
      }
   }
}

static void shadow_puti(Ec_Env *env, IRPutI* puti)
{
   IRRegArray* descr = puti->descr;
   if (has_endianity(puti->descr->elemTy)) {
      Ec_ShadowExpr shadow_value = expr2shadow(env, puti->data);

      IRType ebit_type = type2ebit(puti->descr->elemTy);
      IRRegArray* ebit_array = mkIRRegArray(descr->base + env->shadow_ebit_state_base, ebit_type, descr->nElems);
      stmt(env, IRStmt_PutI(mkIRPutI(ebit_array, puti->ix, puti->bias, shadow_value.ebits)));

      if (EC_(opt_track_origins)) {
         /* Normally, otag is 32bits, but for reg_array otag, it may be 64bit
          * (because the type dictates the stride)
          */
         IRType otag_type = VG_(get_otrack_reg_array_equiv_int_type)(puti->descr);
         Int otag_base = VG_(get_otrack_shadow_offset)(puti->descr->base, sizeofIRType(puti->descr->elemTy));
         if (otag_base >= 0) {
            otag_base += env->shadow_otag_state_base;
            IRExpr* widened_origin = widen_from_32(env, shadow_value.origin, otag_type);
            IRRegArray* otag_array = mkIRRegArray(otag_base, otag_type, descr->nElems);
            stmt(env, IRStmt_PutI(mkIRPutI(otag_array, puti->ix, puti->bias, widened_origin)));
         }
      }
   }
}

static void shadow_store(Ec_Env *env, IREndness endianess, IRExpr* addr, IRExpr* value, IRExpr* guard)
{
   IRType type = typeOfIRExpr(env->tyenv, value);
   Ec_ShadowExpr shadow;
   if (has_endianity(type)) {
      shadow = expr2shadow(env, value);
   } else {
      shadow.ebits = mk_shadow_vector(env, type, EC_NATIVE);
      shadow.origin = EC_NO_OTAG;
   }

   /* TODO: handle endianess swapping, this is not the correct way */
   EC_(gen_shadow_store_guarded)(env->out_sb, endianess, addr, shadow, guard);
}

static void shadow_load_guarded(Ec_Env *env, IRLoadG* load_op)
{
   Ec_ShadowExpr loaded;
   IRType type, arg;
   typeOfIRLoadGOp(load_op->cvt, &type, &arg);
   if (has_endianity(type)) {
      Ec_ShadowExpr alt = expr2shadow(env, load_op->alt);
      loaded = EC_(gen_shadow_load_guarded)(
            env->out_sb, load_op->end, type, load_op->addr, load_op->cvt, load_op->guard, alt);
   } else {
      loaded.ebits = mk_shadow_vector(env, type, EC_ANY);
      loaded.origin = EC_NO_OTAG;
   }
   stmt(env, IRStmt_WrTmp(temp2ebits(env, load_op->dst), loaded.ebits));
   if (EC_(opt_track_origins))
      stmt(env, IRStmt_WrTmp(temp2otag(env, load_op->dst), loaded.origin));
}

static void shadow_dirty(Ec_Env* env, IRDirty* dirty)
{
   if (dirty->tmp == IRTemp_INVALID)
      return;

   IRType type = typeOfIRTemp(env->tyenv, dirty->tmp);
   if (has_endianity(type)) {
      Ec_ShadowExpr shadow = default_shadow_for_type(env, type);
      stmt(env, IRStmt_WrTmp(temp2ebits(env, dirty->tmp), shadow.ebits));
      if (EC_(opt_track_origins))
         stmt(env, IRStmt_WrTmp(temp2otag(env, dirty->tmp), shadow.origin));
   }
}

static VG_REGPARM(2) void helper_set_default_shadow_mem(Addr base, SizeT size)
{
   /* TODO: optimalize this */
   if (EC_(opt_track_origins)) {
      ThreadId tid = VG_(get_running_tid)();
      ExeContext* here = VG_(record_ExeContext)(tid, 0);
      tl_assert(here);
      Ec_Otag otag = VG_(get_ECU_from_ExeContext)(here);
      tl_assert(VG_(is_plausible_ECU)(otag));

      for(size_t i = 0; i<size; i++) {
         EC_(set_shadow)(base + i, EC_NATIVE);
         EC_(set_shadow_otag)(base + i, otag);
      }
   } else {
      for(size_t i = 0; i<size; i++)
         EC_(set_shadow)(base + i, EC_NATIVE);
   }
}

static void shadow_cas(Ec_Env* env, IRCAS* details)
{
   /* It's doubtful that CAS will be used to handle data where endianity matters. For now,
    * just mark everything that the CAS touches as native.
    */
   IRType base_type = typeOfIRTemp(env->tyenv, details->oldLo);
   tl_assert(!!details->expdHi == !!details->dataHi);
   if (details->expdHi) {
      tl_assert(base_type == typeOfIRTemp(env->tyenv, details->oldHi));
   }

   if (!has_endianity(base_type))
      return;

   {
      Ec_ShadowExpr lo_shadow = default_shadow_for_type(env, base_type);
      stmt(env, IRStmt_WrTmp(temp2ebits(env, details->oldLo), lo_shadow.ebits));
      if (EC_(opt_track_origins))
         stmt(env, IRStmt_WrTmp(temp2otag(env, details->oldLo), lo_shadow.origin));
   }

   if (details->expdHi) {
      Ec_ShadowExpr hi_shadow = default_shadow_for_type(env, base_type);
      stmt(env, IRStmt_WrTmp(temp2ebits(env, details->oldHi), hi_shadow.ebits));
      if (EC_(opt_track_origins))
         stmt(env, IRStmt_WrTmp(temp2otag(env, details->oldHi), hi_shadow.origin));
   }
   SizeT mem_size = sizeofIRType(base_type);
   if (details->dataHi)
      mem_size *= 2;
   stmt(env, IRStmt_Dirty(unsafeIRDirty_0_N(
         2, "ec_set_default_shadow_mem", VG_(fnptr_to_fnentry)(helper_set_default_shadow_mem),
         mkIRExprVec_2(details->addr, EC_(const_sizet)(mem_size)))));
}

static void shadow_llsc(Ec_Env* env, IRTemp result, IREndness end, IRExpr* addr, IRExpr* storedata)
{
   /* Same as CAS -- just mark the data as native. */
   if (storedata) {
      tl_assert(!has_endianity(typeOfIRTemp(env->tyenv, result)));
      stmt(env, IRStmt_Dirty(unsafeIRDirty_0_N(
            2, "ec_set_default_shadow_mem", VG_(fnptr_to_fnentry)(helper_set_default_shadow_mem),
            mkIRExprVec_2(addr, EC_(const_sizet)(sizeofIRType(typeOfIRExpr(env->tyenv, storedata)))))));
   } else {
      IRType type = typeOfIRTemp(env->tyenv, result);
      if (!has_endianity(type))
         return;
      Ec_ShadowExpr shadow = default_shadow_for_type(env, type);
      stmt(env, IRStmt_WrTmp(temp2ebits(env, result), shadow.ebits));
      if (EC_(opt_track_origins))
         stmt(env, IRStmt_WrTmp(temp2otag(env, result), shadow.origin));
   }
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
   env.shadow_ebit_state_base = layout->total_sizeB;
   env.shadow_otag_state_base = layout->total_sizeB*2;
   env.tyenv = env.out_sb->tyenv;

   /* Unlike memcheck, we try to get off with having direct mapping between temporaries and their
    * shadow values. They are placed directly after the regular variables */
   int temp_count = sb->tyenv->types_used;
   env.shadow_ebit_temp_base = temp_count;
   env.shadow_otag_temp_base = temp_count*2;
   for(int i = 0; i<temp_count; i++) {
      IRType shadow_type = type2ebit(typeOfIRTemp(env.out_sb->tyenv, i));
      IRTemp temp_index = newIRTemp(env.out_sb->tyenv, shadow_type);
      tl_assert(temp_index == temp2ebits(&env, i));
   }
   if (EC_(opt_track_origins)) {
      for(int i = 0; i<temp_count; i++) {
         IRTemp temp_index = newIRTemp(env.out_sb->tyenv, Ity_I32);
         tl_assert(temp_index == temp2otag(&env, i));
      }
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

         case Ist_CAS:
            shadow_cas(&env, st->Ist.CAS.details);
            break;
         case Ist_LLSC:
            shadow_llsc(
                  &env, st->Ist.LLSC.result, st->Ist.LLSC.end,
                  st->Ist.LLSC.addr, st->Ist.LLSC.storedata);
         break;

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
void EC_(dump_mem_noheader)(Addr start, SizeT size)
{
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

      VG_(message)(Vg_UserMsg, "   %p: %s\n", (void*)(start + i), row);
   }
}

void EC_(dump_mem)(Addr start, SizeT size)
{
   VG_(message)(Vg_UserMsg, "Memory endianity dump (legend: Undefined, Native, Target, Any, - Empty):\n");
   EC_(dump_mem_noheader)(start, size);
   VG_(message)(Vg_UserMsg, "\n");
}

static void ecrq_dump_mem(UWord* arg)
{
   Addr start = arg[1];
   size_t size = arg[2];
   EC_(dump_mem)(start, size);
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
   const char* msg = (const char*) arg[3];

   return EC_(check_memory_endianity)(tid, start, size, msg);
}

static void ec_new_mem_stack(Addr a, SizeT len)
{
   for(SizeT i = 0; i<len; i++) {
      EC_(set_shadow)(a + i, EC_UNKNOWN);
   }
}

static void ec_new_mem_stack_w_ECU(Addr a, SizeT len, UInt otag)
{
   for(SizeT i = 0; i<len; i++) {
      EC_(set_shadow)(a + i, EC_UNKNOWN);
      EC_(set_shadow_otag)(a + i, otag);
   }
}

static int ecrq_protect_region(UWord* arg, Bool protected)
{
   if (!EC_(opt_protection))
      return 0;
   Addr addr = arg[1];
   Addr size = arg[2];
   EC_(set_protected)(addr, size, protected);
   return 0;
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
         case EC_USERREQ__PROTECT_REGION:
            *ret = ecrq_protect_region(arg, True);
         break;
         case EC_USERREQ__UNPROTECT_REGION:
            *ret = ecrq_protect_region(arg, False);
         break;
         default:
            VG_(message)(Vg_UserMsg, "Warning: unknown endicheck client request code %llx\n",(ULong)arg[0]);
         return False;
            return False;
      }
   }
   return False;
}

Bool EC_(opt_guess_const_size) = True;
Bool EC_(opt_track_origins) = False;
Bool EC_(opt_protection) = True;

static Bool ec_process_cmd_line_options(const char* arg)
{
   if VG_BOOL_CLO(arg, "--alow-unknown", EC_(opt_allow_unknown)) {}
   else if VG_BOOL_CLO(arg, "--guess-const-size", EC_(opt_guess_const_size)) {}
   else if VG_BOOL_CLO(arg, "--track-origins", EC_(opt_track_origins)) {}
   else if VG_BOOL_CLO(arg, "--protection", EC_(opt_protection)) {}
   else if VG_BOOL_CLO(arg, "--report-different-origins", EC_(opt_report_different_origins)) {}
   else return False;
   return True;
}

static void ec_print_usage(void) {
   VG_(printf)(
"    --allow-unknown=yes|no      report unknown endianess as error?\n"
"    --guest-const-size=yes|no   guess constant size from its contents\n"
"    --track-origins=yes|no      track origins for data\n"
"    --protection=yes|no         allow certain memory regions to check for endianity on stores\n"
"    --report-different-origins=yes|no report endianity errors as separate if origins are different\n"
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
   if (EC_(opt_track_origins))
      VG_(track_new_mem_stack_w_ECU)(ec_new_mem_stack_w_ECU);
   else
      VG_(track_new_mem_stack)(ec_new_mem_stack);
      
   VG_(needs_command_line_options)(
            ec_process_cmd_line_options,
            ec_print_usage,
            ec_print_debug_usage);
   VG_(needs_client_requests)(
            EC_(client_request));
   VG_(needs_xml_output)();

   EC_(shadow_init)();
}

VG_DETERMINE_INTERFACE_VERSION(EC_(pre_clo_init))

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
