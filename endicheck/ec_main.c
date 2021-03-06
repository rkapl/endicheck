
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
#include "ec_main.h"
#include "ec_shadow.h"
#include "ec_errors.h"
#include "ec_util.h"
#include <stddef.h>

/* Heap allocation tag for Valgrind core malloc */
#define EC_INSTRUMENT_HEAPID "ec_instrument"

/* Common data needed by instrumentation routines */
typedef struct {
      /* Where to output VexIR */
      IRSB* out_sb;
      /* Typing of variables (out_sb->tyenv can be used instead)*/
      IRTypeEnv* tyenv;
      /* Guest native word size */
      IRType word_type;
      /* Current value of otag, lazily initialized */
      IRExpr *lazy_otag;

      /* Note: Do not use the following directly, there are helpers to get
       * shadow variables and state (and it wouldn't work for
       * shadow_otag_state_base anyway) */

      /* Offset to get an ebit shadow variable for a regular one */
      IRTemp shadow_ebit_temp_base;
      /* Offset to get an OTag shadow variable for a regular one */
      IRTemp shadow_otag_temp_base;

      /* Offset to get a ebit guest state area for regular one */
      IRTemp shadow_ebit_state_base;
      /* Offset to get a ebit guest state area for regular one */
      IRTemp shadow_otag_state_base;
} Ec_Env;

/* shortcut to output new statement */
static void stmt(Ec_Env* env, IRStmt* stmt) {
   addStmtToIRSB(env->out_sb, stmt);
}

/* Check if it makes sense to track endianity for a given VexIR type */
static Bool has_endianity(IRType ty)
{
   switch(ty) {
      case Ity_I1:   /* We don't really care */
         return False;
      /* yes, it can have endianess attached, although by default it is ANY */
      case Ity_I8: 
      case Ity_I16:
      case Ity_I32:
      case Ity_I64:
      case Ity_I128:
      case Ity_V128:
      case Ity_V256:

      /* Some archs (like PPC) use the FP registers to move around data */
      case Ity_F128:
      case Ity_F64:
      case Ity_F32:
      case Ity_F16:
      case Ity_D64:
      case Ity_D128:
      case Ity_D32:
         return True;

      default:
         VG_(tool_panic)("endicheck unsupported IRType");
   }
}

/* Get the default endianity for a given type */
static Ec_Shadow default_endianity(IRType ty)
{
   tl_assert(has_endianity(ty));
   return (ty == Ity_I8) ? EC_ANY : EC_NATIVE;
}

/* Extract endianity from ebits (strips out other ebits) */
Ec_Endianity EC_(endianity_for_shadow)(Ec_Shadow shadow) {
   return shadow & 0x3;
}

/* Checks if the ebits have the `empty` flag set */
Bool EC_(is_empty_for_shadow) (Ec_Shadow shadow) {
   return shadow & EC_EMPTY_TAG;
}

/* Get a type for ebits of a given type.
 *
 * For example F32 gets I32 to store all four bytes of ebits.
 * */
static IRType type2ebit(IRType ty)
{
   switch(ty) {
      case Ity_I1:
          return Ity_I1;
      case Ity_F128:
          return Ity_I128;
      case Ity_F64:
          return Ity_I64;
      case Ity_F32:
          return Ity_I32;
      case Ity_F16:
          return Ity_I16;
      case Ity_D64:
          return Ity_I64;
      case Ity_D128:
          return Ity_I128;
      case Ity_D32:
         return Ity_I32;

      case Ity_I8:
      case Ity_I16:
      case Ity_I32:
      case Ity_I64:
      case Ity_I128:
      case Ity_V128:
      case Ity_V256:
         /* We could try to make these types smaller (we don't need 8 bits, just
          * four per byte), but for simplicity we don't pack them */
         return ty;

      default:
         VG_(tool_panic)("endicheck unsupported IRType");
   }
}

/* VexIR helper to obtain the current execution context (OTag) */
static VG_REGPARM(0) ULong helper_gen_exectx(void)
{
   ThreadId tid = VG_(get_running_tid)();
   ExeContext* here = VG_(record_ExeContext)(tid, 0);
   tl_assert(here);
   Ec_Otag otag = VG_(get_ECU_from_ExeContext)(here);
   tl_assert(VG_(is_plausible_ECU)(otag));
   return otag;
}

/* Generates the VexIR to obtain the current OTag (using helper_gen_exectx) */
static IRExpr* current_otag(Ec_Env *env)
{
   tl_assert(EC_(opt_track_origins));
   if (!env->lazy_otag) {
      IRTemp otag = newIRTemp(env->tyenv, Ity_I32);
      IRCallee* call = mkIRCallee(0, "ec_gen_exectx", VG_(fnptr_to_fnentry)(helper_gen_exectx));
      stmt(env, IRStmt_WrTmp(otag, IRExpr_CCall(call, Ity_I32, mkIRExprVec_0())));
      env->lazy_otag = IRExpr_RdTmp(otag);
   }
   return env->lazy_otag;
}

/* Combine the ebits with current OTag to generate full shadow for a variable */
static Ec_ShadowExpr add_current_otag(Ec_Env *env, IRExpr *ebits)
{
   Ec_ShadowExpr r;
   r.ebits = ebits;
   r.origin = NULL;
   if (EC_(opt_track_origins))
      r.origin = current_otag(env);
   return r;
}

/* Get a shadow ebit temp variable corresponding to an original temp. */
static IRTemp temp2ebits(Ec_Env* env, IRTemp temp)
{
   return temp + env->shadow_ebit_temp_base;
}

/* Get a otag temp variable corresponding to an original temp. */
static IRTemp temp2otag(Ec_Env* env, IRTemp temp)
{
   tl_assert(EC_(opt_track_origins));
   return temp + env->shadow_otag_temp_base;
}

/* Get a shadow state ebit offset corresonding to a given state offset */
static Int state2ebits(Ec_Env* env, Int offset)
{
   return offset + env->shadow_ebit_state_base;
}

/*  Get a shadow state origin trackings offset corresonding to a given state offset.
 *  A simple wrapper around VG_(get_otrack_shadow_offset).
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
 *
 * In future, we might replace this by compilation pass.
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

/* See mk_shadow_vector below */
static IRExpr* mk_shadow_i128(Ec_Env* env, Ec_Shadow endianity)
{
   IRExpr* part0 = IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_ANY, endianity)));
   IRExpr* part1 = IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, endianity, endianity)));
   return assignNew(env, IRExpr_Binop(Iop_64HLto128, part0, part1));
}

/* See mk_shadow_vector below */
static IRExpr* mk_shadow_v128(Ec_Env* env, Ec_Shadow endianity)
{
   IRExpr* part0 = IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_ANY, endianity)));
   IRExpr* part1 = IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, endianity, endianity)));
   return assignNew(env, IRExpr_Binop(Iop_64HLtoV128, part0, part1));
}

/* See mk_shadow_vector below */
static IRExpr* mk_shadow_v256(Ec_Env* env, Ec_Shadow endianity)
{
   IRExpr* part = assignNew(env, mk_shadow_v128(env, endianity));
   return assignNew(env, IRExpr_Binop(Iop_V128HLtoV256, part, part));
}

/* Construct shadow ebits values containing the given endianity for all bytes, except
 * the first one, which is marked EC_ANY. Generic for any values. */
static IRExpr* mk_shadow_vector(Ec_Env* env,IRType ty, Ec_Shadow endianity)
{
   switch(ty) {
      case Ity_I8:
         return IRExpr_Const(IRConst_U8(EC_(mk_byte_vector)(1, EC_ANY, endianity)));
      case Ity_I16:
         return IRExpr_Const(IRConst_U16(EC_(mk_byte_vector)(2, EC_ANY, endianity)));
      case Ity_I32:
      case Ity_F32:
         return IRExpr_Const(IRConst_U32(EC_(mk_byte_vector)(4, EC_ANY, endianity)));
      case Ity_F64:
      case Ity_D64:
      case Ity_I64:
         return IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_ANY, endianity)));
      case Ity_F128:
      case Ity_D128:
      case Ity_I128:
         return mk_shadow_i128(env, endianity);
      case Ity_V128:
         return mk_shadow_v128(env, endianity);
      case Ity_V256:
         return mk_shadow_v256(env, endianity);
      default:
         ppIRType(ty);
         VG_(tool_panic)("unhandled IrType");
   }
}

/* Widen a VexIR expression to 64-bit (can be used for 64-bit) */
static IRExpr* widen_to_64(Ec_Env* env, IRExpr* from)
{
   return assignNew(env, EC_(change_width)(env->tyenv, from, Ity_I64));
}

/* Widen a VexIR expression from 32-bit to a given type (32-bit or 64-bit) */
static IRExpr* widen_from_32(Ec_Env* env, IRExpr* from, IRType dst)
{
   IRType type = typeOfIRExpr(env->tyenv, from);
   tl_assert(type == Ity_I32);
   return assignNew(env, EC_(change_width)(env->tyenv, from, dst));
}

/* Narrow a VexIR expresion to 32-bit */
static IRExpr* narrow_to_32(Ec_Env* env, IRExpr* from) {
   return assignNew(env, EC_(change_width)(env->tyenv, from, Ity_I32));
}

/* Narrow/widen a VexIR expression to a given type (can be the same) */
static IRExpr* change_width(Ec_Env* env, IRExpr* value, IRType to)
{
    return assignNew(env, EC_(change_width)(env->tyenv, value, to));
}

/* Helper: Perform a sanity check (assert) on ebits */
static void helper_check_ebits(ULong ebits)
{
    if (ebits & ~EC_(mk_byte_vector)(8, 0x7, 0x7)) {
        VG_(message)(Vg_UserMsg, "Invalid ebits 0x%llx\n", ebits);
        VG_(tool_panic)("helper_check_ebits failure");
    }
}

/* Perform a sanity check (assert) on ebits, works only for =< native size.
 * Use the function below instead. */
static void check_part(Ec_Env* env, IRExpr* ebits)
{
    stmt(env, IRStmt_Dirty(unsafeIRDirty_0_N(
                0, "ec_check_ebits", VG_(fnptr_to_fnentry)(helper_check_ebits),
                mkIRExprVec_1(ebits))));
}

/* Will place an assertion on the ebits -- it will check if any invalid bits are set.
 *
 * Not used by default (too slow), but it can be placed at strategic points if a
 * developer runs into problems, like garbage in shadow memory.
 */
static void __attribute__ ((unused)) check_ebits(Ec_Env* env, IRExpr* ebits) {
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

/* Provide the default shadow expression for a given type.
 *
 * The default shadow is EC_ANY ebits for the first byte, EC_NATIVE for the
 * remaining and no EC_EMPTY flags. OTag will be the current otag. */
static Ec_ShadowExpr default_shadow_for_type(Ec_Env* env, IRType expr_type)
{
   tl_assert(has_endianity(expr_type));
   return add_current_otag(env, mk_shadow_vector(env, type2ebit(expr_type), default_endianity(expr_type)));
}

/* Provide the default shadow expression for a given type. Shortcut for
 * default_shadow_for_type. */
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
   case Iex_Qop:
      r.ebits = IRExpr_Qop(expr->Iex.Qop.details->op,
            expr2shadow(env, expr->Iex.Qop.details->arg1).ebits,
            expr2shadow(env, expr->Iex.Qop.details->arg2).ebits,
            expr2shadow(env, expr->Iex.Qop.details->arg3).ebits,
            expr2shadow(env, expr->Iex.Qop.details->arg4).ebits);
      if (EC_(opt_track_origins)) {
         r.origin = current_otag(env);
      }
   break;
   default:
      VG_(tool_panic)("expr is not an op");
   }
   return r;
}

/* Handler for Iop_GetElem<>x<>. We extract the ebits and copy origin. */
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

/* Prepare the shadow of and unary operation and the result with the otag copied.
 * Used by unop2shadow. */
static void unop2shadow_inner_helper(
      Ec_Env* env, Ec_ShadowExpr* result, Ec_ShadowExpr* inner,
      IRExpr* expr)
{
   *inner = same_for_shadow(env, expr);
   inner->ebits = assignNew(env, inner->ebits);
   result->origin = inner->origin;
   result->ebits = NULL;
}

/* Handler for all unary expressions */
static Ec_ShadowExpr unop2shadow(Ec_Env* env, IRExpr* expr)
{

   Ec_ShadowExpr r, inner;
   IRExpr* tmp_const = NULL;

   switch (expr->Iex.Unop.op) {
      /* for widening, mark the new bytes as NATIVE_EMPTY */
      case Iop_8Uto64:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_NATIVE_EMPTY, EC_NATIVE_EMPTY) & 0xFFFFFFFFFFFFFF00)),
            inner.ebits);
         return r;

      case Iop_16Uto64:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_NATIVE_EMPTY, EC_NATIVE_EMPTY) & 0xFFFFFFFFFFFF0000)),
            inner.ebits);
         return r;

      case Iop_32Uto64:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_NATIVE_EMPTY, EC_NATIVE_EMPTY) & 0xFFFFFFFF00000000)),
            inner.ebits);
         return r;

      case Iop_8Uto32:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or32,
            IRExpr_Const(IRConst_U32(EC_(mk_byte_vector)(4, EC_NATIVE_EMPTY, EC_NATIVE_EMPTY) & 0xFFFFFF00)),
            inner.ebits);
         return r;

      case Iop_16Uto32:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or32,
            IRExpr_Const(IRConst_U32(EC_(mk_byte_vector)(4, EC_NATIVE_EMPTY, EC_NATIVE_EMPTY) & 0xFFFF0000)),
            inner.ebits);
         return r;

      case Iop_8Uto16:
         unop2shadow_inner_helper(env, &r, &inner, expr);
         r.ebits = IRExpr_Binop(Iop_Or16,
            IRExpr_Const(IRConst_U16(EC_(mk_byte_vector)(2, EC_NATIVE_EMPTY, EC_NATIVE_EMPTY) & 0xFF00)),
            inner.ebits);
         return r;

      case Iop_32UtoV128:
         r = expr2shadow(env, expr->Iex.Unop.arg);
         tmp_const = IRExpr_Const(IRConst_U32(EC_(mk_byte_vector)(4, EC_NATIVE, EC_NATIVE)));
         r.ebits = IRExpr_Binop(Iop_64HLtoV128,
            assignNew(env, IRExpr_Binop(Iop_32HLto64, tmp_const, tmp_const)),
            assignNew(env, IRExpr_Binop(Iop_32HLto64, tmp_const, r.ebits))
         );
         return r;
      case Iop_64UtoV128:
         r = expr2shadow(env, expr->Iex.Unop.arg);
         r.ebits = IRExpr_Binop(Iop_64HLtoV128,
            IRExpr_Const(IRConst_U64(EC_(mk_byte_vector)(8, EC_NATIVE, EC_NATIVE))),
            r.ebits
         );
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
      case Iop_V128to32:
      case Iop_V256to64_0:
      case Iop_V256to64_1:
      case Iop_V256to64_2:
      case Iop_V256to64_3:
      case Iop_V256toV128_0:
      case Iop_V256toV128_1:
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

/* Separate empty tags from endianess tags. Output expressions are stored in
 * endianess and tags. From is the shadow ebit expression to separate. */
static void split_empty_tags(Ec_Env* env, IRExpr* from, IRExpr** endianess, IRExpr** tags)
{
   IRType type = typeOfIRExpr(env->tyenv, from);
   *endianess = assignNew(env, IRExpr_Binop(EC_(op_for_type)(Iop_And8, type), mk_shadow_vector(env, type, ~EC_EMPTY_TAG), from));
   *tags = assignNew(env, IRExpr_Binop(EC_(op_for_type)(Iop_And8, type), mk_shadow_vector(env, type, EC_EMPTY_TAG), from));
}

typedef UChar shadow_vector __attribute__ ((vector_size (sizeof(Ec_LargeInt))));

/* Helper to handle bitwise OR. OR is the most complicated bitwise operation,
 * due to the disjointness analysis, so we use helper for that. We use some
 * serious vector magic too. */
static VG_REGPARM(2) Ec_LargeInt helper_combine_or_shadow(Ec_LargeInt a_shadow, Ec_LargeInt b_shadow)
{
   /* hopefully the compiler will recognize these are constants */
   Ec_LargeInt tag_mask = EC_(mk_byte_vector)(sizeof(Ec_LargeInt),EC_EMPTY_TAG, EC_EMPTY_TAG);
   Ec_LargeInt native = EC_(mk_byte_vector)(sizeof(Ec_LargeInt), EC_ANY, EC_NATIVE);

   /* True if both cells are full */
   Ec_LargeInt nempty_intersection = (~a_shadow & ~b_shadow) & tag_mask;
   /* True if both cells are empty */
   Ec_LargeInt empty_union = (a_shadow & b_shadow) & tag_mask;
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

      shadow_vector va_filtered_shadow = (va_tags == (shadow_vector)(Ec_LargeInt) 0) & ((shadow_vector)a_shadow);
      shadow_vector vb_filtered_shadow = (vb_tags == (shadow_vector)(Ec_LargeInt) 0) & ((shadow_vector)b_shadow);
      shadow_vector empty_shadow = (((shadow_vector) empty_union) != (shadow_vector)(Ec_LargeInt) 0) & ((shadow_vector) native);

      Ec_LargeInt shadow = ((Ec_LargeInt)va_filtered_shadow) | ((Ec_LargeInt)vb_filtered_shadow) | ((Ec_LargeInt)empty_shadow);
      return (shadow & ~tag_mask) | empty_union;
   }
}

/* Handler for OR expressions. Uses a helper */
static Ec_ShadowExpr or2shadow(Ec_Env* env, IRExpr* expr)
{
   IRExpr* arg1 = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg1).ebits);
   IRExpr* arg2 = assignNew(env, expr2shadow(env, expr->Iex.Binop.arg2).ebits);
   /* Call a helper for doing the OR */
   IRExpr* v = IRExpr_CCall(mkIRCallee(2, "combine_or_shadow", VG_(fnptr_to_fnentry)(helper_combine_or_shadow)),
      EC_LARGEINT, mkIRExprVec_2(
             change_width(env, arg1, EC_LARGEINT),
             change_width(env, arg2, EC_LARGEINT)));
   return add_current_otag(env, change_width(env, assignNew(env, v), typeOfIRExpr(env->tyenv, expr)));
}

/* Cross-platform helper for doing cmpeq, which is a bit rough on PPC */
static IRExpr* cmpeq(Ec_Env* env, IRExpr* a, IRExpr* b)
{
    /* PPC does not support comparisons on integers other than 32 bits, so
     * workaround that */
#  if defined(VGA_ppc32)
    a = assignNew(env, change_width(env, a, Ity_I32));
    b = assignNew(env, change_width(env, b, Ity_I32));
    return assignNew(env, IRExpr_Binop(Iop_CmpEQ32, a, b));
#  else
    IRType type = typeOfIRExpr(env->tyenv, a);
    return assignNew(env, IRExpr_Binop(EC_(op_for_type)(Iop_CmpEQ8, type), a, b));
#   endif
}

/* Handler for bitwise binary operations */
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
   IRExpr* are_equal = cmpeq(env, arg1st, arg2st);

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

/* Get a shift operation code in opposite direction, but with the same operation
 * width. */
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

/* Handler for shift operations. Shifts by multiples of eight are handled
 * specially.*/
static Ec_ShadowExpr shift2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(expr->tag == Iex_Binop);
   IRType type = typeOfIRExpr(env->tyenv, expr);
   int value_size = sizeofIRType(type) * 8;
   /* Shift size can no be be multiple of eight, unless zero, but that
    * hopefully does not happen. */
   if (value_size == 8)
      return default_shadow(env, expr);

   /* Decide if the shift is multiple of eight */
   /* Note: arg1 is the value, arg2 is the shift amount (8bit) */
   IRExpr* mod_8 = assignNew(env, IRExpr_Binop(
            Iop_And8, expr->Iex.Binop.arg2, IRExpr_Const(IRConst_U8(7))));
   IRExpr* is_byte_sized = cmpeq(env, mod_8, IRExpr_Const(IRConst_U8(0)));

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

   /* Use the correct algorithm based on shift size */
   Ec_ShadowExpr r;
   r.ebits = IRExpr_ITE(is_byte_sized, shifted_shadow, fallback_shadow.ebits);
   r.origin = NULL;
   if (EC_(opt_track_origins))
      r.origin = IRExpr_ITE(is_byte_sized, value_shadow.origin, fallback_shadow.origin);
   return r;
}

/* Generic handler for binary operations */
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
      /* Concatenations */
      case Iop_8HLto16:
      case Iop_16HLto32:
      case Iop_32HLto64:
      case Iop_64HLto128:
      case Iop_64HLtoV128:
      case Iop_V128HLtoV256:
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

/* Generic handler for ternary operations */
static Ec_ShadowExpr triop2shadow(Ec_Env* env, IRExpr* expr)
{
   IRTriop* op = expr->Iex.Triop.details;
   switch (op->op) {
   default:
      return default_shadow(env, expr);
   }
}

/* Generic handler for quad operations */
static Ec_ShadowExpr qop2shadow(Ec_Env* env, IRExpr* expr)
{
   IRQop* op = expr->Iex.Qop.details;
   switch (op->op) {
   case Iop_64x4toV256:
      return same_for_shadow(env, expr);
   default:
      return default_shadow(env, expr);
   }
}

/* Guess ebits for a constant value. This include EC_ANY or EC_NATIVE and the empty
 * tags. They are set according to the constant value */
/* TODO: also have EC_ANY always for the first byte ? */
static Ec_LargeInt guess_constant(Ec_LargeInt value) {
   Bool still_zero = True;
   Ec_LargeInt acc = 0;
   if (value == 0) {
      return EC_(mk_byte_vector)(sizeof(Ec_LargeInt), EC_ANY|EC_EMPTY_TAG, EC_ANY|EC_EMPTY_TAG);
   }
   for(int i = sizeof(Ec_LargeInt) - 1; i >= 0; i--) {
      acc = acc << 8;
      Ec_LargeInt leading = (value >> i*8);
      if (leading != 0)
         still_zero = False;

      if (still_zero)
         acc |= EC_EMPTY_TAG;

      acc |= (i == 0) ? EC_ANY : EC_NATIVE;
   }
   // VG_(message)(Vg_UserMsg, "guessed shadow %llx for constant %llx\n", acc, value);
   return acc;
}

/* Constant expression handler. Constant shadows are computed (guessed) from the
 * actual constant value */
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

/* ITE (ternary expression) handler. Simple pass-through. */
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

/* GET(register load) handler. Reads from shadow guest area. */
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

/* GETi(indexed register load) handler. Reads from shadow guest area. */
static Ec_ShadowExpr geti2shadow(Ec_Env* env, IRExpr* expr)
{
   tl_assert(has_endianity(typeOfIRExpr(env->tyenv, expr)));
   Ec_ShadowExpr r;
   r.origin = EC_NO_OTAG;
   IRRegArray* orig_array = expr->Iex.GetI.descr;
   IRExpr* ix = expr->Iex.GetI.ix;
   Int bias = expr->Iex.GetI.bias;
   IRType ebit_type = type2ebit(orig_array->elemTy);
   IRRegArray* ebit_array = mkIRRegArray(orig_array->base + env->shadow_ebit_temp_base, ebit_type, orig_array->nElems);
   r.ebits = IRExpr_GetI(ebit_array, ix, bias);
   if (EC_(opt_track_origins)) {
      /* See the shadow_puti for comments */
      /* Note that get_otrack_shadow_offset is not used in geti/puti case */
      IRType otag_type = VG_(get_otrack_reg_array_equiv_int_type)(orig_array);
      Int otag_base = orig_array->base + env->shadow_otag_state_base;
      if (otag_type != Ity_INVALID) {
          IRRegArray* otag_array = mkIRRegArray(otag_base, otag_type, orig_array->nElems);
          IRExpr* otag_expr = assignNew(env, IRExpr_GetI(otag_array, ix, bias));
          r.origin = assignNew(env, narrow_to_32(env, otag_expr));
      } else {
          r.origin = current_otag(env);
      }
   }
   return r;
}

/* RDTMP(read timestamp) handler. Has default endianity tags. */
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

/* Root-level expression handler. Generates the expressions computing the shadow
 * expression (ebits and OTags) shadowing the given expression. Relies on other
 * `x2shadow` functiosn. */
static Ec_ShadowExpr expr2shadow(Ec_Env* env, IRExpr* expr)
{
   // ppIRExpr(expr); VG_(printf)("\n");
   switch (expr->tag) {
      case Iex_Get:
         return get2shadow(env, expr);
      case Iex_GetI:
         return geti2shadow(env, expr);
      case Iex_Load:
         return EC_(gen_shadow_load)(
             env->out_sb, expr->Iex.Load.end, type2ebit(expr->Iex.Load.ty), expr->Iex.Load.addr);
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
         if (EC_(opt_guess_const_size) || EC_(opt_ignore_zeroes))
            return const_guess2shadow(env, expr);
         else
            return default_shadow(env, expr);
      default:
         return default_shadow(env, expr);
   }
}

/* Handler for the wrtmp statement. Computes the shadow expression and writes it
 * to the shadow variables. */
static void shadow_wrtmp(Ec_Env *env, IRTemp to, IRExpr* from)
{
   if (has_endianity(typeOfIRTemp(env->tyenv, to))) {
      Ec_ShadowExpr e = expr2shadow(env, from);
      stmt(env, IRStmt_WrTmp(temp2ebits(env, to), e.ebits));
      if (EC_(opt_track_origins))
         stmt(env, IRStmt_WrTmp(temp2otag(env, to), e.origin));
   }
}

/* Handler for the PUT(store register) statement. Computes the shadow
 * expression and writes it to guest shadow area. */
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

/* Handler for the PUTi(store register, indexed) statement. Computes the shadow
 * expression and writes it to guest shadow area. */
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
          * (because the type is used to dictate the stride, and sometimes
          * Valgrind wants us to use 8 byte stride)
          */
         /* Note that get_otrack_shadow_offset is not used in geti/puti case */
         IRType otag_type = VG_(get_otrack_reg_array_equiv_int_type)(puti->descr);
         Int otag_base = puti->descr->base + env->shadow_otag_state_base;
         if (otag_type != Ity_INVALID) {
            IRExpr* widened_origin = widen_from_32(env, shadow_value.origin, otag_type);
            IRRegArray* otag_array = mkIRRegArray(otag_base, otag_type, descr->nElems);
            stmt(env, IRStmt_PutI(mkIRPutI(otag_array, puti->ix, puti->bias, widened_origin)));
         }
      }
   }
}

/* Handler for memory store statement. Computes the shadow expressions and calls
 * out to ec_shadow to store them */
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

/* See above, but guarded */
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

/* Dirty calls handler, we mark their results as native */
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

/* Helper: set a given memory area as EC_NATIVE. */
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

/* CAS (compare and store) statement handler.
 *
 * It's doubtful that CAS will be used to handle data where endianity matters.
 * For now, just mark everything that the CAS touches as native. It is
 * complicated enough as-is.
 */
static void shadow_cas(Ec_Env* env, IRCAS* details)
{
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

/* LLSC (linked load and store conditional) statement handler. */
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

/* The most important entry point. Instruments the basic blocks of VexIR */
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

   /* Prepare the common variables used by the instrumentation */
   env.out_sb = deepCopyIRSBExceptStmts(sb);
   env.word_type = gWordTy;
   env.shadow_ebit_state_base = layout->total_sizeB;
   env.shadow_otag_state_base = layout->total_sizeB*2;
   env.tyenv = env.out_sb->tyenv;
   env.lazy_otag = NULL;

   /* Unlike memcheck, we try to get off with having direct mapping between temporaries and their
    * shadow values. They are placed directly after the regular variables, so
    * that we can compute their location by adding an offset. */
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

   /* Handle all statements one by one. :*/
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

         case Ist_Dirty:
            shadow_dirty(&env, st->Ist.Dirty.details);
         break;

         case Ist_LoadG:
            shadow_load_guarded(&env, st->Ist.LoadG.details);
         break;
         case Ist_StoreG:
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
         case Ist_NoOp:
         case Ist_MBE:
         break;
         case Ist_IMark:
            if (EC_(opt_precise_origins))
               env.lazy_otag = NULL;
         break;

         default:
            ppIRStmt(st);
            VG_(printf)("\n");
            VG_(tool_panic)("endicheck: unhandled IRStmt");
      }
      /* After doing the shadow operation, perform the original operation */
      stmt(&env, st);
   }

   return env.out_sb;
}

/* Valgrind callback, not needed */
static void EC_(post_clo_init)(void)
{
}

/* Valgrind callback, not needed */
static void EC_(fini)(Int exitcode)
{
}

/* Number for bytes per row of shadow memory dump */
#define ECRQ_DUMP_ROW_SIZE 40

/* Dump shadow memory (ebits) */
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

/* Dump shadow memory and include explanatory header with legend */
void EC_(dump_mem)(Addr start, SizeT size)
{
   VG_(message)(Vg_UserMsg, "Memory endianity dump (legend: Undefined, Native, Target, Any, - Empty):\n");
   EC_(dump_mem_noheader)(start, size);
   VG_(message)(Vg_UserMsg, "\n");
}

/* Valgrind user-request handler for EC_DUMP_MEM */
static void ecrq_dump_mem(UWord* arg)
{
   Addr start = arg[1];
   size_t size = arg[2];
   EC_(dump_mem)(start, size);
}

/* Valgrind user-request handler for EC_MARK_ENDIANITY */
static void ecrq_mark_endian(UWord* arg)
{
   Addr start = arg[1];
   SizeT size = arg[2];
   Ec_Shadow endianity = arg[3];
   for(SizeT i = 0; i<size; i++) {
      EC_(set_shadow)(start + i, endianity);
   }
}

/* Valgrind user-request handler for EC_CHECK_ENDIANITY */
static int ecrq_assert_endian(ThreadId tid, UWord* arg)
{
   Addr start = arg[1];
   SizeT size = arg[2];
   const char* msg = (const char*) arg[3];

   return EC_(check_memory_endianity)(tid, start, size, msg);
}

/* Valgrind callback for stack growth. We mark all new memory as EC_UNKNOWN. */
static void ec_new_mem_stack(Addr a, SizeT len)
{
   for(SizeT i = 0; i<len; i++) {
      EC_(set_shadow)(a + i, EC_UNKNOWN);
   }
}

/* Valgrind callback for stack growth, origin tracking variant. We mark all new
 * memory as EC_UNKNOWN and add current otag. */
static void ec_new_mem_stack_w_ECU(Addr a, SizeT len, UInt otag)
{
   for(SizeT i = 0; i<len; i++) {
      EC_(set_shadow)(a + i, EC_UNKNOWN);
      EC_(set_shadow_otag)(a + i, otag);
   }
}


/* Valgrind user-request handler for EC_PROTECT_REGION and EC_UNPROTECT_REGION. */
static int ecrq_protect_region(UWord* arg, Bool protected)
{
   if (!EC_(opt_protection))
      return 0;
   Addr addr = arg[1];
   Addr size = arg[2];
   EC_(set_protected)(addr, size, protected);
   return 0;
}

/* Valgrind callback for user request. Calls down to ecrq_* handlers */
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

/* Other command-line options are defined in ec_shadow and ec_errors, if
 * appropriate. */

/* Command-line option to control constant shadow ebits handling. If true, the
 * ebits are derived from constant value, otherwise it is treated as nullary
 * arithmetic operation (default native endianity). */
Bool EC_(opt_guess_const_size) = True;
/* Enabled origin tracking. Same effect as mem-check. */
Bool EC_(opt_track_origins) = False;
/* Enable memory protection. Allow memory regions to be `protected`,
 * automatically guarding against storing wrong endianity. Has performance
 * impact. */
Bool EC_(opt_protection) = False;
/* Produce per-instruction OTags. If False, OTags are shared for the whole IRSB, reducing the
 * precision */
Bool EC_(opt_precise_origins) = True;
/* Consider 'zero' constants as having 'any' type */
Bool EC_(opt_ignore_zeroes) = True;

/* Parse command-line options (even those defined in other files) */
static Bool ec_process_cmd_line_options(const char* arg)
{
   if VG_BOOL_CLO(arg, "--allow-unknown", EC_(opt_allow_unknown)) {}
   else if VG_BOOL_CLO(arg, "--guess-const-size", EC_(opt_guess_const_size)) {}
   else if VG_BOOL_CLO(arg, "--track-origins", EC_(opt_track_origins)) {}
   else if VG_BOOL_CLO(arg, "--protection", EC_(opt_protection)) {}
   else if VG_BOOL_CLO(arg, "--precise-origins", EC_(opt_precise_origins)) {}
   else if VG_BOOL_CLO(arg, "--report-different-origins", EC_(opt_report_different_origins)) {}
   else if VG_BOOL_CLO(arg, "--ignore-zeroes", EC_(opt_ignore_zeroes)) {}
   else return False;
   return True;
}

/* Print --help text */
static void ec_print_usage(void) {
   VG_(printf)(
"    --allow-unknown=yes|no      report unknown endianess as error?\n"
"    --guest-const-size=yes|no   guess constant size from its contents\n"
"    --track-origins=yes|no      track origins for data\n"
"    --protection=yes|no         allow certain memory regions to check for endianity on stores\n"
"    --report-different-origins=yes|no report endianity errors as separate if origins are different\n"
"    --precise-origins=yes|no    do origin tracking more precisely, but with less performance"
"    --ignore-zeroes=yes|no      consider all zero constants byte-sized, even if they are wider"
   );
}

/* Print --help-debug text */
static void ec_print_debug_usage(void) {

}

/* Ec_Endianity tag names (short versions). */
const char EC_(endianity_codes)[] = "UNTA";

/* Ec_Endianity tag names (long versions). */
const char* EC_(endianity_names)[] = {
   "Undefined",
   "Native",
   "Target",
   "Any"
};

/* Main entry point -- initializes all other callbacks */
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
