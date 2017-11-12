
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
#include "pub_tool_tooliface.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcprint.h"
#include "ec_include.h"
#include "ec_shadow.h"
#include <stddef.h>

#define EC_INSTRUMENT_HEAPID "ec_instrument"

typedef struct {
      IRSB* out_sb;
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

static Ec_Endianity default_endianity(IRType ty)
{
   tl_assert(has_endianity(ty));
   return (ty == Ity_I8) ? EC_ANY : EC_NATIVE;
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
 * We use this function every time when an expression (which was previouslu flat)
 * is expanded to a non-flat one or when we make a composite constant.
 */
static IRExpr* assignNew(Ec_Env* env, IRExpr* expr)
{
   if (isIRAtom(expr))
      return expr;

   IRType type = typeOfIRExpr(env->out_sb->tyenv, expr);
   IRTemp tmp = newIRTemp(env->out_sb->tyenv, type);
   IRStmt* assignment = IRStmt_WrTmp(tmp, expr);
   tl_assert(isFlatIRStmt(assignment));
   stmt(env, assignment);
   return IRExpr_RdTmp(tmp);
}

static ULong mk_shadow(Ec_Env* env,int length, Ec_Endianity e)
{
   tl_assert(length > 0 && length <= 8);
   ULong acc = 0;
   for (int i = 0; i<length; i++) {
      acc <<= 8;
      acc |= e;
   }
   return acc;
}

static IRExpr* mk_shadow_i128(Ec_Env* env,Ec_Endianity endianity)
{
   IRExpr* part = IRExpr_Const(IRConst_U64(mk_shadow(env, 8, endianity)));
   return assignNew(env, IRExpr_Binop(Iop_64HLto128, part, part));
}

static IRExpr* mk_shadow_v128(Ec_Env* env,Ec_Endianity endianity)
{
   IRExpr* part = IRExpr_Const(IRConst_U64(mk_shadow(env, 8, endianity)));
   return assignNew(env, IRExpr_Binop(Iop_64HLtoV128, part, part));
}

static IRExpr* mk_shadow_v256(Ec_Env* env,Ec_Endianity endianity)
{
   IRExpr* part = assignNew(env, mk_shadow_v128(env, endianity));
   return assignNew(env, IRExpr_Binop(Iop_V128HLtoV256, part, part));
}

static IRExpr* mk_shadow_vector(Ec_Env* env,IRType ty, Ec_Endianity endianity)
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

static IRExpr* default_shadow_for_type(Ec_Env* env, IRType expr_type)
{
   tl_assert(has_endianity(expr_type));
   return mk_shadow_vector(env, type2shadow(expr_type), default_endianity(expr_type));
}

static IRExpr* default_shadow(Ec_Env* env, IRExpr* expr)
{
   IRType expr_type = typeOfIRExpr(env->out_sb->tyenv, expr);
   return default_shadow_for_type(env, expr_type);
}

static IRExpr* expr2shadow(Ec_Env* env, IRExpr* expr);

/* Default handler for IR ops that just move around bytes. In that case we
 * simply apply the same operation to the shadow data.
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
      // for widening, mark the new bytes as NATIVE
      case Iop_8Uto64:
         return IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(mk_shadow(env, 8, EC_NATIVE) & 0xFFFFFFFFFFFFFF00)),
            assignNew(env, same_for_shadow(env, expr)));
      case Iop_16Uto64:
         return IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(mk_shadow(env, 8, EC_NATIVE) & 0xFFFFFFFFFFFF0000)),
            assignNew(env, same_for_shadow(env, expr)));
      case Iop_32Uto64:
         return IRExpr_Binop(Iop_Or64,
            IRExpr_Const(IRConst_U64(mk_shadow(env, 8, EC_NATIVE) & 0xFFFFFFFF00000000)),
            assignNew(env, same_for_shadow(env, expr)));
         break;
      case Iop_8Uto32:
         return IRExpr_Binop(Iop_Or32,
            IRExpr_Const(IRConst_U32(mk_shadow(env, 4, EC_NATIVE) & 0xFFFFFF00)),
            assignNew(env, same_for_shadow(env, expr)));
      case Iop_16Uto32:
         return IRExpr_Binop(Iop_Or32,
            IRExpr_Const(IRConst_U32(mk_shadow(env, 4, EC_NATIVE) & 0xFFFF0000)),
            assignNew(env, same_for_shadow(env, expr)));
      case Iop_8Uto16:
         return IRExpr_Binop(Iop_Or16,
            IRExpr_Const(IRConst_U16(mk_shadow(env, 2, EC_NATIVE) & 0xFF00)),
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
      case Iex_Const:
      default:
         return default_shadow(env, expr);
   }
}

static void shadow_wrtmp(Ec_Env *env, IRTemp to, IRExpr* from)
{
   if (has_endianity(typeOfIRTemp(env->out_sb->tyenv, to))) {
      stmt(env, IRStmt_WrTmp(temp2shadow(env, to), expr2shadow(env, from)));
   }
}

static void shadow_put(Ec_Env *env, Int to, IRExpr* from)
{
   if (has_endianity(typeOfIRExpr(env->out_sb->tyenv, from))) {
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
   IRType type = typeOfIRExpr(env->out_sb->tyenv, value);
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

   IRType type = typeOfIRTemp(env->out_sb->tyenv, dirty->tmp);
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

static const char endianity_codes[] = "UNTA";

#define ECRQ_DUMP_ROW_SIZE 40
static void ecrq_dump_mem(UWord* arg)
{
   ec_addr start = arg[1];
   size_t size = arg[2];
   VG_(message)(Vg_UserMsg, "Memory endianity dump (legend: Undefined, Native, Target, Any):\n");
   for(size_t i = 0; i<size; i += ECRQ_DUMP_ROW_SIZE) {
      char row[ECRQ_DUMP_ROW_SIZE + 1];
      size_t row_size = size - i;
      if (row_size > ECRQ_DUMP_ROW_SIZE)
         row_size = ECRQ_DUMP_ROW_SIZE;
      for (size_t c = 0; c<row_size; c++) {
         Ec_Endianity e = EC_(get_shadow)(start + i + c);
         tl_assert(e >= EC_UNKNOWN && e < EC_ENDIANITY_COUNT);
         row[c] = endianity_codes[e];
      }
      row[row_size] = 0;

      VG_(message)(Vg_UserMsg, "%p: %s\n", (void*)(start + i), row);
   }
   VG_(message)(Vg_UserMsg, "\n");
}

static void ecrq_mark_endian(UWord* arg)
{
   ec_addr start = arg[1];
   size_t size = arg[2];
   Ec_Endianity endianity = arg[3];
   for(size_t i = 0; i<size; i++) {
      EC_(set_shadow)(start + i, endianity);
   }
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
         case EC_USERREQ__MARK_ENDIAN:
            ecrq_mark_endian(arg);
            *ret = 1;
         break;
         default:
            VG_(message)(Vg_UserMsg, "Warning: unknown endicheck client request code %llx\n",(ULong)arg[0]);
         return False;
            return False;
      }
   }
   return False;
}

static void EC_(pre_clo_init)(void)
{
   VG_(details_name)            ("endicheck");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("wrong endianity detector");
   VG_(details_copyright_author)(
      "Copyright (C) 2002-2017, and GNU GPL'd, by Roman Kapl.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(basic_tool_funcs)        (
             EC_(post_clo_init),
             EC_(instrument),
             EC_(fini));
   VG_(needs_client_requests)     (EC_(client_request));
}

VG_DETERMINE_INTERFACE_VERSION(EC_(pre_clo_init))

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
