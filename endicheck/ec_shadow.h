/*--------------------------------------------------------------------*/
/*--- A header file for the shadow memory table handling.          ---*/
/*---                                                 ec_shadow.h ---*/
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

#ifndef __EC_SHADOW_H
#define __EC_SHADOW_H

#include <stdint.h>
#include "ec_main.h"

typedef uint32_t Ec_Otag;
#define EC_NO_OTAG 0
#define EC_MAX_STORE 16

void EC_(shadow_init)(void);
void EC_(set_protected)(Addr addr, SizeT size, Bool protected);
Bool EC_(is_protected)(Addr addr);
void EC_(set_shadow)(Addr addr, Ec_Shadow endianity);
void EC_(set_shadow_otag)(Addr addr, Ec_Otag tag);
Ec_Shadow EC_(get_shadow)(Addr addr);
Ec_Shadow EC_(get_shadow_with_protection)(Addr addr);
Ec_Otag EC_(get_shadow_otag)(Addr addr);

void EC_(gen_shadow_store)(IRSB* out, IREndness endness, IRExpr* addr, Ec_ShadowExpr shadow);
void EC_(gen_shadow_store_guarded)(
      IRSB* out, IREndness endness, IRExpr* addr, Ec_ShadowExpr data,
      IRExpr* guard);

Ec_ShadowExpr EC_(gen_shadow_load)(
      IRSB* out, IREndness endness, IRType type, IRExpr* addr);
Ec_ShadowExpr EC_(gen_shadow_load_guarded)(
      IRSB* out, IREndness endness, IRType type, IRExpr* addr,
      IRLoadGOp cvt, IRExpr* guard, Ec_ShadowExpr alt);

#endif
