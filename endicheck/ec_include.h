/*--------------------------------------------------------------------*/
/*--- A header file for main parts of the Endicheck tool.          ---*/
/*---                                                 ec_include.h ---*/
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

#ifndef __EC_INCLUDE_H
#define __EC_INCLUDE_H

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "endicheck.h"
#include <stdint.h>

#define EC_(str)    VGAPPEND(vgEndiCheck_,str)

#define EC_EMPTY_TAG 0x8
#define EC_NATIVE_EMPTY (EC_NATIVE + EC_EMPTY_TAG)
typedef uint8_t Ec_Shadow;

/* A tuple of endianity tag and origin tag */
typedef struct {
   IRExpr* ebits;
   IRExpr* origin;
} Ec_ShadowExpr;

extern Bool EC_(opt_guess_const_size);
extern Bool EC_(opt_track_origins);

Ec_Endianity EC_(endianity_for_shadow)(Ec_Shadow shadow);
Bool EC_(is_empty_for_shadow) (Ec_Shadow shadow);
IRExpr* EC_(const_sizet)(SizeT size);
void EC_(dump_mem)(Addr start, SizeT size);

extern const char EC_(endianity_codes)[];
extern const char* EC_(endianity_names)[];

#endif
