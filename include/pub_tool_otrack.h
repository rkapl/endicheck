/*--------------------------------------------------------------------*/
/*--- Get shadow offsets for origin tracking.  pub_tool_addrinfo.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2017-2017 Roman Kapl

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

#ifndef __PUB_TOOL_OTRACK_H
#define __PUB_TOOL_OTRACK_H

#include "pub_tool_basics.h"   // VG_ macro
#include "pub_tool_tooliface.h"

/* See detailed comments in mc_otrack.c. */
Int VG_(get_otrack_shadow_offset) ( Int offset, Int szB );
IRType VG_(get_otrack_reg_array_equiv_int_type) ( IRRegArray* arr );

#endif   // __PUB_TOOL_OTRACK_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
