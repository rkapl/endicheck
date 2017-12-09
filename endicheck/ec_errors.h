/*--------------------------------------------------------------------*/
/*--- A header file for error reporting and memory checking.       ---*/
/*---                                                 ec_errors.h  ---*/
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

#ifndef __EC_ERRORS_H
#define __EC_ERRORS_H

#include "ec_include.h"
#include "ec_shadow.h"

extern Bool EC_(opt_check_syscalls);
extern Bool EC_(opt_allow_unknown);

Bool EC_(check_memory_endianity)(
      ThreadId tid, Addr base, SizeT size, const char* source_msg);
void EC_(check_store)(Addr addr, SizeT size, Ec_Shadow* stored, Ec_Otag origin);

Bool EC_(eq_Error)(VgRes res, const Error* e1, const Error* e2 );
void EC_(before_pp_Error)(const Error* err);
void EC_(pp_Error)(const Error* err);
UInt EC_(update_Error_extra)(const Error* err);
Bool EC_(is_recognised_suppression) (const HChar* name, Supp* su );
Bool EC_(read_extra_suppression_info)(Int fd, HChar** bufpp, SizeT* nBufp, Int* lineno, Supp *suppresion);
Bool EC_(error_matches_suppression)(const Error* err, const Supp* su);
const HChar* EC_(get_error_name)(const Error* err);
SizeT EC_(get_extra_suppression_info)(const Error* err, /*OUT*/HChar* buf, Int nBuf);
SizeT EC_(print_extra_suppression_use)(const Supp *su, /*OUT*/HChar *buf, Int nBuf);
void EC_(update_extra_suppression_use)( const Error* err, const Supp* su);

#endif
