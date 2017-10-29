
/*--------------------------------------------------------------------*/
/*--- Endicheck: Wrong endianity.                        ec_main.c ---*/
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

static void ec_post_clo_init(void)
{
}

static
IRSB* ec_instrument ( VgCallbackClosure* closure,
		      IRSB* bb,
		      const VexGuestLayout* layout,
		      const VexGuestExtents* vge,
		      const VexArchInfo* archinfo_host,
		      IRType gWordTy, IRType hWordTy )
{
    return bb;
}

static void ec_fini(Int exitcode)
{
}

static void ec_pre_clo_init(void)
{
   VG_(details_name)            ("endicheck");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("wrong endianity detector");
   VG_(details_copyright_author)(
      "Copyright (C) 2002-2017, and GNU GPL'd, by Roman Kapl.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(basic_tool_funcs)        (ec_post_clo_init,
				 ec_instrument,
				 ec_fini);

}

VG_DETERMINE_INTERFACE_VERSION(ec_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
