/*
   ----------------------------------------------------------------

   Notice that the following BSD-style license applies to this one
   file (endicheck.h) only.  The rest of Valgrind is licensed under the
   terms of the GNU General Public License, version 2, unless
   otherwise indicated.  See the COPYING file in the source
   distribution for details.

   ----------------------------------------------------------------

   This file is part of Endicheck, a tool for detecting data with wrong
   endianity leaving the program.

   Copyright (C) 2002-2017 Roman Kapl
      code@rkapl.cz

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. The origin of this software must not be misrepresented; you must
      not claim that you wrote the original software.  If you use this
      software in a product, an acknowledgment in the product
      documentation would be appreciated but is not required.

   3. Altered source versions must be plainly marked as such, and must
      not be misrepresented as being the original software.

   4. The name of the author may not be used to endorse or promote
      products derived from this software without specific prior written
      permission.

   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   ----------------------------------------------------------------

   Notice that the above BSD-style license applies to this one file
   (memcheck.h) only.  The entire rest of Valgrind is licensed under
   the terms of the GNU General Public License, version 2.  See the
   COPYING file in the source distribution for details.

   ----------------------------------------------------------------
*/

#ifndef __ENDICHECK_H
#define __ENDICHECK_H


/* This file is for inclusion into client (your!) code.

   You can use these macros to manipulate and query endianity of your data.

   See comment near the top of valgrind.h on how to use them.
*/

#include "valgrind.h"

typedef enum {
   EC_USERREQ__DUMP_MEM = VG_USERREQ_TOOL_BASE('E','C'),
   EC_USERREQ__MARK_ENDIANITY,
   EC_USERREQ__CHECK_ENDIANITY,
   EC_USERREQ__PROTECT_REGION,
   EC_USERREQ__UNPROTECT_REGION
} Ec_ClientRequest;

typedef enum {
   EC_UNKNOWN, EC_NATIVE, EC_TARGET, EC_ANY, EC_ENDIANITY_COUNT
} Ec_Endianity;

#define EC_DUMP_MEM(start, size) \
   VALGRIND_DO_CLIENT_REQUEST_EXPR(0, EC_USERREQ__DUMP_MEM, (start), (size), 0, 0, 0)

#define EC_MARK_ENDIANITY(start, size, endianity) \
   VALGRIND_DO_CLIENT_REQUEST_EXPR(0, EC_USERREQ__MARK_ENDIANITY, (start), (size), (endianity), 0, 0)

#define EC_CHECK_ENDIANITY(start, size, msg) \
   VALGRIND_DO_CLIENT_REQUEST_EXPR(0, EC_USERREQ__CHECK_ENDIANITY, (start), (size), (msg), 0, 0)

#define EC_PROTECT_REGION(start, size) \
   VALGRIND_DO_CLIENT_REQUEST_EXPR(0, EC_USERREQ__PROTECT_REGION, (start), (size), 0, 0, 0)

#define EC_UNPROTECT_REGION(start, size) \
   VALGRIND_DO_CLIENT_REQUEST_EXPR(0, EC_USERREQ__UNPROTECT_REGION, (start), (size), 0, 0, 0)

#endif
