#include "ec_errors.h"
#include "ec_shadow.h"
#include <pub_tool_errormgr.h>
#include <pub_tool_options.h>
#include <pub_tool_libcprint.h>

Bool EC_(check_syscalls);
Bool EC_(allow_unknown) = True;

typedef enum  {
   Ec_Err_MemoryEndianity
} Ec_ErrorKind;

typedef struct {
   union {
      struct {
         Addr base;
         SizeT start;
         SizeT size;
         Ec_Shadow wanted_endianity;
      } range_endianity;
   };
   const char* source_msg;
} Ec_Error;

static void report_range(ThreadId tid, Addr base, SizeT start, SizeT end, Ec_Shadow wanted, const char* source_msg)
{
   Ec_Error error;
   error.range_endianity.base = base;
   error.range_endianity.start = start;
   error.range_endianity.size = end - start;
   error.range_endianity.wanted_endianity = wanted;
   error.source_msg = source_msg;

   VG_(maybe_record_error)(tid, Ec_Err_MemoryEndianity, base + start, NULL, &error);
}

Bool EC_(check_memory_endianity)(
      ThreadId tid, Addr base, SizeT size, Ec_Shadow wanted, const char* source_msg)
{
   if (wanted == EC_ANY)
      return True;
   //VG_(message)(Vg_UserMsg, "Checking %lx (size %lu)\n", base, size);

   tl_assert(wanted != EC_UNKNOWN);
   SizeT start = 0;
   Bool last_ok = True;
   Bool all_ok = True;
   for(SizeT i = 0; i<size; i++) {
      Ec_Shadow shadow = EC_(get_shadow)(base + i);
      Ec_Endianity e = EC_(endianity_for_shadow)(shadow);
      Bool ok = (e == wanted) || (e == EC_ANY) || (EC_(allow_unknown) && (e == EC_UNKNOWN));
      if (last_ok != ok) {
         if (!ok) {
            start = i;
         } else {
            report_range(tid, base, start, i - 1, wanted, source_msg);
         }
      }
      last_ok = ok;
      all_ok = all_ok && ok;
   }

   if (!last_ok)
      report_range(tid, base, start, size, wanted, source_msg);

   return all_ok;
}

/*------------------------------------------------------------*/
/*--- Valgrind error callbacks                             ---*/
/*------------------------------------------------------------*/
#define eq_extra(prop) (extra1->prop == extra2->prop)
Bool EC_(eq_Error) ( VgRes res, const Error* e1, const Error* e2)
{
   Ec_Error* extra1 = VG_(get_error_extra)(e1);
   Ec_Error* extra2 = VG_(get_error_extra)(e2);

   /* Guaranteed by calling function (taken from MC) */
   tl_assert(VG_(get_error_kind)(e1) == VG_(get_error_kind)(e2));

   switch (VG_(get_error_kind)(e1)) {
      case Ec_Err_MemoryEndianity:
         return eq_extra(range_endianity.base)
               && eq_extra(range_endianity.start)
               && eq_extra(range_endianity.size)
               && eq_extra(range_endianity.wanted_endianity);
   default:
      VG_(tool_panic)("unknown error kind");
   }
}

void EC_(before_pp_Error)(const Error* err) {
}

static void print_description(const char* err_id, const char* fmt, ...) PRINTF_CHECK(2,3);
static void print_description(const char* err_id, const char* fmt, ...)
{
   const Bool xml  = VG_(clo_xml);
   va_list vargs;
   va_start(vargs, fmt);
   if (xml) {
      VG_(printf_xml)("  <kind>%s</kind>\n", err_id);
      VG_(printf_xml)("  <what>");
      VG_(vprintf_xml)(fmt, vargs);
      VG_(printf_xml)("  </what>");
   } else {
      VG_(vmessage)(Vg_UserMsg, fmt, vargs);
      VG_(message)(Vg_UserMsg, "\n");
   }
   va_end(vargs);
}

static void print_block(const char* msg, Addr base, SizeT start, SizeT size)
{
   const Bool xml  = VG_(clo_xml);
   if (xml) {
      VG_(printf_xml)("  <addr>\n");
      VG_(printf_xml)("    <base>0x%lx</base>\n", base);
      VG_(printf_xml)("    <start>%lu</start>\n", start);
      VG_(printf_xml)("    <size>%lu</size>\n", size);
      VG_(printf_xml)("  </addr>\n");
   } else {
      if (msg)
         VG_(message)(Vg_UserMsg, "A check of block at 0x%lx was requested, with message \"%s\".\n", base, msg);
      else
         VG_(message)(Vg_UserMsg, "A check of block at 0x%lx was requested.\n", base);
      VG_(message)(Vg_UserMsg, "The endianity is invalid at bytes %lu (size %lu) in that block\n", start, size);
   }
}

void EC_(pp_Error)(const Error* err)
{
   Ec_Error* extra = VG_(get_error_extra)(err);
   Ec_ErrorKind kind  = VG_(get_error_kind)(err);
   const HChar* err_name = EC_(get_error_name)(err);
   switch(kind) {
      case Ec_Err_MemoryEndianity:
         print_description(err_name, "Memory does not contain data of endianity %s",
                           EC_(endianity_names)[extra->range_endianity.wanted_endianity]);
         print_block(extra->source_msg, extra->range_endianity.base,
                     extra->range_endianity.start, extra->range_endianity.size);
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
      break;
   }
}

const HChar* EC_(get_error_name)(const Error* err)
{
   Ec_ErrorKind kind  = VG_(get_error_kind)(err);
   switch(kind) {
      case Ec_Err_MemoryEndianity:
         return "MemoryEndianity";
      break;
   default:
      VG_(tool_panic)("unknown error kind");
      break;
   }
}

UInt EC_(update_Error_extra)(const Error* err)
{
   return sizeof(Ec_Error);
}

Bool EC_(is_recognised_suppression) (const HChar* name, Supp* su)
{
   return False;
}
Bool EC_(read_extra_suppression_info)(Int fd, HChar** bufpp, SizeT* nBufp, Int* lineno, Supp *suppresion)
{
   return False;
}
Bool EC_(error_matches_suppression)(const Error* err, const Supp* su)
{
   return False;
}
SizeT EC_(get_extra_suppression_info)(const Error* err, /*OUT*/HChar* buf, Int nBuf)
{
   return 0;
}
SizeT EC_(print_extra_suppression_use)(const Supp *su, /*OUT*/HChar *buf, Int nBuf)
{
   return 0;
}
void EC_(update_extra_suppression_use)( const Error* err, const Supp* su)
{

}

#undef eq
