#include "ec_errors.h"
#include "ec_shadow.h"
#include "pub_tool_errormgr.h"
#include "pub_tool_options.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_execontext.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_oset.h"
#include "pub_tool_mallocfree.h"

Bool EC_(opt_check_syscalls);
Bool EC_(opt_allow_unknown) = True;
Bool EC_(opt_report_different_origins) = True;

typedef enum  {
   Ec_Err_MemoryEndianity,
   Ec_Err_StoreEndianity,
} Ec_ErrorKind;

#define MAX_ORIGINS 5

typedef struct {
   union {
      struct {
         Addr base;
         SizeT start;
         SizeT size;
         SizeT origin_count;
         Ec_Otag origins[MAX_ORIGINS];
      } range_endianity;
      struct {
         Addr addr;
         SizeT store_size;
         Ec_Otag origin;
      } store;
   };
   const char* source_msg;
} Ec_Error;

static void report_range(
      ThreadId tid, Addr base, SizeT start, SizeT end, const char* source_msg, OSet **origins)
{
   Ec_Error error;
   error.range_endianity.base = base;
   error.range_endianity.start = start;
   error.range_endianity.size = end - start;

   if (*origins) {
      VG_(OSetWord_ResetIter)(*origins);
      SizeT origin_count = 0;
      UWord origin;
      while (VG_(OSetWord_Next)(*origins, &origin) && origin_count < MAX_ORIGINS) {
         error.range_endianity.origins[origin_count++] = origin;
      }
      error.range_endianity.origin_count = origin_count;
      VG_(OSetWord_Destroy)(*origins);
   } else {
      error.range_endianity.origin_count = 0;
   }
      
   error.source_msg = source_msg;
   
   *origins = NULL;

   VG_(maybe_record_error)(tid, Ec_Err_MemoryEndianity, base + start, NULL, &error);
}

static Bool is_endianity_ok(Ec_Endianity e)
{
   return (e == EC_TARGET) || (e == EC_ANY) || (EC_(opt_allow_unknown) && (e == EC_UNKNOWN));
}

void EC_(check_store)(Addr addr, SizeT size, Ec_Shadow *stored, Ec_Otag otag)
{
   tl_assert(EC_(opt_protection));
   tl_assert(size <= EC_MAX_STORE);
   Bool problem = False;
   for(SizeT i = 0; i<size; i++) {
      Bool is_protected = EC_(is_protected)(addr + i);
      Ec_Endianity e = EC_(endianity_for_shadow(stored[i]));
      if (is_protected && !is_endianity_ok(e))
         problem = True;
   }

   if (problem) {
      Ec_Error error;
      error.store.addr = addr;
      error.store.store_size = size;
      error.store.origin = otag;
      error.source_msg = NULL;

      VG_(maybe_record_error)(VG_(get_running_tid)(), Ec_Err_StoreEndianity, addr, NULL, &error);
   }

}

Bool EC_(check_memory_endianity)(
      ThreadId tid, Addr base, SizeT size, const char* source_msg)
{  
   // VG_(message)(Vg_UserMsg, "Checking %lx (size %lu)\n", base, tsize);

   SizeT start = 0;
   Bool last_ok = True;
   OSet *origins = NULL;
   Bool all_ok = True;
   /* Go throught the memory and try to find consecutive regions of invalid endianity with the
    * same origin.
    */
   for(SizeT i = 0; i<size; i++) {
      Ec_Shadow shadow = EC_(get_shadow)(base + i);
      Ec_Endianity e = EC_(endianity_for_shadow)(shadow);
      Ec_Otag origin = EC_NO_OTAG;
      Bool ok = is_endianity_ok(e);
      if (EC_(opt_track_origins))
         origin = EC_(get_shadow_otag)(base + i);

      if (ok != last_ok) {
         if (!last_ok) {
            report_range(tid, base, start, i, source_msg, &origins);
         } else {
            start = i;
            if (EC_(opt_track_origins))
               origins = VG_(OSetWord_Create)(VG_(malloc), "ec_origin_reporting_oset", VG_(free));
         }
      }
      
      if (!ok && EC_(opt_track_origins) && (VG_(is_plausible_ECU)(origin) || origin == EC_NO_OTAG)) {
         if (!VG_(OSetWord_Contains)(origins, origin))
            VG_(OSetWord_Insert)(origins, origin);
      }

      last_ok = ok;
      all_ok = all_ok && ok;
   }

   if (!last_ok)
      report_range(tid, base, start, size, source_msg, &origins);

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
         if (EC_(opt_report_different_origins)) {
            return extra1->range_endianity.origin_count == extra2->range_endianity.origin_count
               && VG_(memcmp)(
                  extra1->range_endianity.origins, 
                  extra2->range_endianity.origins, 
                  sizeof(Ec_Otag)*extra1->range_endianity.origin_count) == 0;
         }
         return True;
      case Ec_Err_StoreEndianity:
         return True;
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

static void print_origin(Ec_Otag origins[], SizeT origin_count)
{
   if (EC_(opt_track_origins)) {
      tl_assert(origin_count > 0);
      if (VG_(clo_xml)) {
         VG_(printf_xml)("  <origins/>n");
         for (SizeT i = 0; i<origin_count; i++) {
            if (origins[i] == EC_NO_OTAG) 
               VG_(printf_xml)("      <unknown-origin/>n");
            else
               VG_(pp_ExeContext)(VG_(get_ExeContext_from_ECU)(origins[i]));
         }
         VG_(printf_xml)("  </origins/>n");
      } else {
         if (origin_count == 1) {
            VG_(message)(Vg_UserMsg, "The value was probably created at this point:\n");
         } else {
            VG_(message)(Vg_UserMsg, "The value was probably created at these points:\n");
         }
         
         Bool unknown_seen = False;
         for (SizeT i = 0; i<origin_count; i++) {
            if (origins[i] == EC_NO_OTAG)
               unknown_seen = True;
            else
               VG_(pp_ExeContext)(VG_(get_ExeContext_from_ECU)(origins[i]));
         }
         if (unknown_seen)
            VG_(message)(Vg_UserMsg, "Unknown creatiom point.\n");
      }
   }
}

static void print_block(const char* msg, Addr base, SizeT start, SizeT size, Ec_Otag origins[], SizeT origin_count)
{
   const Bool xml  = VG_(clo_xml);

   if (xml) {
      VG_(printf_xml)("  <addr>\n");
      VG_(printf_xml)("    <base>0x%lx</base>\n", base);
      VG_(printf_xml)("    <start>%lu</start>\n", start);
      VG_(printf_xml)("    <size>%lu</size>\n", size);
      VG_(printf_xml)("  </addr>\n");
      if (msg)
         VG_(printf_xml)("  <msg>%ps</msg\n", msg);
      
      print_origin(origins, origin_count);
   } else {
      if (msg)
         VG_(message)(Vg_UserMsg,
            "Problem was found in block %p (named %s) at offset %lu, size %lu:\n",
            (void*)base, msg, start, size);
      else
         VG_(message)(Vg_UserMsg,
            "Problem was found in block %p at offset %lu, size %lu:\n",
            (void*)base, start, size);
      EC_(dump_mem_noheader)(base + start, size);

      print_origin(origins, origin_count);
      VG_(message)(Vg_UserMsg, "The endianity check was requested here:\n");
   }
}

static void print_store(Addr addr, SizeT size, Ec_Otag origin)
{
   const Bool xml  = VG_(clo_xml);
   ExeContext* origin_ctx = NULL;
   if (EC_(opt_track_origins)) {
      if (VG_(is_plausible_ECU)(origin)) {
         origin_ctx = VG_(get_ExeContext_from_ECU)(origin);
      }
   }

   if (xml) {
      VG_(printf_xml)("  <addr>\n");
      VG_(printf_xml)("    <base>0x%lx</base>\n", addr);
      VG_(printf_xml)("    <size>%lu</size>\n", size);
      VG_(printf_xml)("  </addr>\n");
      
      VG_(printf_xml)("  <origins>\n");
         VG_(pp_ExeContext)(origin_ctx);
      VG_(printf_xml)("  </origins>\n");
   } else {
      VG_(message)(Vg_UserMsg, "Address written to is %p, length %lu:\n",(void*)addr, size);
      /* TODO: dump the endianity */
      print_origin(&origin, 1);
      VG_(message)(Vg_UserMsg, "The write occured here:\n");
   }
}

void EC_(pp_Error)(const Error* err)
{
   Ec_Error* extra = VG_(get_error_extra)(err);
   Ec_ErrorKind kind  = VG_(get_error_kind)(err);
   const HChar* err_name = EC_(get_error_name)(err);
   switch(kind) {
      case Ec_Err_MemoryEndianity:
         print_description(err_name, "Memory does not contain data of Target endianity");
         print_block(extra->source_msg, extra->range_endianity.base,
                     extra->range_endianity.start, extra->range_endianity.size,
                     extra->range_endianity.origins, extra->range_endianity.origin_count
                    );
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
      break;
   case Ec_Err_StoreEndianity:
      print_description(err_name, "Writing data of invalid endianity into protected region");
      print_store(extra->store.addr, extra->store.store_size, extra->store.origin);
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
      case Ec_Err_StoreEndianity:
         return "StoreEndianity";
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
