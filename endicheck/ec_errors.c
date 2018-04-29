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

/* Options related error reporting are defined here, but are set in ec_main.c during command-line
 * parsing phase */

/* Allow unknown tags in checked memory (protected or explicitely checkd) when true, report it as
 * error when set to false. */
Bool EC_(opt_allow_unknown) = True;
/* Consider errors with different origin tags as different errors. When true,
 * two errors that differ only in origin tag will be reported twice, when false
 * only one of them will be reported.
 *
 * Since origin tags can differ if they are the same from users point of view
 * (he does not care about parts of stack, for example), this is false by
 * default to reduce the number of errors.
 *
 * Has no effect if origin tracking is disabled */
Bool EC_(opt_report_different_origins) = True;

/* Error report types supported by Endicheck */
typedef enum  {
   /* Reports a bad endianity in part of memory that was explicitely checked
    * using user request */
   Ec_Err_MemoryEndianity,
   /* Reports a bad endianity written to a protected region of memory */
   Ec_Err_StoreEndianity,
} Ec_ErrorKind;

/* Maximum number of origin tags remembered per error report. */
#define MAX_ORIGINS 5

typedef struct {
   union {
      /* Information for Ec_Err_MemoryEndianity error type */
      struct {
         /* The region of memory that was checked using user request */
         Addr base;
         /* The start of sub-region that has invalid endianity */
         SizeT start;
         /* Size of the sub-region that has invalid endianity */
         SizeT size;
         /* Number of origin tags used in the array bellow. Zero if origin
          * tracking is not enabled. */
         SizeT origin_count;
         /* The origin tags seen in the memory-sub region that has invalid
          * endianity. Only the first MAX_ORIGINS ones are reported. */
         Ec_Otag origins[MAX_ORIGINS];
      } memory;
      /* Information for Ec_Err_StoreEndianity error type */
      struct {
         /* Addres inside a protected region to which a write has been performed
          */
         Addr addr;
         /* Size of the write operation */
         SizeT store_size;
         /* Origin tag of the write operation */
         Ec_Otag origin;
      } store;
   };
   /* Message provided by the caller (currently on for Ec_Err_MemoryEndianity */
   const char* source_msg;
} Ec_Error;

/* Helper function to create an error report (Ec_Error) of
 * Ec_Err_MemoryEndianity type.
 *
 * The source_msg argument is assumed to be a static string (won't be
 * deallocated).
 *
 * Origins are passed as an OSet (a hashset) by the caller and the OSet is
 * copied to the error report origin array. If set is NULL, the array will be
 * empty. The OSet is destroyed by this function. */
static void report_range(
      ThreadId tid, Addr base, SizeT start, SizeT end, const char* source_msg, OSet **origins)
{
   Ec_Error error;
   error.memory.base = base;
   error.memory.start = start;
   error.memory.size = end - start;

   /* Copy over the origin tags */
   if (*origins) {
      VG_(OSetWord_ResetIter)(*origins);
      SizeT origin_count = 0;
      UWord origin;
      while (VG_(OSetWord_Next)(*origins, &origin) && origin_count < MAX_ORIGINS) {
         error.memory.origins[origin_count++] = origin;
      }
      error.memory.origin_count = origin_count;
      VG_(OSetWord_Destroy)(*origins);
   } else {
      error.memory.origin_count = 0;
   }

   error.source_msg = source_msg;

   *origins = NULL;

   /* Finally report */
   VG_(maybe_record_error)(tid, Ec_Err_MemoryEndianity, base + start, NULL, &error);
}

/* Check if given endianity tag is considered a valid endianity or should cause
 * and error report. It respects the opt_allow_unknown command-line option */
static Bool is_endianity_ok(Ec_Endianity e)
{
   return (e == EC_TARGET) || (e == EC_ANY) || (EC_(opt_allow_unknown) && (e == EC_UNKNOWN));
}

/* Called by ec_shadow.c for each memory store in a protected memory region
 * (only if memory protection is enabled) */
void EC_(check_store)(Addr addr, SizeT size, Ec_Shadow *stored, Ec_Otag otag)
{
   tl_assert(EC_(opt_protection));
   tl_assert(size <= EC_MAX_STORE);
   Bool problem = False;
   /* Check each byte for valid endianity and protection status */
   for(SizeT i = 0; i<size; i++) {
      Bool is_protected = EC_(is_protected)(addr + i);
      Ec_Endianity e = EC_(endianity_for_shadow(stored[i]));
      if (is_protected && !is_endianity_ok(e))
         problem = True;
   }

   /* Any part problematic? */
   if (problem) {
      Ec_Error error;
      error.store.addr = addr;
      error.store.store_size = size;
      error.store.origin = otag;
      error.source_msg = NULL;

      VG_(maybe_record_error)(VG_(get_running_tid)(), Ec_Err_StoreEndianity, addr, NULL, &error);
   }

}

/* Check endianity of memory regions.
 *
 * Called by ec_main.c when user-request is encountered */
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
            /* Changed to OK, report the previous range that was NOT OK. */
            report_range(tid, base, start, i, source_msg, &origins);
         } else {
            /* Changed to NOT OK, start tracking the region */
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
/*--- Valgrind error callbacks + print                     ---*/
/*------------------------------------------------------------*/

/* The callbacks in this section are directly given to Valgrind core in
 * ec_main.c */

/* Helper to compare and error report property */
#define eq_extra(prop) (extra1->prop == extra2->prop)

/* Used for error de-duplication by Valgrind. We need to compare
 * all the extra information valgrind does not have access to. */
Bool EC_(eq_Error) ( VgRes res, const Error* e1, const Error* e2)
{
   Ec_Error* extra1 = VG_(get_error_extra)(e1);
   Ec_Error* extra2 = VG_(get_error_extra)(e2);

   /* Guaranteed by calling function (taken from MC) */
   tl_assert(VG_(get_error_kind)(e1) == VG_(get_error_kind)(e2));

   switch (VG_(get_error_kind)(e1)) {
      case Ec_Err_MemoryEndianity:
         if (EC_(opt_report_different_origins)) {
            return extra1->memory.origin_count == extra2->memory.origin_count
               && VG_(memcmp)(
                  extra1->memory.origins,
                  extra2->memory.origins,
                  sizeof(Ec_Otag)*extra1->memory.origin_count) == 0;
         }
         return True;
      case Ec_Err_StoreEndianity:
         return True;
   default:
      VG_(tool_panic)("unknown error kind");
   }
}

/* Print an error description: error type name and formatted message */
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

/* Print a list of deduplicated origin tags. */
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

/* Print Ec_Err_MemoryEndianity type error details (without description and
 * stack traces). */
static void print_memory(const char* msg, Addr base, SizeT start, SizeT size, Ec_Otag origins[], SizeT origin_count)
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

/* Print Ec_Err_StoreEndianity type error details (without description and stack
 * traces) */
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

/* Print and error. This is a Valgrind callback. */
void EC_(pp_Error)(const Error* err)
{
   Ec_Error* extra = VG_(get_error_extra)(err);
   Ec_ErrorKind kind  = VG_(get_error_kind)(err);
   const HChar* err_name = EC_(get_error_name)(err);
   switch(kind) {
   case Ec_Err_MemoryEndianity:
      print_description(err_name, "Memory does not contain data of Target endianity");
      print_memory(extra->source_msg, extra->memory.base,
                  extra->memory.start, extra->memory.size,
                  extra->memory.origins, extra->memory.origin_count
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

/* Get an error type name. This is a Valgrind callback. */
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

/*------------------------------------------------------------*/
/*--- Unused callbacks                                     ---*/
/*------------------------------------------------------------*/

/* In particular, we do not support suppressions yet */

void EC_(before_pp_Error)(const Error* err) {
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
