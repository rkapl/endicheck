#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>

struct ex
{
   uint32_t native_wrong;
   uint32_t native_target;
};

static uint32_t htobe32(uint32_t param) {
    EC_MARK_ENDIANITY(&param, sizeof(param), EC_TARGET);
    return param;
}

/* Try to avoid compiler optimization */
static __attribute__ ((noinline)) uint32_t source() {
   int test = 1;
   return 0xDEADBEEF;
}

int main() {
   struct ex ex;
   EC_PROTECT_REGION(&ex, sizeof(ex));
   ex.native_wrong = source();
   ex.native_target = htobe32(source());
   EC_UNPROTECT_REGION(&ex, sizeof(ex));

   return 0;
}
