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

int main() {
   struct ex ex;
   EC_PROTECT_REGION(&ex, sizeof(ex));
   ex.native_wrong = 0xDEADBEEF;
   ex.native_target = htobe32(0xDEADBEEF);
   EC_UNPROTECT_REGION(&ex, sizeof(ex));

   return 0;
}
