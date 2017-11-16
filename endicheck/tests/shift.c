#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>

static uint32_t htobe32(uint32_t param) {
    EC_MARK_ENDIANITY(&param, sizeof(param), EC_TARGET);
    return param;
}

int main() {
   uint32_t t;
   t = htobe32(0xDEADBEEF) << 8;
   EC_DUMP_MEM(&t, sizeof(t));

   t = htobe32(0xDEADBEEF) >> 8;
   EC_DUMP_MEM(&t, sizeof(t));

   return 0;
}
