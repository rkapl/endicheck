#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>


static uint32_t htobe32(uint32_t param) {
    EC_MARK_ENDIANITY(&param, sizeof(param), EC_TARGET);
    return param;
}

/* Try to avoid compiler optimization */
static __attribute__ ((noinline)) uint8_t get_byte() {
   return 'a';
}

int main() {
   /* let's try how the endianness survives packing bytes */
   uint64_t packed;
   packed = ( ((uint64_t)htobe32(0xDEADBEEF)) << 32) | htobe32(0xDEADBEEF);
   EC_DUMP_MEM(&packed, sizeof(packed));
   EC_CHECK_ENDIANITY(&packed, sizeof(packed), EC_TARGET, NULL);

   packed = ((uint64_t)get_byte()) | ((uint64_t)get_byte() << 8);
   EC_DUMP_MEM(&packed, sizeof(packed));
   EC_CHECK_ENDIANITY(&packed, sizeof(packed), EC_TARGET, NULL);

   return 0;
}
