#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

static uint32_t htobe32(uint32_t param) {
    EC_MARK_ENDIANITY(&param, sizeof(param), EC_TARGET);
    return param;
}

int main() {
   uint32_t ex = htobe32(0xDEADBEEF) ^ htobe32(0x12345678);
   assert(ex == htobe32(0xDEADBEEF ^ 0x12345678));

   return EC_CHECK_ENDIANITY(&ex, sizeof(ex), NULL);
}
