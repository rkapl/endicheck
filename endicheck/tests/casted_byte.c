#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>

static __attribute__ ((noinline)) uint16_t source() {
   return 0xDEAD;
}

int main() {
   uint8_t ex = (uint8_t) source();

   return EC_CHECK_ENDIANITY(&ex, sizeof(ex), NULL);
}
