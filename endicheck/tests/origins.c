#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>


/* Try to avoid compiler optimization */
static __attribute__ ((noinline)) uint8_t source() {
   return 'a';
}

int main() {
   uint32_t native = source();
   uint32_t copy;

   memcpy(&copy, &native, sizeof(native));
   EC_CHECK_ENDIANITY(&copy, sizeof(copy), NULL);

   return 0;
}
