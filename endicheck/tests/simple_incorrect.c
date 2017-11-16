#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>

struct ex
{
   uint8_t native_byte;
   uint32_t native_marked;
};

int main() {
   struct ex ex;
   ex.native_byte = 0xDD;
   ex.native_marked = 0xDEADBEEF;

   return EC_CHECK_ENDIANITY(&ex, sizeof(ex), EC_TARGET, NULL);
}
