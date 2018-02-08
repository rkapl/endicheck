#include "../endicheck.h"
#include <stdint.h>
#include <stddef.h>

typedef uint8_t v128 __attribute__ ((vector_size (16)));
typedef uint8_t v256 __attribute__ ((vector_size (32)));

/* tests load/stores with more exotic vector types */
typedef union {
   /* 256 bits in total */
   uint32_t d32[8];
   uint64_t d64[4];
   v128 v128[2];
   v256 v256[1];
} ex;

static void copy_64(ex* dst, ex* src)
{
   dst->d64[0] = src->d64[0];
   dst->d64[1] = src->d64[1];
   dst->d64[2] = src->d64[2];
   dst->d64[3] = src->d64[3];
}

static void copy_v128(ex* dst, ex* src)
{
   dst->v128[0] = src->v128[0];
   dst->v128[1] = src->v128[1];
}

static void copy_v256(ex* dst, ex* src)
{
   dst->v256[0] = src->v256[0];
}

int main() {
   ex src;
   int i;
   for(i = 0; i<8; i++)
      src.d32[i] = 0xDEADBEEF;
   EC_MARK_ENDIANITY(&src.d32[0], sizeof(src.d32[0]), EC_TARGET);

   ex dst64;
   copy_64(&dst64, &src);
   EC_DUMP_MEM(&dst64, sizeof(dst64));

   ex dst128;
   copy_v128(&dst128, &src);
   EC_DUMP_MEM(&dst128, sizeof(dst128));

   ex dst256;
   copy_v256(&dst256, &src);
   EC_DUMP_MEM(&dst256, sizeof(dst256));

   return 0;
}
