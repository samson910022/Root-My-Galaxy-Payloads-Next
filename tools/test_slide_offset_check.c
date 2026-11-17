/* Host regression test for src/slide_offset_check.h.
 *
 * Build twice, from the repository root:
 *   cc -Isrc tools/test_slide_offset_check.c -o /tmp/offsetcheck            # default 0x10000 grid
 *   cc -Isrc -DSLIDE_P0_FORCE_ALIGN=0x8000 -DSLIDE_P0_FORCE_MAX=0x1f8000 \
 *      tools/test_slide_offset_check.c -o /tmp/offsetcheck-gzif              # GZIF 0x8000 grid
 *
 * The expectations switch on which configuration is compiled in; both must pass.
 */
#include "slide_offset_check.h"
#include <stdint.h>
#include <stdio.h>

static int failures;

static void check(uint64_t value, int expect) {
  int got = slide_forced_p0_offset_ok(value);
  const char *verdict = got == expect ? "ok  " : "FAIL";
  printf("%s slide_forced_p0_offset_ok(0x%llx) = %d (expected %d)\n",
         verdict, (unsigned long long)value, got, expect);
  if (got != expect) failures++;
}

int main(void) {
  /* Common cases. */
  check(0x000000ULL, 1);   /* base offset always allowed */
  check(0x10000ULL, 1);    /* first classic-grid step */
  check(0x1f0000ULL, 1);   /* classic top candidate */

#if !defined(SLIDE_P0_FORCE_ALIGN)
  /* Classic 0x10000-grid constraint (unchanged for pre-existing targets). */
  check(0x8000ULL, 0);     /* odd 0x8000 step: rejected */
  check(0x18000ULL, 0);
  check(0x1f8000ULL, 0);   /* above classic top */
  check(0x200000ULL, 0);   /* out of range */
  check(0x1f0001ULL, 0);   /* misaligned */
  check(0xffffULL, 0);
#else
  /* GZIF 0x8000-grid constraint (target's own candidate table). */
  check(0x8000ULL, 1);     /* odd multiples of 0x8000 are real candidates */
  check(0x18000ULL, 1);
  check(0x1e8000ULL, 1);
  check(0x1f8000ULL, 1);   /* probe offset: must be forceable */
  check(0x1f0000ULL, 1);
  check(0x200000ULL, 0);   /* out of range */
  check(0x1ff000ULL, 0);   /* above table top */
  check(0x4000ULL, 0);     /* finer than the table's stride */
  check(0x1f0001ULL, 0);   /* misaligned */
#endif

  if (failures) {
    printf("%d check(s) FAILED\n", failures);
    return 1;
  }
  printf("all forced-offset checks passed\n");
  return 0;
}
