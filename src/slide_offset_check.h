/* Forced slide-P0-offset (SLIDE_P0_OFFSET env) validity check, shared by
 * src/slide.c and src/slide_app.c.
 *
 * Targets on the classic 0x10000 slide grid accept 0x000000..0x1f0000 in
 * 0x10000 steps (the historical constraint, preserved exactly for every
 * target that does not opt in below).
 *
 * A target whose candidate table uses another stride defines
 * SLIDE_P0_FORCE_ALIGN (must be a power of two) and SLIDE_P0_FORCE_MAX
 * *next to its candidate table*; the forced path then follows that grid
 * instead. The dm3q-S9180ZHU8GZIF target is the first user (0x8000 grid,
 * 0x1f8000 top). The two macros must be defined together.
 *
 * Include this only after common.h (which pulls in offset.h → TARGET_HEADER);
 * including it earlier silently yields classic-grid semantics.
 */
#ifndef SLIDE_OFFSET_CHECK_H
#define SLIDE_OFFSET_CHECK_H

#include <stdint.h>

#if defined(SLIDE_P0_FORCE_ALIGN) != defined(SLIDE_P0_FORCE_MAX)
#error "SLIDE_P0_FORCE_ALIGN and SLIDE_P0_FORCE_MAX must be defined together"
#endif

#if defined(SLIDE_P0_FORCE_ALIGN)
#if SLIDE_P0_FORCE_ALIGN == 0 || (SLIDE_P0_FORCE_ALIGN & (SLIDE_P0_FORCE_ALIGN - 1ULL)) != 0
#error "SLIDE_P0_FORCE_ALIGN must be a power of two"
#endif
#endif

static inline int slide_forced_p0_offset_ok(uint64_t value) {
#if defined(SLIDE_P0_FORCE_ALIGN) && defined(SLIDE_P0_FORCE_MAX)
  if (value > (uint64_t)SLIDE_P0_FORCE_MAX) return 0;
  if ((value & ((uint64_t)SLIDE_P0_FORCE_ALIGN - 1ULL)) != 0) return 0;
  return 1;
#else
  if (value > 0x1f0000ULL) return 0;
  if ((value & 0xffffULL) != 0) return 0;
  return 1;
#endif
}

#endif
