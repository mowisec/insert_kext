/*
 * kpayload - a tiny freestanding SDK for a kext compiled into an XNU
 * kernelcache by insert_kext.
 *
 * The model: the blob is position-independent, so its internal references are
 * correct wherever it lands and whatever KASLR does.  References *out* of the
 * blob are static VAs from the config plus a slide measured at runtime.
 *
 * Rules this SDK cannot enforce for you, so read them:
 *
 *   - NO WRITABLE DATA.  The blob lands in an executable, read-only segment
 *     that the hardware locks at runtime.  A non-const global, a
 *     `static int counter`, or a string you try to modify will fault.
 *     `insert_kext build` fails if the linked image has a non-empty __DATA or
 *     __bss, and again if the blob is not byte-identical when linked at two
 *     different addresses.
 *   - NO FP/SIMD.  Built -mgeneral-regs-only; a hooked context may not have
 *     saved the vector state.  Do not defeat this with intrinsics.
 *   - LITTLE STACK.  Kernel stacks are 16 KiB and you are borrowing someone
 *     else's.  No large locals, no recursion.
 *   - NO LIBC, NO SYMBOLS.  Nothing is linked in.  Call kernel functions by
 *     static VA through KP_CALL.
 *   - WHATEVER YOU HOOK, YOU ARE INSIDE.  Locks held, interrupts possibly
 *     off, any CPU.  Do the least possible and return.
 */
#ifndef KPAYLOAD_H
#define KPAYLOAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Start of the blob.  Taking its address is PC-relative, so this is where the
 * blob actually is, right now, after slide. */
extern char kp_image_start[];

/* The address the blob was linked at, baked in as data.  The only absolute
 * value in the whole payload; see start.S. */
extern const uint64_t kp_link_va;

/* The KASLR slide, measured rather than assumed. */
static inline uint64_t
kp_slide(void)
{
	return (uint64_t)(uintptr_t)kp_image_start - kp_link_va;
}

/* Turn a static VA from the config into a runtime address. */
static inline void *
kp_addr(uint64_t static_va)
{
	return (void *)(uintptr_t)(static_va + kp_slide());
}

/*
 * Call a kernel function named by its static VA:
 *   KP_CALL(int, KADDR_something, int, char *)(3, p)
 */
#define KP_CALL(ret, static_va, ...) \
	((ret (*)(__VA_ARGS__))kp_addr(static_va))

/* The boot/hook entry point.  Arguments are the hooked call's own x0..x5. */
void payload_main(uint64_t a0, uint64_t a1, uint64_t a2,
    uint64_t a3, uint64_t a4, uint64_t a5);

#endif /* KPAYLOAD_H */
