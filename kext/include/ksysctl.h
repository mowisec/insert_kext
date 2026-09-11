/*
 * Give an injected kext a real sysctl node, registered AT RUNTIME.
 *
 * ---------------------------------------------------------------------------
 * WHY AT RUNTIME, AFTER A BUILD-TIME VERSION WAS TRIED AND FAILED ON HARDWARE
 * ---------------------------------------------------------------------------
 *
 * The first version of this wrote a `struct sysctl_oid` into the kernelcache
 * and pointed the parent node's list head at it, on the theory that a runtime
 * `sysctl_register_oid` was impossible: a sysctl_oid_list head lives next to
 * its parent node in __DATA_CONST, which is read-only once boot has finished.
 *
 * That theory was wrong in one place and the implementation was wrong in
 * another, and hardware said so:
 *
 *   1. XNU has an ANCHOR for exactly this problem.  The first entry in a
 *      node's children list can be an `__anchor__(_name)` OID with
 *      oid_number == INT_MIN, and `sysctl_register_oid_locked` then takes
 *      `anchor->oid_arg1` as a SECOND children list.  For `debug` that second
 *      list lives in __DATA,__bss -- writable at runtime.  An OID_AUTO
 *      registration is inserted THERE, not into the __DATA_CONST head.  So
 *      runtime registration was available the whole time.
 *
 *   2. The static version got the node registered -- `sysctl -N debug` listed
 *      it -- but READING it panicked:
 *
 *        panic(cpu 3): PAC failure from kernel with IA key while branching
 *        to x23 ... x22 = the OID, x19 = &oid->oid_handler with the top 16
 *        bits cleared
 *
 *      The OID was at exactly the designed address, the handler pointer's
 *      target was correct, and the modifier the call site used was bit-for-bit
 *      what the build had assumed.  The SIGNATURE still did not verify.  The
 *      build had asked the chained-fixup loader to produce an address-blended
 *      IA signature by setting addrDiv=1 and diversity=0, and whatever the
 *      loader produced was not what the CPU wanted -- even though that exact
 *      encoding appears 24477 times in the stock image.
 *
 * The lesson is the design, not the diagnosis: DO NOT ASK A THIRD PARTY TO
 * PRODUCE A SIGNATURE YOU COULD PRODUCE YOURSELF.  This version signs the two
 * pointers with `pacda` and `pacia` executed by the CPU that will later
 * authenticate them, and then hands the OID to the kernel's own
 * `sysctl_register_oid`, which re-signs the handler with the address blend
 * exactly as it does for the kernel's own 60 `debug` OIDs.  There is nothing
 * left to get wrong that the kernel does not already get wrong for itself.
 *
 * ---------------------------------------------------------------------------
 * THE TWO SIGNATURES
 * ---------------------------------------------------------------------------
 *
 *   oid_parent   key DA, modifier = blend(&oid->oid_parent, 0xdb49)
 *                `sysctl_register_oid_locked` authenticates it with
 *                `mov x17, x0 / movk x17, #0xdb49, lsl #48 / autda x16, x17`,
 *                and x0 is the OID, which is also &oid->oid_parent.
 *
 *   oid_handler  key IA, modifier = the constant 0x0e2e, NO address blend.
 *                This is the form a shipped image stores.  Registration does
 *                `mov x17, #0xe2e / autia x16, x17` and then re-signs with the
 *                address blend.  We hand over the unblended form and let it.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE KEXT MUST PROVIDE
 * ---------------------------------------------------------------------------
 *
 *   - `payload_sysctl`, declared with KSYSCTL_HANDLER.  It is reached through
 *     _kp_sysctl_entry, which supplies the BTI landing pad the kernel's
 *     authenticated indirect call requires.
 *   - a call to `ksysctl_register()` from `payload_main`.  It is one-shot: the
 *     guard word lives in the config's scratch region, because the kext's own
 *     memory is read-only.
 *
 * Registration takes a mutex, so it must not run from a context holding a
 * spinlock.  The hook the shipped config uses was already calling os_log, so
 * it is an ordinary thread context.
 */
#ifndef KSYSCTL_H
#define KSYSCTL_H

#include "kpayload.h"
#include "kaddrs.h"

/* struct sysctl_oid, 0x50 bytes.  Offsets verified against this kernel's
 * sysctl_register_oid / sysctl_register_oid_locked / sysctl_root. */
struct ksysctl_oid {
	void     *oid_parent;                   /* 0x00, signed DA */
	void     *oid_link;                     /* 0x08 */
	int32_t   oid_number;                   /* 0x10 */
	uint32_t  oid_kind;                     /* 0x14 */
	void     *oid_arg1;                     /* 0x18 -- KEEP NULL, see below */
	int32_t   oid_arg2;                     /* 0x20 */
	uint32_t  _pad;                         /* 0x24 */
	const char *oid_name;                   /* 0x28 */
	void     *oid_handler;                  /* 0x30, signed IA/0x0e2e */
	const char *oid_fmt;                    /* 0x38 */
	const char *oid_descr;                  /* 0x40 */
	int32_t   oid_version;                  /* 0x48 -- must be 1 */
	int32_t   oid_refcnt;                   /* 0x4c */
};

#define KSYSCTL_OID_AUTO        (-1)
#define KSYSCTL_VERSION         1

#define KCTLTYPE_INT            0x00000002u
#define KCTLFLAG_RD             0x80000000u
#define KCTLFLAG_LOCKED         0x00800000u
#define KCTLFLAG_OID2           0x00400000u   /* "has oid_version/oid_refcnt" */
#define KCTLFLAG_PERMANENT      0x00200000u

/*
 * Read-only int, locked, OID2, PERMANENT.
 *
 * PERMANENT is deliberate and does two things.  `sysctl_register_oid` skips
 * the zalloc-and-copy for a permanent OID and registers the struct we pass in
 * place -- no allocation in a context we did not choose.  And `sysctl_root`
 * skips the oid_refcnt increment on every read, which matters because that
 * increment is a store into the OID.
 *
 * OID2 and oid_version == 1 are both CHECKED by sysctl_register_oid; get
 * either wrong and it refuses.
 */
#define KSYSCTL_KIND_RD_INT \
	(KCTLTYPE_INT | KCTLFLAG_RD | KCTLFLAG_LOCKED | KCTLFLAG_OID2 | \
	 KCTLFLAG_PERMANENT)

#define KSYSCTL_HANDLER(fn) \
	__attribute__((used)) \
	int fn(void *oidp, void *arg1, int arg2, void *req)

/* The thunk in start.S; its first instruction is the BTI landing pad. */
extern char kp_sysctl_entry[];

static inline uint64_t
ksysctl_blend(const void *addr, uint16_t disc)
{
	return ((uint64_t)(uintptr_t)addr & 0x0000ffffffffffffULL)
	    | ((uint64_t)disc << 48);
}

static inline void *
ksysctl_sign_da(void *p, uint64_t modifier)
{
	void *r = p;
	__asm__ volatile("pacda %0, %1" : "+r"(r) : "r"(modifier));
	return r;
}

static inline void *
ksysctl_sign_ia(void *p, uint64_t modifier)
{
	void *r = p;
	__asm__ volatile("pacia %0, %1" : "+r"(r) : "r"(modifier));
	return r;
}

/* Forward to the kernel's own sysctl_handle_int.  With arg1 == NULL it reads
 * back arg2, which is the value baked into the OID.  Doing the output this way
 * keeps the copyout and the req bookkeeping on the kernel's side. */
static inline int
ksysctl_handle_int(void *oidp, void *arg1, int arg2, void *req)
{
	return KP_CALL(int, KADDR_sysctl_handle_int,
	    void *, void *, int, void *)(oidp, arg1, arg2, req);
}

/*
 * Register `name` under the parent named by KADDR_sysctl_parent_children.
 * One-shot, guarded by a magic word in scratch.  Returns 1 if this call did
 * the registration, 0 if it had already been done.
 *
 * oid_arg1 is left NULL on purpose.  The handler's re-signing discriminator is
 * blend(&oid_handler, hash16(oid_arg1 >> 4)); the kernel computes it either
 * way, but a NULL arg1 makes the value reproducible when reading a paniclog,
 * and `sysctl_handle_int` then reads back oid_arg2.
 */
static inline int
ksysctl_register(const char *name, const char *descr, int value)
{
	volatile uint64_t *guard = (volatile uint64_t *)kp_addr(KADDR_scratch);
	struct ksysctl_oid *oid =
	    (struct ksysctl_oid *)((char *)kp_addr(KADDR_scratch) + 0x40);

	if (*guard == 0x494b534332303236ULL)        /* "IKSC2026" */
		return 0;
	*guard = 0x494b534332303236ULL;

	oid->oid_parent = ksysctl_sign_da(kp_addr(KADDR_sysctl_parent_children),
	    ksysctl_blend(&oid->oid_parent, 0xdb49));
	oid->oid_link = 0;
	oid->oid_number = KSYSCTL_OID_AUTO;
	oid->oid_kind = KSYSCTL_KIND_RD_INT;
	oid->oid_arg1 = 0;
	oid->oid_arg2 = value;
	oid->_pad = 0;
	oid->oid_name = name;
	oid->oid_handler = ksysctl_sign_ia((void *)kp_sysctl_entry, 0x0e2e);
	oid->oid_fmt = "I";
	oid->oid_descr = descr;
	oid->oid_version = KSYSCTL_VERSION;
	oid->oid_refcnt = 0;

	KP_CALL(void, KADDR_sysctl_register_oid, struct ksysctl_oid *)(oid);
	return 1;
}

#endif /* KSYSCTL_H */
