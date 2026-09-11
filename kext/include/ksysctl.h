/*
 * The sysctl side of an injected kext.
 *
 * `insert_kext inject --sysctl <name>` writes a `struct sysctl_oid` into the
 * image and points the parent node's list head at it, with `oid_handler`
 * pointing here.  See ikext/ksysctl.py for why the registration is done in the
 * image rather than by calling sysctl_register_oid at runtime.
 *
 * The handler is called exactly as XNU calls any other one:
 *
 *     int handler(struct sysctl_oid *oidp, void *arg1, int arg2,
 *                 struct sysctl_req *req)
 *
 * It must be reachable through an authenticated indirect call, so it needs a
 * BTI landing pad; KSYSCTL_HANDLER gives it one.  Clang emits a landing pad
 * for a C function only when it can see its address escape, and here it
 * cannot, because the address is taken by the injector after the link.
 *
 * `ksysctl_handle_int` forwards to the kernel's own `sysctl_handle_int`, which
 * with arg1 == NULL returns arg2 -- the value `insert_kext inject
 * --sysctl-value` baked into the OID.  Doing the output that way rather than
 * by hand means the copyout, the req bookkeeping and the write path are the
 * kernel's, not ours.
 */
#ifndef KSYSCTL_H
#define KSYSCTL_H

#include "kpayload.h"
#include "kaddrs.h"

#define KSYSCTL_HANDLER(fn)                                                   \
	__attribute__((used))                                                 \
	int fn(void *oidp, void *arg1, int arg2, void *req)

static inline int
ksysctl_handle_int(void *oidp, void *arg1, int arg2, void *req)
{
	return KP_CALL(int, KADDR_sysctl_handle_int,
	    void *, void *, int, void *)(oidp, arg1, arg2, req);
}

#endif /* KSYSCTL_H */
