/*
 * Reaching an injected kext from userspace through a spare `sysent` slot.
 *
 * `insert_kext insert --syscall-slot N` points sysent[N].sy_call at the thunk
 * in start.S, so userspace calls syscall(N, a, b, c) and arrives at the kext's
 * `payload_syscall`.  A sysctl carries one number out; this carries three full
 * 64-bit arguments in, which is what you want for anything that reads or
 * writes on demand.
 *
 * XNU's shape:
 *
 *     int sy_call(struct proc *p, void *uap, int32_t *retval)
 *
 * The three arguments arrive in `uap` as an array of three 64-bit words --
 * NOT in registers -- because the slot is patched with the same 3-argument
 * munger the kernel uses for an ordinary 3-argument syscall.  The return value
 * userspace sees is `*retval`; a non-zero function return is an errno.
 *
 * A kext with no use for this simply does not define `payload_syscall`; the
 * build then links kext/nosyscall.S, which returns ENOSYS.  Note that ENOSYS
 * is also what an UNPATCHED spare slot returns, so if you want to prove the
 * channel works, return something recognisable instead.
 */
#ifndef KSYSCALL_H
#define KSYSCALL_H

#include "kpayload.h"

/* A value no ordinary syscall returns, so a test can tell "our code ran" from
 * "the slot was never patched". */
#define IK_SYSCALL_MAGIC 0x4B450000      /* 'KE' << 16 */

#define KSYSCALL_HANDLER(fn) \
	__attribute__((used)) \
	int fn(void *p __attribute__((unused)), void *uap, int32_t *retval)

#endif /* KSYSCALL_H */
