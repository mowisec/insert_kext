/*
 * The example kext that ships with insert_kext.
 *
 * It exists to be replaced.  Its whole job is to demonstrate the two halves of
 * getting your own code into a kernel and reaching it again afterwards:
 *
 *   payload_main    runs from the call site --hook retargeted.  It registers
 *                   the sysctl, ONCE, and then does nothing for the rest of
 *                   the boot.
 *
 *   payload_sysctl  runs when someone reads that sysctl.  It logs, and returns
 *                   the value baked into the OID.
 *
 * WHY payload_main IS SILENT AFTER THE FIRST CALL.  The hook fires every few
 * seconds for the life of the boot, and an earlier version logged every time.
 * That is noise, and it is noise in a small ring buffer that other subsystems
 * are also writing to.  The hook is a way IN, not a heartbeat: once the sysctl
 * exists, the sysctl is the observable, and it produces output exactly when
 * somebody asks for it.
 *
 * The sysctl is also the proof that payload_main ran at all -- nothing else
 * registers it -- which is why `insert_kext check` treats its presence as the
 * evidence rather than looking for a log line that has long since scrolled.
 */
#include "kpayload.h"
#include "klog.h"
#include "ksysctl.h"
#include "ksyscall.h"

void
payload_main(uint64_t a0, uint64_t a1, uint64_t a2,
    uint64_t a3, uint64_t a4, uint64_t a5)
{
	(void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;

#ifdef IK_SYSCTL_NAME
	/*
	 * One-shot.  ksysctl_register returns 0 both when it has already run
	 * and when it is still too early to run -- see ksysctl.h -- so the
	 * common case after the first success is a load, a compare and a
	 * return.
	 */
	if (ksysctl_register(IK_SYSCTL_NAME, IK_SYSCTL_DESCR, IK_SYSCTL_VALUE))
		klog_err("insert_kext: registered sysctl " IK_SYSCTL_NAME
		    ", slide=" KLOG_ADDR_FMT, KLOG_ADDR(kp_slide()));
#else
	/*
	 * With no sysctl there is no on-demand observable, so this is the only
	 * evidence the kext ran -- and it is still one-shot, because a kernel
	 * log ring wraps in well under a minute on a busy device and a line
	 * printed every three seconds would not survive any longer than a line
	 * printed once.  Catch it with `dmesg` shortly after boot.
	 */
	static const uint64_t MARK = 0x494b48454c4c4f31ULL;      /* "IKHELLO1" */
	volatile uint64_t *once = (volatile uint64_t *)kp_addr(KADDR_scratch);

	if (*once != MARK) {
		*once = MARK;
		klog_err("hello from insert_kext (boot hook), slide="
		    KLOG_ADDR_FMT, KLOG_ADDR(kp_slide()));
	}
#endif
}

/*
 * Reached through _kp_sysctl_entry, which supplies the BTI landing pad the
 * kernel's authenticated indirect call requires.  Logging here is not noise:
 * it happens once per read, when somebody asked.
 */
KSYSCTL_HANDLER(payload_sysctl)
{
	klog_err("hello from insert_kext (sysctl), slide=" KLOG_ADDR_FMT,
	    KLOG_ADDR(kp_slide()));

	return ksysctl_handle_int(oidp, arg1, arg2, req);
}

/*
 * The third way in, reached only when the image was built with
 * --syscall-slot N: userspace calls syscall(N, a, b, c) and lands here.
 *
 * XNU calls it as sy_call(struct proc *p, void *uap, int32_t *retval), with
 * the three arguments already munged into uap[0..2] as full 64-bit values.
 *
 * IT RETURNS A MAGIC RATHER THAN ENOSYS, AND THAT IS THE POINT.  The default
 * payload_syscall in kext/nosyscall.S returns ENOSYS -- which is exactly what
 * an unpatched spare sysent slot returns, so a test against it cannot tell a
 * working channel from a slot nobody touched.  Echoing a recognisable value
 * back through *retval makes the channel's success visible.
 */
KSYSCALL_HANDLER(payload_syscall)
{
	const uint64_t *uap64 = (const uint64_t *)uap;

	klog_err("hello from insert_kext (syscall), a=%llx b=%llx c=%llx",
	    (unsigned long long)uap64[0], (unsigned long long)uap64[1],
	    (unsigned long long)uap64[2]);

	*retval = (int32_t)(IK_SYSCALL_MAGIC + (int32_t)uap64[0]);
	return 0;
}
