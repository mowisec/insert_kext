/*
 * The example kext that ships with insert_kext.
 *
 * It does one thing, twice over, so that both trigger paths can be told apart
 * on a running device:
 *
 *   on boot     `payload_main` runs from whatever call site --hook retargeted
 *               and logs to dmesg.  With the default hook that site fires
 *               every few seconds, which makes it a positive control rather
 *               than a one-shot you might miss.
 *
 *   on demand   `payload_sysctl` runs when someone reads the sysctl node that
 *               --sysctl registered, logs the same line, and returns the value
 *               baked into the OID.
 *
 * Both are deliberately trivial.  A kext that only misbehaves on failure is
 * silent both when it works and when it never ran, so the useful first
 * payload is one whose success is visible.
 */
#include "kpayload.h"
#include "klog.h"
#include "ksysctl.h"

void
payload_main(uint64_t a0, uint64_t a1, uint64_t a2,
    uint64_t a3, uint64_t a4, uint64_t a5)
{
	(void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;

	klog_err("hello from insert_kext (boot hook), slide=" KLOG_ADDR_FMT,
	    KLOG_ADDR(kp_slide()));
}

/*
 * Reached through _kp_sysctl_entry, which supplies the BTI landing pad.
 * Logging first and forwarding to the kernel's own sysctl_handle_int second
 * keeps every byte of the copyout on the kernel's side of the line.
 */
KSYSCTL_HANDLER(payload_sysctl)
{
	klog_err("hello from insert_kext (sysctl), slide=" KLOG_ADDR_FMT,
	    KLOG_ADDR(kp_slide()));

	return ksysctl_handle_int(oidp, arg1, arg2, req);
}
