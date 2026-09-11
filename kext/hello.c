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

#ifndef IK_IOREG_KEY
#define IK_IOREG_KEY   "insert_kext"
#endif
#ifndef IK_IOREG_VALUE
#define IK_IOREG_VALUE "hello"
#endif
#ifndef IK_IOREG_NODE
#define IK_IOREG_NODE  "insert_kext"
#endif
#ifndef IK_IOREG_CLASS
#define IK_IOREG_CLASS "IOService"
#endif

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
 * Publishing a property into the IO registry, so the injected kext is visible
 * to `ioreg` and not only to `sysctl`.
 *
 * WHY FROM THE SYSCTL HANDLER AND NOT FROM payload_main.  The hook fires
 * during early boot, and the registry root does not exist until IOKit has been
 * initialised.  A sysctl read happens when userspace asks, which is long after
 * that, so calling from here removes the timing question entirely instead of
 * guessing where in the boot the hook sits.
 *
 * WHY setProperty(const char *, const char *) AND NOT A C++ CLASS.  Defining
 * an IOService subclass would mean building a vtable, and on arm64e vtable
 * entries are signed pointers: constructing one by hand is exactly the mistake
 * that kext/include/ksysctl.h documents at length.  Calling two existing,
 * non-virtual kernel functions constructs nothing -- every pointer involved
 * was signed by the kernel that owns it.
 *
 * Both addresses must be in the config's symbol map, so this compiles away
 * entirely on an image where they are not known.
 */
static void
ik_publish_ioreg_property(void)
{
#if defined(KADDR_IORegistryEntry_getRegistryRoot) && \
    defined(KADDR_IORegistryEntry_setProperty_cstr)
	static const uint64_t MARK = 0x494b494f524547ULL;       /* "IKIOREG" */
	volatile uint64_t *once = (volatile uint64_t *)
	    ((char *)kp_addr(KADDR_scratch) + 16);
	void *root;

	if (*once == MARK)
		return;

	root = KP_CALL(void *, KADDR_IORegistryEntry_getRegistryRoot, void)();
	if (root == 0) {
		klog_err("insert_kext (ioreg): no registry root yet");
		return;
	}
	KP_CALL(int, KADDR_IORegistryEntry_setProperty_cstr,
	    void *, const char *, const char *)(root, IK_IOREG_KEY,
	    IK_IOREG_VALUE);

	*once = MARK;
	klog_err("insert_kext (ioreg): set %s on the registry root %p",
	    IK_IOREG_KEY, root);
#endif
}

/*
 * Registering an actual node, rather than a property on somebody else's.
 *
 * THE OBJECT IS ALLOCATED BY THE KERNEL, WHICH IS THE WHOLE TRICK.  Defining
 * our own IOService subclass would mean emitting a vtable, and on arm64e a
 * vtable is a table of signed pointers.  Asking the runtime to allocate an
 * instance of a class it already knows gives us an object whose vtable is the
 * kernel's own, correctly signed, with nothing constructed by us.  Every call
 * below then goes directly to the concrete implementation -- which is exactly
 * what virtual dispatch on that object would have reached anyway.
 *
 * The addresses came out of the class's vtable rather than a name match: the
 * symbol table scored `attach` at 0.28 and `registerService` at 0.42, which is
 * not good enough to call blind, and the vtable gives them exactly.
 */
static void
ik_register_ioservice(void)
{
#if defined(KADDR_OSMetaClass_allocClassWithName) && \
    defined(KADDR_IOService_init) && \
    defined(KADDR_IORegistryEntry_setName_cstr) && \
    defined(KADDR_IOService_getServiceRoot) && \
    defined(KADDR_IOService_attach) && \
    defined(KADDR_IOService_registerService)
	static const uint64_t MARK = 0x494b4e4f444531ULL;       /* "IKNODE1" */
	volatile uint64_t *once = (volatile uint64_t *)
	    ((char *)kp_addr(KADDR_scratch) + 24);
	void *obj, *provider;

	if (*once == MARK)
		return;
	*once = MARK;                   /* set FIRST: one attempt, never a loop */

	obj = KP_CALL(void *, KADDR_OSMetaClass_allocClassWithName,
	    const char *)(IK_IOREG_CLASS);
	if (obj == 0) {
		klog_err("insert_kext (node): allocClassWithName returned null");
		return;
	}
	if (!KP_CALL(int, KADDR_IOService_init, void *, void *)(obj, 0)) {
		klog_err("insert_kext (node): init failed");
		return;
	}
	KP_CALL(int, KADDR_IORegistryEntry_setName_cstr,
	    void *, const char *, void *)(obj, IK_IOREG_NODE, 0);

	provider = KP_CALL(void *, KADDR_IOService_getServiceRoot, void)();
	if (provider == 0) {
		klog_err("insert_kext (node): no service root");
		return;
	}
	if (!KP_CALL(int, KADDR_IOService_attach, void *, void *)(obj, provider)) {
		klog_err("insert_kext (node): attach failed");
		return;
	}
	KP_CALL(void, KADDR_IOService_registerService,
	    void *, unsigned int)(obj, 0);

	klog_err("insert_kext (node): registered %s at %p", IK_IOREG_NODE, obj);
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

	ik_publish_ioreg_property();
	ik_register_ioservice();

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
