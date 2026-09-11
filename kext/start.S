/*
 * insert_kext entry thunks.
 *
 * Linked first, so its __text lands at the start of the blob.
 *
 * The blob is position-independent by construction: every reference inside it
 * is PC-relative (adr / adrp+add / bl), and the ONE absolute value is the
 * `_kp_link_va` quad at the bottom, which the linker fills with the address
 * the blob was linked at.  `insert_kext build` links the same objects at two
 * different bases and requires that those 8 bytes are the only difference.
 * That turns "is this really position-independent?" into a build-time
 * assertion rather than a hope.
 *
 * Built -mgeneral-regs-only: a hooked kernel context may not have saved
 * FP/SIMD, so the kext must never touch it.
 */
    .text
    .p2align 2
    .globl  _kp_image_start
_kp_image_start:

/*
 * The hook trampoline.  Reached either by a stolen BL (`--hook`) or by a
 * detour that displaced one instruction (`--detour`).
 */
    .globl  _kp_entry
_kp_entry:
    bti     c
    /*
     * Save everything an interrupted context can still care about.
     *
     * A stolen BL only needs x0-x8 and x30: x9-x18 are caller-saved and
     * already dead at a call boundary, and x19-x28 are preserved by
     * payload_main because it is an ordinary C function.  A DETOUR is
     * different -- it replaces an ARBITRARY instruction, where x9-x18 and the
     * condition flags are live -- so those are saved too.  Ten extra registers
     * and one `mrs` on every firing is the price of the detour being usable
     * anywhere rather than only at a function entry, and it is paid on a path
     * that already makes a call.
     *
     * SP is restored before _kp_orig / _kp_tail, so a displaced stack-touching
     * instruction (`pacibsp` included) executes in the original context.
     */
    sub     sp, sp, #0xc0
    stp     x0, x1,  [sp, #0x00]
    stp     x2, x3,  [sp, #0x10]
    stp     x4, x5,  [sp, #0x20]
    stp     x6, x7,  [sp, #0x30]
    stp     x8, x30, [sp, #0x40]
    stp     x9, x10, [sp, #0x50]
    stp     x11, x12, [sp, #0x60]
    stp     x13, x14, [sp, #0x70]
    stp     x15, x16, [sp, #0x80]
    stp     x17, x18, [sp, #0x90]
    mrs     x0, nzcv
    str     x0, [sp, #0xa0]

    /* payload_main(x0..x5): the first six original arguments, for context. */
    bl      _payload_main

    ldr     x0, [sp, #0xa0]
    msr     nzcv, x0
    ldp     x17, x18, [sp, #0x90]
    ldp     x15, x16, [sp, #0x80]
    ldp     x13, x14, [sp, #0x70]
    ldp     x11, x12, [sp, #0x60]
    ldp     x9, x10, [sp, #0x50]
    ldp     x8, x30, [sp, #0x40]
    ldp     x6, x7,  [sp, #0x30]
    ldp     x4, x5,  [sp, #0x20]
    ldp     x2, x3,  [sp, #0x10]
    ldp     x0, x1,  [sp, #0x00]
    add     sp, sp, #0xc0

    .globl  _kp_orig
_kp_orig:
    /*
     * The instruction a detour displaced, copied in verbatim by
     * `insert_kext inject --detour <VA>`, and executed here in the original
     * register and stack context.
     *
     * NOTE: this slot is in the STRAIGHT-LINE path between the epilogue above
     * and _kp_tail below, so a stolen-BL payload DOES reach it.  `inject`
     * therefore rewrites it to `nop` whenever --detour is NOT given.  Leaving
     * it as `brk #0xfee0` in the file is still right: an unpatched blob must
     * trap loudly rather than run on.
     *
     * `--detour` REFUSES any PC-relative instruction, because moving it here
     * would change what it computes: B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADR,
     * ADRP and the literal-pool loads.
     */
    brk     #0xfee0

    .globl  _kp_tail
_kp_tail:
    /*
     * Patched by `insert_kext inject --tail ...`:
     *   ret          -> `ret`,    the payload was called and returns
     *   branch:<VA>  -> `b <VA>`, forward to the callee whose BL we stole
     *   nop          -> `nop`,    fall through to whatever follows
     * and by `--detour <VA>` to `b <VA+4>`, returning to the instruction after
     * the one _kp_orig now holds.
     * Left as `brk #0xfeed` so an unpatched blob traps loudly instead of
     * running off its own end.
     */
    brk     #0xfeed

/*
 * The sysctl handler entry point.
 *
 * `insert_kext inject --sysctl <name>` writes a struct sysctl_oid into the
 * image whose oid_handler points here.  XNU calls it as
 *
 *     int handler(struct sysctl_oid *oidp, void *arg1, int arg2,
 *                 struct sysctl_req *req)
 *
 * which is an ordinary AAPCS64 function, so this thunk only has to do the one
 * thing the C function cannot be trusted to do for itself: land a `bti c`.
 * The kernel dispatches with an authenticated indirect branch, so the target
 * must be a type-C landing pad, and clang emits one for a C function only when
 * it can see the address escape -- which it cannot here, because the address
 * is taken by the injector after the link.
 *
 * No PAC in the thunk: the payload is not built with pac-ret, and a `retab`
 * here would have to match a `pacibsp` we do not want to depend on.
 *
 * A kext with no use for a sysctl simply does not define `payload_sysctl`;
 * `insert_kext build` then links kext/nosysctl.S instead, which returns
 * ENOTSUP.  That is a SINGLE-DEFINITION rule rather than a weak symbol on
 * purpose -- a weak default living in this same file would be resolved by the
 * ASSEMBLER, so the `bl` below would bind to it and silently ignore the kext's
 * own definition.
 */
    .globl  _kp_sysctl_entry
_kp_sysctl_entry:
    bti     c
    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    bl      _payload_sysctl
    ldp     x29, x30, [sp], #0x10
    ret

/*
 * A second way in, for a kext reached as a SYSTEM CALL rather than through a
 * stolen BL or a sysctl.
 *
 * `insert_kext insert --syscall-slot N` points sysent[N].sy_call here, so
 * userspace reaches the kext with syscall(N, a, b, c).  XNU calls it as
 *
 *     int sy_call(struct proc *p, void *uap, int32_t *retval)
 *
 * an ordinary AAPCS64 function, so this thunk only does the one thing the C
 * function cannot be trusted to do for itself: land a `bti c`.  The kernel
 * dispatches with an authenticated indirect call, so the target must be a
 * type-C landing pad, and clang emits one for a C function only when it can
 * see the address escape -- which it cannot here, because the address is taken
 * by the injector after the link.
 *
 * No PAC in the thunk: the kext is not built with pac-ret, and a `retab` here
 * would have to match a `pacibsp` we do not want to depend on.
 *
 * A kext with no use for a syscall simply does not define `payload_syscall`;
 * the build then links kext/nosyscall.S instead, which returns ENOSYS.  Same
 * single-definition rule as payload_sysctl, and for the same reason: a weak
 * default living in THIS file would be resolved by the assembler, so the `bl`
 * below would bind to it and silently ignore the kext's own definition.
 */
    .globl  _kp_syscall_entry
_kp_syscall_entry:
    bti     c
    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    bl      _payload_syscall
    ldp     x29, x30, [sp], #0x10
    ret

    .p2align 3
    .globl  _kp_link_va
_kp_link_va:
    .quad   _kp_image_start
