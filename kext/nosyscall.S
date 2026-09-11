/*
 * The default `payload_syscall`, linked only when the kext does not define one
 * of its own.  Returns ENOSYS (78) -- exactly what a spare sysent slot returned
 * before it was patched -- so an image built without a syscall payload behaves
 * like the stock kernel even if a slot were pointed at it.
 *
 * This lives in its own file, not in start.S, so that start.S's
 * `bl _payload_syscall` is an external reference the LINKER resolves.  With
 * both in one file the assembler resolves the branch locally and the kext's
 * own definition is silently ignored.
 */
    .text
    .p2align 2
    .globl  _payload_syscall
_payload_syscall:
    bti     c
    mov     w0, #78
    ret
