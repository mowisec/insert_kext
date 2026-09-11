/*
 * The default `payload_sysctl`, linked only when the kext does not define one
 * of its own.  Returns ENOTSUP (45), so an image built without a sysctl
 * handler behaves sanely even if an OID were pointed at it.
 *
 * This lives in its own file, not in start.S, so that start.S's
 * `bl _payload_sysctl` is an external reference the LINKER resolves.  With
 * both in one file the assembler resolves the branch locally and the kext's
 * own definition is silently ignored.
 */
    .text
    .p2align 2
    .globl  _payload_sysctl
_payload_sysctl:
    bti     c
    mov     w0, #45
    ret
