# insert_kext

Compile a kext from C source and put it into an iOS kernelcache.

`insert_kext` takes a kernelcache — as an `.ipsw`, an IM4P, or an already
decompressed Mach-O — compiles your code into a freestanding,
position-independent blob, splices it into unused space in the image, rewires
one or more existing instructions so it runs, optionally gives it a real
`sysctl` node, stamps a random build tag into the kernel version string, and
packages the result as a bootable IM4P.

It is standalone. It knows nothing about any particular device beyond what a
JSON config tells it, so it should carry over to another iPhone, another iOS
build, or another kernelcache entirely.

```
insert_kext.py insert kernelcache.research.im4p \
    --hook oslog_extensible_paniclog \
    --sysctl insert_kext --sysctl-value 42 \
    -o hello.im4p
```

```
kext:   hello.c  571 bytes, 15805 bytes of slack left
  tail:     branch:0xfffffe000b1d48b4
  0x4368008  571 bytes  kext (entry 0xfffffe000b36c008)
  25 sites  hook 'oslog_extensible_paniclog' -> 0xfffffe000b36c008
  0xfffffe0008412e30  sysctl 'debug.insert_kext' -> handler 0xfffffe000b36c080, returns 42
  build tag: IKCEFFB_ARM64_T8150
```

On the device:

```
$ uname -a                       # must match the build tag above
Darwin ... root:xnu-...~5/IKCEFFB_ARM64_T8150 arm64
$ sysctl debug.insert_kext
debug.insert_kext: 42
$ dmesg | grep insert_kext
hello from insert_kext (boot hook), slide=00000000...
hello from insert_kext (sysctl), slide=00000000...
```

**Check the build tag before believing anything.** A kext that only misbehaves
on failure is silent both when it works and when it never ran, and the tag is
what tells those apart.

---

## What this does, and what it does not

There are two ways to get your own code into a finished kernelcache, and this
tool implements the first.

| | Slack injection *(what this does)* | Full fileset entry *(not implemented)* |
|---|---|---|
| What you add | a raw code blob in unused space | a real `MH_FILESET` kext entry with a bundle identifier |
| Image geometry | **unchanged** — same file size, same offsets | every segment after `__PRELINK_TEXT` moves |
| Space | whatever slack the image has (16376 bytes on T8150) | as much as you want |
| IOKit, C++, `OSObject`, driver matching | no | yes |
| `kextstat` lists it | no | yes |

So "kext" here means *your code, running in the kernel, calling kernel
functions and answering a `sysctl`* — which is what most people want a kext
for — and **not** a bundle IOKit will match a driver against. If you need
`IOService` matching or personalities, this is the wrong tool.

---

## Installing

Nothing to install. You need:

* **Xcode command line tools** — `clang`, `ld`, `nm`, `llvm-objdump`, all
  reached through `xcrun`.
* **Python 3.9+**, standard library only.
* **[`ipsw`](https://github.com/blacktop/ipsw)** — *only* if your input is
  LZFSE-compressed. An `.ipsw` or an IM4P straight off a device is, so in
  practice you want it. A kernelcache you decompressed yourself needs nothing.

---

## Writing a kext

```c
#include "kpayload.h"
#include "klog.h"
#include "ksysctl.h"

void
payload_main(uint64_t a0, uint64_t a1, uint64_t a2,
    uint64_t a3, uint64_t a4, uint64_t a5)
{
	klog_err("hello, slide=" KLOG_ADDR_FMT, KLOG_ADDR(kp_slide()));
}

KSYSCTL_HANDLER(payload_sysctl)
{
	klog_err("someone read my sysctl");
	return ksysctl_handle_int(oidp, arg1, arg2, req);
}
```

`payload_main` receives the first six argument registers of whatever call site
you hooked, so you can inspect the arguments of the function you displaced.
Both entry points are optional: a kext with no `payload_sysctl` links a default
that returns `ENOTSUP`.

Build it with `--kext yourfile.c` (repeatable). See `kext/hello.c`.

### The SDK

| | |
|---|---|
| `kp_slide()` | the KASLR slide, **measured**: `&kp_image_start` (PC-relative, so it is the runtime address) minus `kp_link_va` (an absolute constant baked in at link time) |
| `kp_addr(static_va)` | a static VA from the config, turned into a runtime address |
| `KP_CALL(ret, KADDR_x, argtypes...)` | call a kernel function by static VA |
| `klog_err/klog_info(fmt, ...)` | `os_log`, which reaches `dmesg` |
| `KLOG_ADDR_FMT` / `KLOG_ADDR(v)` | print an address in halves, because `os_log` redacts pointers |
| `KSYSCTL_HANDLER(fn)` | declare the sysctl handler |
| `ksysctl_handle_int(...)` | forward to the kernel's own `sysctl_handle_int` |

`KADDR_*` constants are generated from the config's `symbols` map, so
`"panic": "0x..."` in the config becomes `KADDR_panic` in C.

### The rules, and why

* **No writable data.** The blob lands in an executable, read-only segment
  that the hardware locks at runtime. A non-`const` global, a `static int
  counter`, a string you try to modify — all fault.
* **No absolute addresses.** Injected code has to survive KASLR. The build
  enforces this; see below.
* **No FP/SIMD.** Compiled `-mgeneral-regs-only`. A hooked kernel context may
  not have saved the vector state.
* **Little stack.** Kernel stacks are 16 KiB and you are borrowing someone
  else's. No large locals, no recursion.
* **No libc, no symbols.** Nothing is linked in. iOS kernelcaches export
  essentially nothing, so every kernel entry point has to be found by
  signature or xref and written into the config by hand.
* **Whatever you hook, you are inside.** Locks may be held, interrupts may be
  off, you may be on any CPU. Do the least possible and return.

### How position-independence is *proved*, not hoped for

`insert_kext` links the kext three times:

1. a probe link, only to measure how far into `__TEXT` the Mach-O header
   pushes the first section;
2. the real link, placed so the first section lands **exactly** on the target
   address;
3. the same link one MiB higher.

Links 2 and 3 must be byte-identical except for the eight bytes of
`kp_link_va`. Anything else that changes with the link address — a pointer
initialiser, a jump table, a relocated string table — fails the build with the
offending offsets. So "is this really position independent?" is answered by
the build rather than by a boot.

The two bases differ by a multiple of the 4 KiB `adrp` page, which is what
makes the check valid: `adrp` encodes a page delta, so a blob relocated by a
non-page-multiple would break silently. Linking directly at the target
sidesteps that entirely, which matters because the T8150 slack starts at
`...c008` and is not page-aligned.

---

## Hooking: making the kext run

A hook is a single 4-byte instruction rewrite — the same edit class as an
ordinary one-instruction kernel patch, which is why it is low risk.

### Stealing an existing `BL`

Pick a call site that already calls something, retarget its `BL` to the kext,
and let the kext forward to the original callee when it is done.

```
--hook <name-from-config> --tail branch:<original callee VA>
```

The trampoline saves `x0`–`x18`, `x30` and `NZCV`, calls `payload_main`,
restores everything including `SP`, then executes the tail instruction:

| `--tail` | emits | use when |
|---|---|---|
| `branch:<VA>` | `b <VA>` | you stole a `BL`; forwards to the original callee, which returns to the original caller |
| `ret` | `ret` | you stole a `BL` to something you do not want to run |
| `nop` | `nop` | you are falling through into code appended after the kext |

A config's hook may name a `default_tail`, which is what the shipped config
does, so `--tail` is usually unnecessary.

Unpatched, the tail slot is `brk #0xfeed`, so a blob that somehow ships without
being finished traps loudly instead of running off its own end. The build
refuses any image that still carries a trap placeholder anywhere.

### Choosing a call site

This is the part that takes judgement, and it is where the risk actually
lives. The site the shipped config uses was chosen because:

* the message it logs was **observed leaving `dmesg` on a live device**, so
  the site demonstrably executes — no silent result;
* it fires about every three seconds, often enough to be a positive control
  and rarely enough not to flood;
* it was already calling `os_log`, so the context is **known safe** for the
  thing the kext wants to do.

Hooking a hot funnel like `os_log` itself was considered and rejected: a kext
with no one-shot guard floods, and a guard needs writable memory.

The config can name several call sites under one hook, and all of them get
retargeted. That is deliberate: if you are not certain which copy of an
inlined function runs, hook them all rather than gambling a reboot.

### Detours: hooking somewhere that is not a call site

Stealing a `BL` needs a `BL` to steal. To hook a *function entry* — or any
other instruction — use a detour:

```
--detour <VA>          (and no --tail; the detour sets it)
```

It replaces the instruction at `VA` with a branch to the kext, copies the
displaced instruction into the `_kp_orig` slot, and points the tail at
`VA + 4`. So the kext runs, the trampoline restores the full context
**including `SP`**, the displaced instruction executes in its original register
and stack context, and control returns to the instruction after it. `pacibsp`
at a function entry works for exactly that reason.

**It refuses PC-relative instructions** — `B`, `BL`, `B.cond`, `CBZ`/`CBNZ`,
`TBZ`/`TBNZ`, `ADR`, `ADRP` and the literal-pool loads — because moving one
into the kext changes what it computes. Detour the instruction before or after
it instead. The classifier is differential-tested against `llvm-objdump`:

```
insert_kext.py selftest <image> --va 0xfffffe000b000000 --size 0x20000
```

Over 131072 instructions in four slices of real kernel text: zero
disagreements.

---

## The sysctl node

```
--sysctl <name> [--sysctl-value N] [--sysctl-descr "..."]
```

gives the kext a real sysctl, readable with `sysctl debug.<name>`, whose
handler is your `payload_sysctl`.

**The registration happens in the image, not at runtime, and that is not an
optimisation.** A `struct sysctl_oid_list` is a singly linked list whose head
lives next to the parent node, and every built-in parent node lives in
`__DATA_CONST`, which is read-only once boot has finished. XNU gets away with
calling `sysctl_register_oid` because every built-in OID is registered from a
startup entry while `__DATA_CONST` is still writable, and because there is no
third-party kext loading on iOS for anything to register afterwards. A kext
hooked into ordinary running code is on the wrong side of that line. So
`insert_kext` writes the OID into the kernelcache and points the parent's list
head at it, exactly as the boot-time code would have left things.

That turns out to be *checkable* in a way a runtime call would not be: the list
head in a shipped kernelcache reads **zero**, because the lists really are
built at boot. So the tool is not editing a structure, it is initialising an
empty one — and if the head is not zero, this is not the image the config
describes and the build stops.

Everything else is copied from a **reference OID the image already contains**,
so the result has the shape of an OID this kernel already dispatches rather
than one derived from a specification someone wrote down.

The two pointer-authentication details, both read out of the kernel rather
than assumed, because getting either wrong is a panic on first access:

* `oid_parent` is signed with key **DA**, address-diversified, discriminator
  **0xdb49** — which is what `sysctl_register_oid_locked` authenticates it
  with.
* `oid_handler` is signed with key **IA**, address-diversified, discriminator
  `hash16(oid_arg1 >> 4)`. A shipped image stores it *unblended* (IA,
  discriminator `0x0e2e`, no address diversity) because the boot-time
  registration re-signs it in place. Nothing will re-sign ours, so it is
  written already blended. Keeping `oid_arg1` NULL is not an accident: it
  makes that hash zero, so the diversity is a constant and a chained fixup can
  express it.

The OID and its strings go in the padding between the last section in
`__DATA_CONST` and the end of the segment — 4560 bytes on T8150, covered by no
section of any of the 302 fileset entries. `insert_kext` re-derives that
containment on every run rather than trusting the config's note, and refuses a
region that any section overlaps, that is not all zeros, or that is in a
segment writable at runtime (a `CTLFLAG_PERMANENT` OID belongs in read-only
memory, like every built-in one).

Adding the OID's pointers means adding links to the image's chained-fixup
chains, and that is the one place where plausible arithmetic silently stops a
page of pointers from being rebased. `ikext/macho.py:chain_insert` re-walks
the page afterwards and requires the result to be exactly the old chain plus
the one new offset, in order.

**Status: verified statically, not yet on hardware.** Every byte decodes back
correctly, every chain still walks, and the PAC fields match the kernel's own
— but the sysctl path has not been booted. The hook path has.

---

## Command reference

| | |
|---|---|
| `insert <image>` | the whole pipeline: build, splice, hook, sysctl, tag, package |
| `info <image>` | segments, fileset entry count, linear-mapping check |
| `slack <image> [--min N]` | zero runs per segment, executable ones flagged |
| `build <image> [--kext ...]` | source → blob, with the position-independence proof |
| `verify <image> <patched>` | diff against stock, decoding branch targets |
| `selftest <image>` | the detour classifier against `llvm-objdump` |

Global options: `--config` (auto-selected by content if omitted), `--variant`
(which kernelcache to take out of an `.ipsw`), `--stock-im4p` (where to get the
IM4P properties element when the input is a bare Mach-O).

Every write asserts what it is overwriting first: the slack must still be all
zeros, the bytes before it must still match `preceded_by`, a hooked instruction
must still be the branch `expect_target` says it is, and the sysctl list head
must still be zero. A kernelcache that does not match the config fails the
build rather than producing a bad image.

---

## Installing the result

The image must be an **uncompressed IM4P**. Recompressing with a different
LZFSE encoder makes iBoot take a synchronous exception and panic before the
kernel runs, so `insert_kext` emits the payload uncompressed and no `0x30`
compression descriptor. iBoot also needs the 14 `kc*` properties (segment
sizes, `kclo`, `kcep`) that the stock image carries, so the stock IM4P's
properties element (DER tag `0xa0`) is spliced onto the new one rather than
regenerated. That is why the tool wants the IM4P or the `.ipsw` rather than a
bare Mach-O.

How you get a personalised, signed image onto a device is outside this tool's
scope and depends on what the device lets you do.

---

## Porting to another kernelcache

Write a config in `configs/`. The fields:

```jsonc
{
  "identify": { "sha256": "...", "marker": "RELEASE_ARM64_T8150" },
  "map_base": "0xfffffe0007004000",        // VA = map_base + file_offset
  "slack":    { "file_off": "0x4368008", "va": "0xfffffe000b36c008",
                "size": 16376, "preceded_by": "bf4100d5c0035fd6" },
  "build_tag": { "stock": "RELEASE_ARM64_T8150", "prefix": "IK", "count": 2 },
  "symbols":  { "panic": "0x...", "_os_log_internal": "0x..." },
  "hooks":    { "name": { "expect_target": "0x...", "sites": ["0x...", ...],
                          "default_tail": "branch:0x..." } },
  "sysctl":   { ... }                       // see configs/ for the full shape
}
```

**1. `map_base`.** Run `insert_kext info`. It prints every segment and checks
`VA == map_base + file_offset`, and refuses to go on if that does not hold,
because everything else assumes it.

**2. `slack`.** Run `insert_kext slack`. It reports the longest zero run per
segment and flags the executable ones. Take the biggest run in an `r-x`
segment.

Two cautions. Check the **page granule** — on T8150 the pages are 16 KiB, so
the `0x3ff8`-byte run is the tail of a page whose first 8 bytes are live code,
which is why the region starts at `...008`. And record what precedes it in
`preceded_by`: it is the cheapest check that you are looking at the image the
config was written for.

Is the slack really free? On T8150 it is deterministic linker padding — the
same `0x3ff8` appears in a *different device's* kernelcache of the same build,
despite different segment sizes, both ending in the same 16 bytes. On a new
target, treat it as unproven until a kext that only logs has run.

**3. `symbols`.** iOS kernelcaches export essentially nothing, so this is
manual work. What works:

* **Format-string convergence.** Collect every format-like C string, xref each
  from executable memory via `adrp`/`add`, follow to the next `BL`, and
  histogram the targets. `panic` and the loggers stand out by thousands of
  callers.
* **Watch for auth stubs.** A `BL` target that disassembles to
  `adrp x17 / add x17 / ldr x16,[x17] / braa x16,x17` is a stub, not a
  function. Read the quadword at the GOT address and take
  `map_base + (word & 0xffffffff)`. Skipping this splits one function into two
  apparent ones.
* **Confirm by shape, not by count.** A histogram is a lead; the body is the
  proof.
* **Confirm loggers empirically.** Take a string you have actually watched
  leave `dmesg`, xref it, and see what its call site calls. That also proves
  the output reaches you.
* **Validate a scanner against a known positive before trusting a negative.**
  These scanners have imperfect recall; a zero from one is not absence.

**4. `hooks`.** Find call sites you can prove execute. `expect_target` makes
the injector refuse if the instruction is not the branch you think it is.

**5. `sysctl`.** The addresses to find are the parent node's children list
(`&sysctl__debug_children`, which is the `debug` node's `oid_arg1`), a
reference OID to copy PAC fields from, and `sysctl_handle_int`. The staging
region is whatever padding your image has after the last `__DATA_CONST`
section; the tool will tell you if it overlaps anything.

---

## Layout

```
insert_kext.py        the CLI and the injector
ikext/macho.py        Mach-O, chained fixups, chain_insert
ikext/image.py        .ipsw / IM4P / Mach-O normalisation, decompression
ikext/ksysctl.py      static sysctl OID registration
kext/hello.c          the example kext
kext/start.S          entry thunks, the position-independence anchor
kext/include/         the SDK headers
configs/              one JSON per kernelcache
```

## Licence

Apache 2.0. See `LICENSE`.
