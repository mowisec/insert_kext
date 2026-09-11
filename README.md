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
$ sysctl -d debug.insert_kext
debug.insert_kext: insert_kext example node
$ dmesg | grep insert_kext
hello from insert_kext (boot hook), slide=000000002ee78000
hello from insert_kext (sysctl), slide=000000002ee78000
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
handler is your `payload_sysctl`. Nothing is spliced for it: the kext calls
the kernel's own `sysctl_register_oid` from `payload_main`, once, and the
kernel does the rest.

**Verified on hardware.** `sysctl debug.insert_kext` returns its value,
repeatably; `sysctl -d` returns its description; and the handler logs to
`dmesg` on every read.

### Why it is done that way, which took two panics to learn

The first version registered the OID **at build time** — wrote a
`struct sysctl_oid` into `__DATA_CONST` and pointed the parent's list head at
it — on the theory that a runtime call was impossible, because a
`sysctl_oid_list` head lives next to its parent node in `__DATA_CONST`, which
is read-only once boot has finished.

That theory is wrong, and XNU has the answer built in. The first entry in a
node's children list can be an `__anchor__(_name)` OID with
`oid_number == INT_MIN`, and `sysctl_register_oid_locked` then takes
`anchor->oid_arg1` as a **second** children list. For `debug` that list is in
`__DATA,__bss` — writable at runtime — and every `OID_AUTO` registration is
routed there rather than into the `__DATA_CONST` head. Runtime registration
was available all along.

The build-time version also did not work. It registered — `sysctl -N debug`
listed the node — but reading it panicked:

```
panic(cpu 3): PAC failure from kernel with IA key while branching to x23
x22 = the OID, exactly where the build put it
x19 = &oid->oid_handler with its top 16 bits cleared
```

The pointer's target was right and the modifier the call site used was
bit-for-bit what the build had assumed. The build had asked the chained-fixup
loader to produce an address-blended `IA` signature by setting `addrDiv=1,
diversity=0`, and what it produced was not what the CPU would authenticate —
even though that exact encoding appears 24477 times in the stock image.

**The lesson is the design, not the diagnosis: do not ask a third party to
produce a signature you could produce yourself.** The kext now signs the two
pointers with `pacda` and `pacia`, executed by the CPU that will later
authenticate them:

| field | key | modifier |
|---|---|---|
| `oid_parent` | DA | `blend(&oid->oid_parent, 0xdb49)` — what `sysctl_register_oid_locked` authenticates it with |
| `oid_handler` | IA | the constant `0x0e2e`, **no** address blend — the form a shipped image stores |

and hands the OID to `sysctl_register_oid`, which re-signs the handler with the
address blend exactly as it does for the kernel's own 60 `debug` OIDs. There is
nothing left to get wrong that the kernel does not already get wrong for
itself.

This is the same discipline the `sysent` patcher in the tool this grew out of
already had, and which the splice violated: **never construct PAC fields.**
Copy them from a reference the image already contains, or have the CPU make
them.

### Two things the kernel will refuse

Both cost a boot, and both are cheap to avoid:

* **`CTLFLAG_PERMANENT` is not yours to set.** `sysctl_register_oid` panics
  with *"Use sysctl_register_oid_early to register permanent nodes"*; permanent
  nodes may only be registered from the startup path. Leaving it off is also
  better: the kernel then `zalloc`s its own copy, so `sysctl_root`'s refcount
  increment and the handler re-signing both land in writable memory.
* **`CTLFLAG_OID2` and `oid_version == 1` are checked**, and `oid_number` must
  be greater than `-2`, so `OID_AUTO` (`-1`) is the only sentinel it takes.

### Registering at the right moment

The hook fires during early boot — the panic above landed with *"OS release
type: Not set yet"* — and at that point the parent's children list may still be
empty, which is not merely early but the wrong shape: without the anchor there
is no writable list to route an `OID_AUTO` registration into.

So `ksysctl_register()` checks that the parent's list head is non-zero before
doing anything, and returns without setting its one-shot guard if it is not.
A shipped kernelcache leaves that head zero, so non-zero is exactly the signal
that the kernel's own sysctls are up. The hook fires every few seconds forever,
so the next firing simply tries again.

The OID struct and the guard word live in the config's `scratch` region,
because the kext's own memory is read-only.

## Command reference

| | |
|---|---|
| `insert <image>` | the whole pipeline: build, splice, hook, sysctl, tag, package |
| `info <image>` | segments, fileset entry count, linear-mapping check |
| `slack <image> [--min N]` | zero runs per segment, executable ones flagged |
| `build <image> [--kext ...]` | source → blob, with the position-independence proof |
| `verify <image> <patched>` | diff against stock, decoding branch targets |
| `check <image>` | ask a booted device whether the image did what `insert` said it would |
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

## Checking it on a device

`insert` writes an expectations file next to the image. `check` takes it to a
booted device and asks whether the image did what the build said it would:

```
insert_kext.py check hello.im4p --ssh "ssh -p 2222 root@localhost"
```

```
  [PASS]  booted image           ... root:xnu-13432.2.10~5/IK645C4_ARM64_T8150 ...
  [PASS]  sysctl registered      debug.insert_kext listed -- so the hook ran and payload_main registered it
  [PASS]  sysctl value           debug.insert_kext = 42
  [PASS]  sysctl description     insert_kext example node
  [PASS]  log: sysctl handler    2 line(s) matching 'insert_kext (sysctl)'

5/5 checks passed
```

Exit status is non-zero if anything failed.

Three things about it that are deliberate:

* **The build tag is checked first**, and everything else is meaningless
  without it. A patch that only misbehaves on failure is silent both when it
  works and when it never ran.
* **It is one round trip.** The kernel log ring is small and busy -- on the
  device this was written against it wraps in well under a minute -- so a
  `sysctl` read in one connection and a `dmesg` in the next will usually show
  the read having left no trace. The remote script reads the sysctl and
  captures the log immediately after, in the same shell.
* **There is no log check for the boot hook.** The hook registers the sysctl
  once and then stays quiet, so any line it printed has long since scrolled.
  The registration *is* the evidence: nothing else puts that node there.

`--tool-dir` names a directory holding `sysctl`/`dmesg` if they are not on the
device's PATH (globs allowed). The script goes over as a quoted argument rather
than down stdin, because a stripped-down device may have no working `/bin/sh`.

## Reaching the kext from userspace

Two channels, and they carry different things.

| | `--sysctl NAME` | `--syscall-slot N` |
|---|---|---|
| reached with | `sysctl debug.NAME` | `syscall(N, a, b, c)` |
| carries in | nothing | three full 64-bit arguments |
| carries out | one int | one int, through `*retval` |
| needs | `sysctl_register_oid` etc. in the config | a `sysent_table` in the config |
| kext provides | `payload_sysctl` | `payload_syscall` |

`--syscall-slot` points a **spare** `sysent` slot at the kext. It refuses any
slot the config does not list as spare, because patching a live one replaces a
syscall the system uses.

The slot is a chained-fixup pointer that the loader rebases and PAC-signs, so
the patcher rewrites only the 30-bit target and **copies every PAC field from a
reference slot the image already contains**, refusing if they disagree. That
rule is not decoration: see the sysctl section for what happened when this
project constructed PAC fields instead of copying them.

Note that the default `payload_syscall` returns `ENOSYS`, which is also what an
unpatched spare slot returns -- so a test against it cannot tell a working
channel from one nobody touched. The example kext returns a recognisable value
instead.

## Patching instructions directly

Two mechanisms, both of which refuse to write unless the bytes they expect are
already there:

```
--poke <VA>=<OLD>:<NEW>     ad-hoc, one instruction
--extra <NAME>              a named entry in the config's extra_patches
```

A stale VA -- from a re-symbolicated address, or simply a different
kernelcache -- would otherwise be patched into the wrong place silently, and
the result is a kernel that is wrong in a way no diff will look odd. So `OLD`
is mandatory and a mismatch is a build failure.

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
