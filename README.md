# insert_kext

Compile a kext from C source and put it into an iOS kernelcache.

`insert_kext` takes a kernelcache — as an `.ipsw`, an IM4P, or an already
decompressed Mach-O — compiles your code into a freestanding,
position-independent blob, splices it into unused space in the image, rewires
one or more existing instructions so it runs, optionally gives it a real
`sysctl` node and a `syscall`, stamps a random build tag into the kernel
version string, and packages the result as a bootable IM4P.

It can also add a real, named `MH_KEXT_BUNDLE` fileset entry for your code, so
the image carries an actual bundle identifier rather than only an anonymous
blob — see *Two ways in* below for what that does and does not buy you.

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
kext:   hello.c  1874 bytes, 14502 bytes of slack left
  tail:     branch:0xfffffe000b1d48b4
  0x4368008  1874 bytes  kext (entry 0xfffffe000b36c008)
  25 sites  hook 'oslog_extensible_paniclog' -> 0xfffffe000b36c008
  sysctl 'debug.insert_kext' registered at runtime by the kext (handler 0xfffffe000b36c080, reads back 42)
  build tag: IKC8EA0_ARM64_T8150   (check `uname -a` against this before believing anything)
```

On the device:

```
$ uname -a                       # must match the build tag above
Darwin ... root:xnu-...~5/IKC8EA0_ARM64_T8150 arm64
$ sysctl debug.insert_kext       # also the trigger for the IOKit part below
debug.insert_kext: 42
$ sysctl -d debug.insert_kext
debug.insert_kext: insert_kext example node
$ dmesg | grep insert_kext
hello from insert_kext (boot hook), slide=000000002ee78000
hello from insert_kext (sysctl), slide=000000002ee78000
$ ioreg -l -d 1 | grep insert_kext   # see "Reaching IOKit" for what these are
      "insert_kext" = "hello"
$ ioreg | grep insert_kext
    +-o insert_kext  <class IOService, id 0x100001012, registered, matched, active, ...>
```

**Check the build tag before believing anything.** A kext that only misbehaves
on failure is silent both when it works and when it never ran, and the tag is
what tells those apart.

---

## Two ways in, and what each gets you

There are two ways to get your own code into a finished kernelcache, and this
tool implements both.

**Slack injection** (the default) puts a raw code blob in unused space and
rewires one instruction to reach it. The file size, every offset and every
segment stay exactly as they were.

**An appended fileset entry** (`--append-kext <bundle id>`) adds a real, named
`MH_KEXT_BUNDLE` entry — a bundle identifier, its own Mach-O header, its own
segments — at the end of the image. **Nothing that already exists moves**
either: the entry's header goes in new bytes at the end and the three new load
commands go in the header's zero padding.

```bash
insert_kext.py --variant kernelcache.research.v57 \
    insert iPhone18,3_27.0_24A5424a_Restore.ipsw \
    --append-kext com.apple.testinject --prelink-bundle \
    --hook oslog_extensible_paniclog \
    --sysctl insert_kext --sysctl-value 42 \
    -o hello.im4p
```

```
kext:   hello.c  1874 bytes, 14502 bytes of slack left  appended as 'com.apple.testinject', code in the slack
  25 sites  hook 'oslog_extensible_paniclog' -> 0xfffffe000b36c008

appended fileset entry 'com.apple.testinject'
  __KEXT_EXEC    va 0xfffffe000b9b8000  fo 0x49b4000  16384 bytes  r-x
  __TEXT_EXEC  va 0xfffffe000b36c008  fo 0x4368008  1874 bytes  <- the code
  ncmds 315 -> 317, file 77283328 -> 77299712 (+16384)

== the emitted image  (77299712 bytes)
  19 checks passed, 0 failed

__PRELINK_INFO: added bundle 'com.apple.testinject'
  320 -> 321 bundles, plist 2558342 -> 2559725 bytes, 12563 bytes of padding left

covered the appended 16384 bytes by growing the last region: kclz 802816 -> 819200
```

Note where the two halves land: the entry's **header** is appended, and its
**code** is in the slack, because appended bytes cannot be made executable —
see below. `--prelink-bundle` additionally registers it in `__PRELINK_INFO`.
Everything else is as for slack injection, so `--sysctl`, `--syscall-slot`,
`--detour` and the rest all still apply.

| | slack injection | `--append-kext` |
|---|---|---|
| your code runs in the kernel | yes | yes |
| a named bundle in the image | no | **yes** |
| image geometry | unchanged | unchanged |
| code size limit | the image's slack (16376 bytes on T8150) | the same — see below |
| `__PRELINK_INFO` dictionary | no | with `--prelink-bundle` |
| listed by `kextstat` | no | **no** |
| matched as a driver by a personality | no | **no** |

### Where an appended kext's code has to live, and why

Appended bytes can be **mapped** but not made **executable**: the IM4P region
table has exactly two executable regions, both already spoken for, and every
attempt to resize or relocate one is refused before the kernel runs. Four of
the five region sizes refuse even a one-page change. An appended `__TEXT_EXEC`
would therefore take an instruction-fetch permission fault the moment anything
called it.

So `--append-kext` splits the entry in two: its **code** goes in the slack,
which is already inside an executable region and already runs, and only its
**header page** is appended — covered by growing the last region, the one size
that may change. You get the named bundle and the code, at the slack's size
limit. This is not configurable, because only one arrangement loads.

### What "kext" means here

Your code, running in the kernel, calling kernel functions, answering a
`sysctl` and a `syscall`, and — as the example kext shows — reaching IOKit well
enough to publish a property and register an `IOService` node that shows up in
`ioreg`.

What it is **not** is a driver. The bundle is not listed by `kextstat`: that
listing enumerates *loaded* kexts, and being loaded needs a `kmod_info`
structure with PAC-signed `start`/`stop` pointers in writable memory, which an
appended entry does not have. Nothing matches a personality, and the
`IOService` the example registers is a stock one with no methods of its own.
If you need driver matching, this is still the wrong tool.

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

Build it with `--kext yourfile.c` (repeatable). See `kext/hello.c`, which also
shows a `payload_syscall` and two IOKit examples — see *Reaching IOKit*.

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
| `props <image>` | the IM4P `kc*` region table, and whether it still covers the payload |
| `package <image> -o ...` | wrap an already-patched Mach-O as a bootable IM4P |
| `slack <image> [--min N]` | zero runs per segment, executable ones flagged |
| `build <image> [--kext ...]` | source → blob, with the position-independence proof |
| `verify <image> <patched>` | diff against stock, decoding branch targets |
| `check <image>` | ask a booted device whether the image did what `insert` said it would |
| `selftest <image>` | the detour classifier against `llvm-objdump` |

**Global flags go before the subcommand, everything else after it.**
`--config`, `--variant`, `--stock-im4p` and `--set-prop` belong to the program;
`--append-kext`, `--hook`, `--sysctl` and the rest belong to `insert`. Putting
a subcommand flag first gets you `invalid choice: 'com.apple.example'`, because
argparse reads its value as the subcommand name:

```bash
insert_kext.py --variant kernelcache.research.v57 \
    insert iPhone18,3_27.0_24A5424a_Restore.ipsw \
    --append-kext com.apple.testinject --prelink-bundle \
    --hook oslog_extensible_paniclog \
    --sysctl insert_kext --sysctl-value 42 \
    -o hello.im4p
```

Global options: `--config` (auto-selected by content if omitted), `--variant`
(which kernelcache to take out of an `.ipsw`), `--stock-im4p` (where to get the
IM4P properties element when the input is a bare Mach-O), `--set-prop
NAME=VALUE` (rewrite one `kc*` property before packaging).

`insert` options for an appended entry: `--append-kext <bundle id>` and
`--prelink-bundle`. There is nothing to tune: where the header goes, where the
code goes and which region covers the header are all forced by what the loader
accepts, so the tool does the one thing that works rather than offering choices
that do not.

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
  [PASS]  syscall channel        syscall(8, 0x11, ...) = 1262813201
  [PASS]  ioreg property         "insert_kext" = "hello"
  [PASS]  ioreg node             +-o insert_kext  <class IOService, id 0x10000117c, registered, matched, active, ...>
  [PASS]  log: syscall handler   1 line(s) matching 'insert_kext (syscall)'
  [PASS]  log: sysctl handler    2 line(s) matching 'insert_kext (sysctl)'

9/9 checks passed
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
* **The IOKit probes run after the sysctl read**, because in the example kext
  the sysctl handler is what reaches IOKit. Probing first would correctly find
  nothing.
* **A missing `ioreg` is a skip, not a failure.** An absent probe tool says
  nothing about the image, the same reasoning as the `perl`-less syscall case.
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

## Reaching IOKit

`kext/hello.c` shows two things an injected kext can do to the IO registry,
both called from the sysctl handler so a read triggers them on demand:

```c
/* a property on the registry root */
root = IORegistryEntry::getRegistryRoot();
IORegistryEntry::setProperty(root, "insert_kext", "hello");

/* an actual node */
obj = OSMetaClass::allocClassWithName("IOService");
IOService::init(obj, NULL);
IORegistryEntry::setName(obj, "insert_kext", NULL);
IOService::attach(obj, IOService::getServiceRoot());
IOService::registerService(obj, 0);
```

Both compile away unless the addresses are in the config's `symbols` map, so
this costs nothing on an image you have not resolved them for.

### Seeing it with `ioreg`

**Read the sysctl first.** Nothing exists in the registry until something calls
the code, and in the example kext the sysctl handler is what does. Run `ioreg`
before that and you will correctly see nothing:

```
$ ioreg | grep insert_kext            # nothing yet -- the code has not run
$ sysctl debug.insert_kext            # this is the trigger
debug.insert_kext: 42
```

Now both are visible. They live in different places, so they need different
commands:

```
$ ioreg -l -d 1 | grep insert_kext    # -d 1 = the root node only, -l = with properties
      "insert_kext" = "hello"

$ ioreg | grep insert_kext            # the node tree; no -l, so only names match
    +-o insert_kext  <class IOService, id 0x100001012, registered, matched, active, busy 0 (1 ms), retain 6>
```

The full root node, for context — the property sits among the kernel's own:

```
$ ioreg -l -d 1
+-o Root  <class IORegistryEntry, id 0x100000100, retain 47>
    {
      "IOKitBuildVersion" = "Darwin Kernel Version 27.0.0: ... /IKF8312_ARM64_T8150"
      "OS Build Version" = "24A5424a"
      ...
      "insert_kext" = "hello"
```

Reading the node's line:

| | |
|---|---|
| `class IOService` | the stock class — the object was allocated by the runtime, not defined by you |
| `registered` | `registerService()` completed |
| `matched` | matching ran against it. It found nothing, because there is no personality; this does **not** mean a driver bound |
| `active` | attached to the plane and not terminated |
| `retain 6` | the registry's own references |

`ioreg -l` on its own prints the whole tree with every property, which is
megabytes; `grep` it or use `-d <depth>` to bound it. If the node is not there
after a sysctl read, check `dmesg | grep "insert_kext (node)"` — each failure
step logs its own line rather than failing silently.

On a stripped-down device `ioreg` may not be on the default `PATH`; it is a
diagnostics tool and lives wherever that device keeps them, the same place
`check --tool-dir` points at for `sysctl` and `dmesg`.

### It defines no C++ class, and that is deliberate

An `IOService` subclass of your own means emitting a vtable, and on arm64e a
vtable is a table of **signed pointers**. Producing those by hand is the same
mistake the sysctl section above cost two panics to learn.

Asking the runtime to allocate an instance of a class it **already knows**
avoids it entirely: the object comes back with the kernel's own vtable,
correctly signed, and every call above then goes straight to the concrete
implementation that virtual dispatch on that object would have reached anyway.
Nothing is signed by you.

The limit of that trick is that the node has no behaviour of its own — it is a
stock `IOService`. Giving it methods means a vtable in writable memory with
entries re-signed for the right key and discriminator, and that is the first
thing in this tool that you would have to sign yourself.

### Get C++ addresses from the vtable, not from a name match

Worth stating separately, because it is what makes these calls land instead of
panicking. For the methods above, a symbol table scored:

| method | confidence |
|---|---|
| `IOService::attach(IOService*)` | 0.28 |
| `IOService::registerService(unsigned int)` | 0.42 |
| `IOService::init(OSDictionary*)` | absent |

None of that is callable blind — a wrong address here passes arguments to the
wrong function. A tool that recovers class vtables from an arm64e kernelcache
by their PAC diversifiers (`iometa` is the one used here) gives the entries
**exactly**, and in this case its values matched the low-confidence symbols, so
the two independent methods corroborated each other and the missing `init` came
for free.

For a **non-virtual** function there is no slot to read, so verify it another
way: `OSMetaClass::allocClassWithName(char const*)` was confirmed by what it
calls — `OSSymbol::withCStringNoCopy` and then the `OSSymbol*` overload — which
nothing else does. A fully symbolicated kernel for a different platform of the
same vintage is also a good cross-check for overload sets, where order and
relative size are stable even though addresses are not.

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
compression descriptor. iBoot also needs the 15 `kc*` properties (segment
sizes, `kclo`, `kcep`) that the stock image carries, so the stock IM4P's
properties element (DER tag `0xa0`) is spliced onto the new one rather than
regenerated. That is why the tool wants the IM4P or the `.ipsw` rather than a
bare Mach-O.

How you get a personalised, signed image onto a device is outside this tool's
scope and depends on what the device lets you do.

---

## Porting to another kernelcache

Everything the tool knows about a particular image is one JSON file in
`configs/`, chosen **by content**: `insert` hashes the decompressed Mach-O and
matches `identify.sha256`, so a config can never be silently applied to the
wrong image.

The work splits into a mechanical half the tool does for you, and a manual half
that is the real cost. Below in the order to do it.

```jsonc
{
  "identify":  { "sha256": "...",                 // of the DECOMPRESSED Mach-O
                 "marker": "RELEASE_ARM64_T8150" },
  "map_base":  "0xfffffe0007004000",              // VA = map_base + file_offset
  "slack":     { "file_off": "...", "va": "...", "size": 16376,
                 "preceded_by": "bf4100d5c0035fd6" },
  "build_tag": { "stock": "RELEASE_ARM64_T8150", "prefix": "IK", "count": 2 },
  "symbols":   { "panic": "0x...", ... },         // the work
  "hooks":     { "name": { "expect_target": "0x...", "sites": ["0x...", ...],
                           "default_tail": "branch:0x..." } },
  "sysctl_parent_path": "debug",
  "sysent_table":  { ... },                       // optional, for --syscall-slot
  "extra_patches": { ... }                        // optional, for --extra
}
```

### The mechanical half — minutes

**1. `identify`.** `sha256` of the decompressed kernelcache. `marker` is a
fallback that identifies the build but not the exact image, so a marker-only
match warns and every address should be re-derived before it is trusted.

**2. `map_base`.** Run `insert_kext info`. It prints every segment, checks
`VA == map_base + file_offset`, and **refuses to go on if that does not hold**,
because everything else assumes it.

**3. `slack`.** Run `insert_kext slack`. It reports the longest zero run per
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

**4. `build_tag`.** `stock` is the configuration field of the kernel version
string, which `info` shows. It is replaced in place at the same length, so
`uname -a` names exactly which image booted.

### The manual half — where the hours go

**5. `symbols`: plain C functions.** iOS kernelcaches export essentially
nothing, so this is manual. What works:

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

**6. `symbols`: C++ methods.** The IOKit entry points need a different method,
and guessing here is expensive — a wrong address passes your arguments to the
wrong function. In descending order of strength:

* **A virtual method: read the class vtable.** A tool that recovers C++ class
  layouts from an arm64e kernelcache by their PAC diversifiers (`iometa` is the
  one used for the shipped config) gives the entries **exactly**, with real
  names:

  ```
  0x0a8 func=0x...  IOService::init(OSDictionary*)
  0x2a0 func=0x...  IOService::registerService(unsigned int)
  0x360 func=0x...  IOService::attach(IOService*)
  ```

  This is worth doing even when a symbol table offers a name. For the shipped
  config it scored `attach` at **0.28** and `registerService` at **0.42** and
  had no `init` at all — not callable blind — while the vtable gave all three,
  and its values matched the two low-confidence symbols, so the methods
  corroborated each other.

* **A non-virtual overload set: differential against a symbolicated kernel.**
  `IORegistryEntry::setProperty` has six overloads at consecutive addresses,
  all scoring ~0.42, and disassembly cannot separate them: each calls only
  `OSSymbol::withCString` for the key and reaches its value constructor
  indirectly. A fully symbolicated kernel for another platform of the same
  vintage names all of them, and both the **order** and the **size pattern**
  carry over even though the addresses do not (85/85/54/54/40/40 there against
  71/71/48/46/34/38 in the release build — uniformly tighter, same shape).

* **Anything else: verify by behaviour.** `OSMetaClass::allocClassWithName` is
  not virtual, so it has no slot. It was confirmed by what it calls —
  `OSSymbol::withCStringNoCopy`, then the `OSSymbol*` overload — which nothing
  else does.

**7. `hooks`.** Find a call site you can prove executes, and prefer one whose
message you have **watched leave `dmesg`**, so the site is known to run and its
context is known safe for what the kext wants to do. `expect_target` makes the
injector refuse if the instruction is not the branch you think it is. A hook
may name several sites and all are retargeted — if you are not certain which
copy of an inlined function runs, hook them all rather than gambling a reboot.

**8. `sysctl_parent_path` and `scratch`.** The addresses to find are the parent
node's children list (`&sysctl__debug_children`, which is the `debug` node's
`oid_arg1`), `sysctl_register_oid` and `sysctl_handle_int`. `scratch` is
writable memory for the OID and the one-shot guards — whatever padding your
image has after the last `__DATA_CONST` section; the tool will tell you if it
overlaps anything.

**9. `sysent_table`** (only for `--syscall-slot`) and **`extra_patches`** (only
for `--extra`) are optional. Nothing else needs them.

### Prove as much as possible without booting

Every one of these runs against the image on your desk, and each has caught a
real error:

```bash
insert_kext.py info <image>        # map_base, and the linear-mapping invariant
insert_kext.py slack <image>       # that the slack is where you think
insert_kext.py build <image>       # the position-independence proof
insert_kext.py selftest <image>    # the detour classifier vs llvm-objdump
insert_kext.py verify <image> <patched>   # every changed byte, branches decoded
```

`insert` itself asserts what it overwrites: the slack must still be zeros, the
bytes before it must match `preceded_by`, a hooked instruction must still be
the branch `expect_target` names. A config that does not match its image fails
the build rather than producing a bad image.

### What you do *not* need

`--append-kext` and `--prelink-bundle` need **no extra config**. The fileset
entry, the region covering it and the `__PRELINK_INFO` dictionary are all
derived from the image itself.

### What to expect

The mechanical half is minutes. The symbols are the cost, and how much depends
on distance: a kernelcache of the **same build for a different device** is the
easy case — same structure, different addresses, and every technique above
transfers directly. A different iOS version is harder, because signatures
drift. There is no button to press.

Start with the smallest config that can do anything: `map_base`, `slack`,
`build_tag`, and just `_os_log_internal` plus its two globals. That is enough
for a kext that only logs, which is also the experiment that tells you whether
the slack is really free.

## Layout

```
insert_kext.py        the CLI and the injector
ikext/macho.py        Mach-O, chained fixups, chain_insert
ikext/image.py        .ipsw / IM4P / Mach-O normalisation, kc* region table
ikext/fileset.py      appending a fileset entry, and __PRELINK_INFO
ikext/sysent.py       the spare-syscall-slot patcher
kext/hello.c          the example kext
kext/start.S          entry thunks, the position-independence anchor
kext/include/         the SDK headers
configs/              one JSON per kernelcache
```

## Licence

Apache 2.0. See `LICENSE`.
