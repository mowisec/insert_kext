# Project instructions for AI agents: insert_kext

## What this project is

A standalone tool that compiles C into a freestanding blob, splices it into an
iOS kernelcache's unused space, rewires an instruction so it runs, optionally
registers a `sysctl` node for it, and packages the result as a bootable IM4P.

Read `README.md` first. It is the specification as well as the manual: the
"why" behind every refusal in the code is written there, and a change that
makes the tool accept something it currently refuses needs the README's
reasoning addressed, not just the check deleted.

## Scope

This repository is **only** about getting code into a kernelcache and making it
run. Nothing else belongs here. If a task needs something outside that — a
different kind of image, a different device workflow, tooling that consumes the
result — it belongs in a separate repository.

Do not add references to other projects, private research, internal document
numbers, issue identifiers, or device-specific workflows from elsewhere.
Everything in this repository must be readable on its own by someone who has
only this repository.

## The rules the code is built on

These are not style preferences. Each one exists because its absence produced a
wrong image that looked right.

* **Every write asserts what it is overwriting first.** The slack must still be
  all zeros, `preceded_by` must still match, a hooked instruction must still be
  the branch `expect_target` names, the sysctl list head must still be zero. A
  kernelcache that does not match the config fails the build rather than
  producing a bad image. Never relax one of these to make a build pass — a
  failing assertion means the config and the image disagree, and that is the
  finding.
* **Position independence is proved by the build, not by a boot.** Three links,
  two of them one MiB apart, byte-identical except for `kp_link_va`. If you
  change the link step, that property has to survive.
* **No trap placeholder may survive in a packaged blob**, reachable or not.
  Every one exists to be patched by exactly one code path, so a survivor means
  a path did not run for this build mode.
* **The detour classifier refuses on doubt.** A wrongly-permitted PC-relative
  instruction is a silently miscomputed address, not a crash. It is
  differential-tested against `llvm-objdump`; run `selftest` after touching it.
* **Chain surgery is verified by re-walking, never by arithmetic.**
  `chain_insert` re-walks the page and requires exactly the old chain plus one
  new offset. Plausible arithmetic that is wrong stops a page of pointers from
  being rebased with nothing looking wrong.
* **The build tag is random and is stamped on every image.** Do not make it
  content-derived: two byte-identical builds should still be distinguishable in
  a log. Do not add a way to skip it.

## What is proven and what is not

Say which, in the README and in commit messages, and do not let the two blur.

* **Proven on hardware:** slack injection, the hook trampoline, the detour, the
  uncompressed-IM4P packaging, `os_log` reaching `dmesg` from injected code, and
  the runtime `sysctl` registration — node registered, read back, repeatable,
  handler logging on every read.
* **Not established:** the detour has been booted, but only at a function entry
  (`pacibsp`). Nothing else here is unproven; when you add something that is,
  say so in this list and in README.md, and keep saying it until a device says
  otherwise.

A negative result from an experiment that was never run is not a negative
result. If you cannot test something, write down what would test it.

## Working on the code

* Python 3.9+, standard library only. Do not add dependencies. `ipsw` is
  reached through `subprocess` and only for LZFSE decompression; keep it
  optional.
* The kext side is compiled `-ffreestanding -mgeneral-regs-only
  -mbranch-protection=bti -fno-jump-tables -Werror`. Do not weaken those: each
  flag corresponds to a rule in `kext/include/kpayload.h`.
* Addresses in configs are strings like `"0xfffffe..."` and are converted on
  load. Keep them that way — a JSON integer that large is unreadable in a diff.
* `zsh` truncates 16-digit hex in `$(( ))`. Compute VAs in Python.

## Verifying a change

```bash
python3 insert_kext.py info     <image>
python3 insert_kext.py selftest <image> --va <r-x VA> --size 0x20000
python3 insert_kext.py insert   <image> --hook <name> --sysctl insert_kext -o /tmp/t.im4p
python3 insert_kext.py verify   <image> /tmp/t.raw
```

`verify` should show the kext blob, one 4-byte branch per hook site, the sysctl
OID and its strings, one or two chained-fixup `next` repairs, and the build tag
in both copies of the version string. Anything else is a bug.

## Adding a config for a new kernelcache

Follow README.md, "Porting to another kernelcache". Two things agents get wrong:

* **Symbol absence does not prove a feature is compiled out**, and **strings do
  not prove one is compiled in.** iOS kernelcaches name only exported KPI.
* **Do not guess an address.** If you cannot establish one, leave it out and say
  so. A wrong `KADDR_` is a panic on a device someone else has to recover.
