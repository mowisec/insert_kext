#!/usr/bin/env python3
"""insert_kext - compile a kext from source and put it into an iOS kernelcache.

    insert_kext.py insert <image> [options]      the whole pipeline
    insert_kext.py info    <image>               segments, entries, geometry
    insert_kext.py slack   <image>               where a kext could go
    insert_kext.py build   <image> [--kext ...]  source -> blob only
    insert_kext.py verify  <image> <patched>     diff, with branches decoded
    insert_kext.py selftest <image>              the detour classifier vs objdump

`<image>` is an .ipsw, an IM4P, or an already-decompressed kernelcache; all
three are normalised to the same thing before anything else happens.

Design notes that matter if you port this:

  * A kernelcache of this era is an MH_FILESET that maps LINEARLY, so
    `VA = map_base + file_offset` for every segment.  `info` checks that and
    refuses to continue if it is not true, because everything else assumes it.
  * The kext is LINKED at the static VA it will occupy.  Internal references
    are then PC-relative and survive KASLR untouched; external references are
    static VAs plus a slide the kext measures at runtime.
  * Every write asserts what it is overwriting first.  A kernelcache that does
    not match the config fails the build rather than producing a bad image.
  * Every image gets a RANDOM build tag spliced into its version string, so
    `uname -a` on the device names exactly which build booted.  It is random
    rather than derived from the contents on purpose: two builds that happen to
    be byte-identical should still be distinguishable in a log.
"""
import argparse, json, os, re, secrets, shlex, struct, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ikext import fileset, image as imageio, sysent
from ikext.macho import MachO, chained_fixups

HERE = os.path.dirname(os.path.abspath(__file__))
KEXT_DIR = os.path.join(HERE, "kext")
CONFIG_DIR = os.path.join(HERE, "configs")

KP_ORIG_PLACEHOLDER = 0xd4200000 | (0xfee0 << 5)      # brk #0xfee0
KP_TAIL_PLACEHOLDER = 0xd4200000 | (0xfeed << 5)      # brk #0xfeed
TRAP_PLACEHOLDERS = (0xfee0, 0xfeed)


# ----------------------------------------------------------------- config ---

def _num(o):
    if isinstance(o, dict):
        return {k: _num(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_num(v) for v in o]
    if isinstance(o, str) and re.fullmatch(r"0x[0-9a-fA-F]+", o):
        return int(o, 0)
    return o


def load_config(path):
    cfg = _num(json.load(open(path)))
    cfg["_path"] = os.path.abspath(path)
    return cfg


def pick_config(img, explicit):
    """Choose the config for this image, by content rather than by filename."""
    if explicit:
        return load_config(explicit)
    import hashlib
    sha = hashlib.sha256(img["raw"]).hexdigest()
    cands = []
    for fn in sorted(os.listdir(CONFIG_DIR)):
        if not fn.endswith(".json"):
            continue
        cfg = load_config(os.path.join(CONFIG_DIR, fn))
        ident = cfg.get("identify", {})
        if ident.get("sha256") == sha:
            return cfg
        marker = ident.get("marker")
        if marker and marker.encode() in img["raw"]:
            cands.append(cfg)
    if len(cands) == 1:
        print(f"config: {os.path.basename(cands[0]['_path'])} "
              f"(matched on {cands[0]['identify']['marker']!r}, not on sha256 -- "
              "this is a DIFFERENT build of the same kernel, so every address "
              "below is unverified)", file=sys.stderr)
        return cands[0]
    if not cands:
        raise SystemExit(
            f"no config in {CONFIG_DIR} matches this image (sha256 {sha[:16]}...).  "
            "Write one: see README.md, 'Porting to another kernelcache'.")
    raise SystemExit("several configs match; choose one with --config: "
                     + ", ".join(os.path.basename(c["_path"]) for c in cands))


# ------------------------------------------------------------- arm64 bits ---

def enc_branch(frm, to, link):
    off = (to - frm) >> 2
    if not -(1 << 25) <= off < (1 << 25):
        raise SystemExit(f"branch {frm:#x} -> {to:#x} is out of +-128 MB range")
    return (0x94000000 if link else 0x14000000) | (off & 0x3ffffff)


def dec_branch(word, at):
    if word & 0xfc000000 not in (0x94000000, 0x14000000):
        return None
    imm = word & 0x3ffffff
    if imm & (1 << 25):
        imm -= 1 << 26
    return at + imm * 4


def pc_relative(w):
    """Name the PC-relative instruction `w` is, or None if it is not one.

    A detour moves the displaced instruction into the kext, so anything whose
    result depends on where it sits computes something different there.  The
    classifier is deliberately conservative: it refuses on doubt.
    """
    if (w & 0x7c000000) == 0x14000000:
        return "B/BL"
    if (w & 0xff000010) == 0x54000000:
        return "B.cond"
    if (w & 0x7e000000) == 0x34000000:
        return "CBZ/CBNZ"
    if (w & 0x7e000000) == 0x36000000:
        return "TBZ/TBNZ"
    if (w & 0x1f000000) == 0x10000000:
        return "ADR/ADRP"
    if (w & 0x3b000000) == 0x18000000:
        return "literal-pool load (LDR/LDRSW literal)"
    if (w & 0x3e000000) == 0x1c000000:
        return "literal-pool load (SIMD)"
    return None


# ------------------------------------------------------------------ info ----

def cmd_info(cfg, img, args):
    m = MachO(img["raw"])
    base = cfg["map_base"]
    print(f"{img['source']}  ({img['name']})")
    print(f"filetype {m.filetype:#x}  {len(m.fileset)} fileset entries  "
          f"map_base {base:#x}  {len(img['raw'])} bytes")
    print(f"{'segment':<18}{'file':>22}  {'VA':>18}  prot  linear?")
    ok = True
    for s in m.segs:
        lin = (s["va"] == base + s["foff"])
        ok &= lin or s["fsize"] == 0
        print(f"{s['name']:<18}{s['foff']:#010x}-{s['foff']+s['fsize']:#010x}  "
              f"{s['va']:#018x}  {m.prot(s)}   {'yes' if lin else 'NO'}")
    if not ok:
        raise SystemExit("image is not linearly mapped; insert_kext assumes it is")
    print("all segments satisfy VA = map_base + file_offset")


# ----------------------------------------------------------------- slack ----

def zero_runs(buf, lo, hi, minlen):
    runs, start = [], None
    for i in range(lo, hi):
        if buf[i] == 0:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= minlen:
                runs.append((start, i - start))
            start = None
    if start is not None and hi - start >= minlen:
        runs.append((start, hi - start))
    return runs


def cmd_slack(cfg, img, args):
    d = img["raw"]
    m = MachO(d)
    base = cfg["map_base"]
    print(f"{'segment':<18}{'prot':<6}{'longest zero run':>20}  file        VA")
    for s in m.segs:
        if not s["fsize"]:
            continue
        runs = zero_runs(d, s["foff"], s["foff"] + s["fsize"], args.min)
        if not runs:
            print(f"{s['name']:<18}{m.prot(s):<6}{'-':>20}")
            continue
        off, n = max(runs, key=lambda r: r[1])
        note = "  <- executable" if s["initprot"] & 4 else ""
        print(f"{s['name']:<18}{m.prot(s):<6}{n:#20x}  {off:#010x}  "
              f"{base+off:#x}{note}")


# ----------------------------------------------------------------- build ----

CFLAGS = [
    "-arch", "arm64", "-O2", "-std=c11",
    "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-common",
    "-mgeneral-regs-only",              # a hooked context may not have saved FP/SIMD
    "-mbranch-protection=bti",          # the kernel runs with BTI on; emit landing pads
    "-fno-jump-tables",                 # a jump table would need writable/relocated data
    "-Wall", "-Wextra", "-Werror",
]


def _link(cfg, srcs, base, tmp, tag, defines=None):
    inc = os.path.join(KEXT_DIR, "include")
    gen = os.path.join(tmp, "kaddrs.h")
    if not os.path.exists(gen):
        with open(gen, "w") as f:
            f.write("/* generated by insert_kext from the config; do not edit */\n"
                    "#ifndef KADDRS_H\n#define KADDRS_H\n")
            for k, v in cfg.get("symbols", {}).items():
                f.write(f"#define KADDR_{k} {v:#x}ULL\n")
            for k, v in (defines or {}).items():
                f.write(f"#define {k} {v}\n")
            f.write("#endif\n")

    def compile(s_):
        o = os.path.join(tmp, tag + "_" + os.path.basename(s_) + ".o")
        subprocess.run(["xcrun", "clang", "-c", "-o", o, s_, *CFLAGS,
                        "-I", inc, "-I", tmp], check=True)
        return o

    objs = [compile(os.path.join(KEXT_DIR, "start.S"))] + [compile(s) for s in srcs]
    defined = subprocess.run(["xcrun", "nm", "-g", "--defined-only", *objs[1:]],
                             capture_output=True, text=True).stdout \
        if len(objs) > 1 else ""
    if "_payload_sysctl" not in defined:
        objs.append(compile(os.path.join(KEXT_DIR, "nosysctl.S")))
    if "_payload_syscall" not in defined:
        objs.append(compile(os.path.join(KEXT_DIR, "nosyscall.S")))

    macho = os.path.join(tmp, tag + ".macho")
    # -segalign 4 so the segment may start at an arbitrary word address: the
    # slack we are aiming at is deliberately not page aligned.
    subprocess.run(["xcrun", "ld", "-arch", "arm64", "-static", "-e", "_kp_entry",
                    "-o", macho, "-segalign", "0x4",
                    "-segaddr", "__TEXT", f"{base:#x}",
                    "-no_uuid", *objs], check=True)
    m = MachO(open(macho, "rb").read())
    for seg in m.segs:
        if seg["name"] not in ("__TEXT", "__LINKEDIT", "__PAGEZERO") and seg["vsize"]:
            raise SystemExit(f"the kext has a non-empty {seg['name']} "
                             f"({seg['vsize']} bytes).  Injected code cannot have "
                             "writable or relocated data; see kext/include/kpayload.h.")
    texts = [x for x in m.sects if x["seg"] == "__TEXT"]
    if not texts:
        raise SystemExit("the linked kext has no __TEXT sections")
    lo = min(x["foff"] for x in texts)
    hi = max(x["foff"] + x["size"] for x in texts)
    seg = next(x for x in m.segs if x["name"] == "__TEXT")
    return (bytearray(open(macho, "rb").read()[lo:hi]), m.syms,
            seg["va"] + (lo - seg["foff"]))


def build_blob(cfg, srcs, defines=None, target=None):
    """Source -> raw blob, linked to sit exactly where it will be spliced.

    Three links.  The first is a probe, only to measure how far into __TEXT the
    Mach-O header pushes the first section, so the second can be placed such
    that the first section lands exactly on the target address.  The second and
    third are the real link and the same link one MiB higher; the two blobs
    must be byte-identical except for the `_kp_link_va` quad.

    That diff is the whole safety argument.  Injected code has to survive
    KASLR, which means it may contain no absolute address at all.  Anything
    baked in -- a pointer initialiser, a jump table, a string table of pointers
    -- moves with the link base and shows up here, so "is this really position
    independent?" is answered by the build rather than by a boot.

    The two bases differ by a multiple of the 4 KiB `adrp` page, which is what
    makes this a valid check: `adrp` encodes a page delta, so a blob relocated
    by a non-page-multiple would break silently.  Linking directly at the
    target sidesteps that entirely.
    """
    target = cfg["slack"]["va"] if target is None else target
    PROBE = 0xfffffe0000000000
    with tempfile.TemporaryDirectory() as t:
        _, _, probe_base = _link(cfg, srcs, PROBE, t, "probe", defines)
        hdr = probe_base - PROBE
        blob_a, syms_a, base_a = _link(cfg, srcs, target - hdr, t, "a", defines)
        blob_b, _, _ = _link(cfg, srcs, target - hdr + 0x100000, t, "b", defines)
    if base_a != target:
        raise SystemExit(f"linker put the kext at {base_a:#x}, wanted {target:#x}")
    if len(blob_a) != len(blob_b):
        raise SystemExit("the two links differ in size; something is address-dependent")
    quad = syms_a["_kp_link_va"] - base_a
    stray = [i for i in range(len(blob_a))
             if blob_a[i] != blob_b[i] and not (quad <= i < quad + 8)]
    if stray:
        raise SystemExit(
            "the kext is NOT position-independent: bytes "
            + ", ".join(f"{i:#x}" for i in stray[:16])
            + (" ..." if len(stray) > 16 else "")
            + " change with the link address.  Look for an absolute pointer, a "
              "jump table, or a relocated initialiser.")
    if struct.unpack_from("<Q", blob_a, quad)[0] != target:
        raise SystemExit("_kp_link_va does not hold the target address")
    meta = dict(base=target, size=len(blob_a),
                entry=target + syms_a["_kp_entry"] - base_a,
                orig=target + syms_a["_kp_orig"] - base_a,
                tail=target + syms_a["_kp_tail"] - base_a,
                sysctl_entry=target + syms_a["_kp_sysctl_entry"] - base_a,
                syscall_entry=target + syms_a["_kp_syscall_entry"] - base_a)
    return blob_a, meta


def cmd_build(cfg, img, args):
    blob, meta = build_blob(cfg, args.kext or [os.path.join(KEXT_DIR, "hello.c")])
    room = cfg["slack"]["size"] - len(blob)
    print("position-independent: only _kp_link_va differs between links 1 MiB apart")
    print(f"blob {len(blob)} bytes at {meta['base']:#x}  entry {meta['entry']:#x}  "
          f"sysctl {meta['sysctl_entry']:#x}")
    print(f"{room} bytes of slack left over")
    if room < 0:
        raise SystemExit("the kext does not fit the slack")
    if args.out:
        open(args.out + ".bin", "wb").write(bytes(blob))
        json.dump(meta, open(args.out + ".json", "w"), indent=2)
        print(f"wrote {args.out}.bin / {args.out}.json")
    return blob, meta


# ---------------------------------------------------------------- detour ----

def apply_detour(d, blob, meta, base, va):
    """Replace the instruction at `va` with a branch to the kext.

    The kext runs, restores the full context including x9-x18 and NZCV,
    executes the displaced instruction out of _kp_orig, and branches back to
    va + 4.
    """
    off = va - base
    if not (0 <= off < len(d) - 4) or off % 4:
        raise SystemExit(f"--detour {va:#x}: not a 4-byte aligned address in the image")
    w = struct.unpack_from("<I", d, off)[0]
    kind = pc_relative(w)
    if kind:
        raise SystemExit(f"--detour {va:#x}: {w:#010x} is {kind}, which is "
                         "PC-relative and cannot be displaced.  Detour the "
                         "instruction before or after it instead.")
    if w in (0, KP_ORIG_PLACEHOLDER):
        raise SystemExit(f"--detour {va:#x}: holds {w:#010x}, which is not code")
    orig_off = meta["orig"] - meta["base"]
    have = struct.unpack_from("<I", blob, orig_off)[0]
    if have != KP_ORIG_PLACEHOLDER:
        raise SystemExit(f"_kp_orig holds {have:#010x}, expected the "
                         f"brk #0xfee0 placeholder {KP_ORIG_PLACEHOLDER:#010x}")
    struct.pack_into("<I", blob, orig_off, w)
    struct.pack_into("<I", blob, meta["tail"] - meta["base"],
                     enc_branch(meta["tail"], va + 4, link=False))
    struct.pack_into("<I", d, off, enc_branch(va, meta["entry"], link=False))
    return w


def assert_no_trap_placeholder(blob, base):
    """Refuse a blob that still carries a `brk` trap placeholder.

    Every placeholder exists to be patched by exactly one code path, so a
    survivor means a path did not run for this build mode -- and an image with
    one is unbootable the moment that path executes.  The check is on the
    CONTENT rather than on the diff, because the diff is only ever checked
    against what was INTENDED, and the intended blob contains the brk.
    """
    bad = []
    for i in range(0, len(blob) - 3, 4):
        w = struct.unpack_from("<I", blob, i)[0]
        if (w & 0xffe0001f) == 0xd4200000 and ((w >> 5) & 0xffff) in TRAP_PLACEHOLDERS:
            bad.append((base + i, (w >> 5) & 0xffff))
    if bad:
        raise SystemExit(
            "the kext still carries an unpatched trap placeholder:\n"
            + "\n".join(f"    {a:#x}  brk #{i:#x}" for a, i in bad))


# ---------------------------------------------------------------- insert ----

def stamp_build_tag(d, cfg, rng=None):
    """Splice a RANDOM tag into every copy of the kernel version string.

    A patched kernel that only misbehaves on failure is silent both when it
    works and when it never ran.  The tag is what makes those distinguishable:
    `uname -a` on the device names exactly which image booted.  Same length, in
    place, so nothing moves.
    """
    mk = cfg.get("build_tag")
    if not mk:
        return None
    stock = mk["stock"].encode()
    n = d.count(stock)
    if n != mk.get("count", 2):
        raise SystemExit(f"expected {mk.get('count', 2)} copies of "
                         f"{mk['stock']!r} in the image, found {n}")
    keep = stock[stock.index(b"_"):]                  # e.g. b"_ARM64_T8150"
    room = len(stock) - len(keep)
    prefix = mk.get("prefix", "IK")
    body = (rng or secrets.token_hex(16).upper())[:max(0, room - len(prefix))]
    tag = (prefix + body)[:room].ljust(room, "0")
    marker = tag.encode() + keep
    assert len(marker) == len(stock)
    d[:] = bytes(d).replace(stock, marker)
    return marker.decode()


def cmd_insert(cfg, img, args):
    base = cfg["map_base"]
    d = bytearray(img["raw"])
    slack = cfg["slack"]
    srcs = args.kext or [os.path.join(KEXT_DIR, "hello.c")]
    defines = {}
    if args.sysctl:
        need = ("sysctl_register_oid", "sysctl_parent_children", "scratch",
                "sysctl_handle_int")
        missing = [k for k in need if k not in cfg.get("symbols", {})]
        if missing:
            raise SystemExit("--sysctl needs these in the config's symbols map: "
                             + ", ".join(missing))
        defines = {"IK_SYSCTL_NAME": '"%s"' % args.sysctl,
                   "IK_SYSCTL_DESCR": '"%s"' % args.sysctl_descr,
                   "IK_SYSCTL_VALUE": str(args.sysctl_value)}
    # Where the kext will live decides where it must be LINKED, so this has
    # to be settled before the blob is built.  Appending does not disturb any
    # existing offset, so the destination address is known from the current
    # image length alone.
    append = args.append_kext
    in_slack = append          # the entry's code goes in the slack

    if args.prelink_bundle and not append:
        raise SystemExit("--prelink-bundle only makes sense with --append-kext")
    if append and not in_slack:
        exec_va = base + len(img["raw"]) + fileset.PAGE
        blob, meta = build_blob(cfg, srcs, defines, target=exec_va)
        print(f"kext:   {', '.join(os.path.basename(s) for s in srcs)}  "
              f"{len(blob)} bytes, appended as {append!r} (no size ceiling)")
    else:
        blob, meta = build_blob(cfg, srcs, defines)
        where = f"appended as {append!r}, code in the slack" if in_slack else ""
        print(f"kext:   {', '.join(os.path.basename(s) for s in srcs)}  "
              f"{len(blob)} bytes, {slack['size'] - len(blob)} bytes of slack "
              f"left  {where}")
        if len(blob) > slack["size"]:
            raise SystemExit("the kext does not fit the slack")

    # 1. Refuse to write over anything.  The slack must still be all zeros, and
    #    the bytes immediately before it must still be the live code the config
    #    says is there -- the cheapest check that this is the image the config
    #    was written for.
    dst = slack["file_off"]
    guard = slack.get("preceded_by") if (in_slack or not append) else None
    if guard:
        n = len(guard) // 2
        have = bytes(d[dst - n:dst]).hex()
        if have != guard:
            raise SystemExit(f"bytes before the slack are {have}, config says {guard}")
    if (in_slack or not append) and bytes(d[dst:dst + len(blob)]).strip(b"\0"):
        raise SystemExit(f"destination {dst:#x} is not all zeros")

    # 2. The tail instruction -- or, for a detour, _kp_orig and a tail that
    #    returns to the instruction after the displaced one.
    if args.detour:
        if args.tail is not None:
            raise SystemExit("--detour sets the tail itself; do not pass --tail")
        va = int(args.detour, 0)
        w = apply_detour(d, blob, meta, base, va)
        print(f"  {va:#09x}  {w:#010x} -> b {meta['entry']:#x}   "
              f"displaced into _kp_orig, tail returns to {va + 4:#x}")
    else:
        tail = args.tail
        if tail is None:
            hook = cfg.get("hooks", {}).get(args.hook[0]) if args.hook else None
            if hook and "default_tail" in hook:
                tail = hook["default_tail"]
            else:
                raise SystemExit("--tail is required unless --detour is given")
        if tail == "ret":
            word = 0xd65f03c0
        elif tail == "nop":
            word = 0xd503201f
        elif tail.startswith("branch:"):
            word = enc_branch(meta["tail"], int(tail.split(":", 1)[1], 0), link=False)
        else:
            raise SystemExit("--tail must be ret, nop or branch:<VA>")
        tail_off = meta["tail"] - meta["base"]
        have = struct.unpack_from("<I", blob, tail_off)[0]
        if have != KP_TAIL_PLACEHOLDER:
            raise SystemExit(f"tail slot holds {have:#010x}, expected the "
                             f"brk #0xfeed placeholder {KP_TAIL_PLACEHOLDER:#010x}")
        struct.pack_into("<I", blob, tail_off, word)
        # _kp_orig sits BETWEEN the trampoline epilogue and _kp_tail, so a
        # stolen-BL kext falls straight through it.  Nop it out so the epilogue
        # reaches the tail; leaving the brk there would panic on first firing.
        orig_off = meta["orig"] - meta["base"]
        if struct.unpack_from("<I", blob, orig_off)[0] != KP_ORIG_PLACEHOLDER:
            raise SystemExit("_kp_orig does not hold its brk #0xfee0 placeholder")
        struct.pack_into("<I", blob, orig_off, 0xd503201f)
        print(f"  tail:     {tail}")

    assert_no_trap_placeholder(blob, meta["base"])
    if in_slack or not append:
        d[dst:dst + len(blob)] = blob
        print(f"  {dst:#09x}  {len(blob)} bytes  kext (entry {meta['entry']:#x})")

    # 3. Hooks: rewrite each named call site to reach the entry point.
    for name in args.hook:
        sites = cfg.get("hooks", {}).get(name)
        if sites is None:
            raise SystemExit(f"no hook set named {name!r}; have "
                             f"{list(cfg.get('hooks', {}))}")
        for site in sites["sites"]:
            off = site - base
            old = struct.unpack_from("<I", d, off)[0]
            want = sites.get("expect_target")
            if want is not None and dec_branch(old, site) != want:
                raise SystemExit(f"{site:#x}: expected a branch to {want:#x}, "
                                 f"found {old:#010x}")
            struct.pack_into("<I", d, off,
                             enc_branch(site, meta["entry"], link=bool(old & 0x80000000)))
        print(f"  {len(sites['sites'])} sites  hook {name!r} -> {meta['entry']:#x}")

    # 4. The sysctl node.  Nothing is spliced for it: the kext registers it
    #    itself at runtime, because a signature the CPU will authenticate is
    #    better produced by that CPU than asked of the loader.  See
    #    kext/include/ksysctl.h for the hardware result that settled this.
    if args.sysctl:
        path = cfg.get("sysctl_parent_path", "")
        full = "%s.%s" % (path, args.sysctl) if path else args.sysctl
        print("  sysctl %r registered at runtime by the kext (handler %#x, "
              "reads back %d)" % (full, meta["sysctl_entry"], args.sysctl_value))
        print("            one-shot guard + struct sysctl_oid in scratch at %#x"
              % cfg["symbols"]["scratch"])

    # 5. Named single-instruction patches from the config, by name.  The
    #    mechanism is generic; what a config puts in `extra_patches` is its
    #    own business.
    for name in args.extra:
        pch = cfg.get("extra_patches", {}).get(name)
        if pch is None:
            raise SystemExit(f"no extra patch named {name!r}; have "
                             f"{list(cfg.get('extra_patches', {}))}")
        off, old_hex, new_hex = pch["off"], pch["old"], pch["new"]
        have = bytes(d[off:off + len(old_hex) // 2]).hex()
        if have != old_hex:
            raise SystemExit(f"{name} @ {off:#x}: expected {old_hex}, found {have}")
        d[off:off + len(old_hex) // 2] = bytes.fromhex(new_hex)
        print(f"  {off:#09x}  {old_hex} -> {new_hex}  {pch.get('what', name)}")

    # 6. --poke: ad-hoc single-instruction rewrites of kernel text.
    #
    #    Each poke names the word it EXPECTS to find as well as the one to
    #    write, and a mismatch is a build failure.  That is not ceremony: a
    #    stale VA -- from a re-symbolicated address, or simply a different
    #    kernelcache -- would otherwise be patched into the wrong place
    #    silently, and the result is a kernel that is wrong in a way no diff
    #    will look odd.
    for spec in args.poke:
        try:
            va_s, words = spec.split("=", 1)
            old_s, new_s = words.split(":", 1)
            va, old_w, new_w = int(va_s, 0), int(old_s, 0), int(new_s, 0)
        except ValueError:
            raise SystemExit(f"--poke {spec!r}: expected VA=OLD:NEW")
        off = va - base
        if not (0 <= off < len(d) - 4) or off % 4:
            raise SystemExit(f"--poke {va:#x}: not a 4-byte aligned address "
                             "in the image")
        have = struct.unpack_from("<I", d, off)[0]
        if have != old_w:
            raise SystemExit(f"--poke {va:#x}: image holds {have:#010x}, "
                             f"--poke says {old_w:#010x}.  REFUSING.  Either "
                             "the address is wrong or this is not the "
                             "kernelcache the address was read from.")
        struct.pack_into("<I", d, off, new_w)
        print(f"  {off:#09x}  VA {va:#x}  {old_w:#010x} -> {new_w:#010x}  (poke)")

    # 7. Spare syscall slots -> the kext, reachable as syscall(N, a, b, c).
    for spec in args.syscall_slot:
        if "sysent_table" not in cfg:
            raise SystemExit("--syscall-slot needs a `sysent_table` in the config")
        rep = sysent.patch(cfg, d, int(spec, 0), meta["syscall_entry"])
        print(f"  {rep['file_off']:#09x}  sysent[{rep['slot']}] sy_call -> "
              f"{rep['target']:#x} (was nosys); munge/narg/arg_bytes copied "
              f"from slot {rep['reference']}")
        print(f"            chain page: {rep['links_before']} -> "
              f"{rep['links_after']} links, every prior link intact")
        print(f"            reach it with syscall({rep['slot']}, a, b, c)")

    # 8. The build tag, always.
    tag = None if args.no_mark else stamp_build_tag(d, cfg)
    if tag:
        print(f"  build tag: {tag}   "
              f"(check `uname -a` against this before believing anything)")

    expect = {
        "build_tag": tag,
        "kext": [os.path.basename(x) for x in srcs],
        "hooks": {n: len(cfg["hooks"][n]["sites"]) for n in args.hook},
        "detour": args.detour,
        "sysctl": ({"path": (("%s.%s" % (cfg.get("sysctl_parent_path"), args.sysctl))
                             if cfg.get("sysctl_parent_path") else args.sysctl),
                    "parent": cfg.get("sysctl_parent_path", ""),
                    "name": args.sysctl,
                    "value": args.sysctl_value,
                    "descr": args.sysctl_descr}
                   if args.sysctl else None),
        "dmesg": {"boot": args.expect_log_boot, "sysctl": args.expect_log_sysctl,
                  "syscall": args.expect_log_syscall},
    }
    if args.syscall_slot:
        # The example kext returns IK_SYSCALL_MAGIC + the first argument, so a
        # probe proves BOTH that the slot reaches our code and that the three
        # arguments arrived.  A kext that returns something else needs
        # --expect-syscall-retval.
        a0 = 0x11
        expect["syscall"] = {
            "slot": int(args.syscall_slot[0], 0),
            "args": [a0, 0x22, 0x33],
            "retval": (args.expect_syscall_retval
                       if args.expect_syscall_retval is not None
                       else 0x4B450000 + a0),
        }

    # 7. The appended entry itself.  This happens LAST, after every patch to
    #    the existing image, because it appends to the end of `d` and rewrites
    #    the header's command count -- and because the hook edits above have to
    #    land in the image the entry is then measured against.
    if append:
        newd, geom = fileset.emit_entry(bytes(d), append, code=bytes(blob),
                                        data_size=0,
                                        exec_at=((slack["file_off"], slack["va"],
                                                  len(blob)) if in_slack else None))
        if geom["exec_va"] != meta["base"]:
            raise SystemExit(f"the entry's __TEXT_EXEC landed at "
                             f"{geom['exec_va']:#x} but the kext was linked for "
                             f"{meta['base']:#x}")
        d = bytearray(newd)
        print()
        if not fileset.check(bytes(d), label="the emitted image", verbose=False):
            raise SystemExit("the emitted image fails its own layout checks")
        if args.prelink_bundle:
            d = bytearray(fileset.add_prelink_bundle(bytes(d), append))
            expect["prelink_bundle"] = append
        expect["append"] = geom

    # The IO registry expectations, recorded only when the config carries the
    # addresses the example kext's IOKit code is compiled against -- the same
    # condition as the #if in kext/hello.c, so `check` asks for exactly what
    # the build put in.  A kext of your own that does something else should
    # pass --expect-ioreg-property "" / --expect-ioreg-node "" to say so.
    syms = cfg.get("symbols", {})
    if args.expect_ioreg_property and all(
            k in syms for k in ("IORegistryEntry_getRegistryRoot",
                                "IORegistryEntry_setProperty_cstr")):
        k, _, v = args.expect_ioreg_property.partition("=")
        expect["ioreg_property"] = {"key": k, "value": v}
    if args.expect_ioreg_node and all(
            k in syms for k in ("OSMetaClass_allocClassWithName", "IOService_init",
                                "IORegistryEntry_setName_cstr", "IOService_attach",
                                "IOService_getServiceRoot",
                                "IOService_registerService")):
        expect["ioreg_node"] = {"name": args.expect_ioreg_node}

    out = args.out or "kernelcache.insert_kext.im4p"
    raw_out = os.path.splitext(out)[0] + ".raw"
    open(raw_out, "wb").write(bytes(d))
    report_diff(img["raw"], d, base)
    if img["props"] is None:
        print(f"\nwrote {raw_out}")
        print("no stock IM4P to take the properties element from, so no bootable "
              "image was written.  Re-run with the .ipsw or the IM4P as <image>, "
              "or pass --stock-im4p.")
        return
    package(cfg, img, bytes(d), out)
    if tag:
        open(out + ".uname", "w").write(tag + "\n")
    json.dump(expect, open(out + ".expect.json", "w"), indent=2)
    print(f"\nwrote {out}  (and {raw_out}, {os.path.basename(out)}.expect.json)")
    print(f"after booting it:  insert_kext.py check {out} --ssh '<ssh command>'")


# ---------------------------------------------------------------- verify ----

def report_diff(a, b, base, gap=16):
    """Every changed region, with single-word changes decoded as branches.

    Runs separated by less than `gap` untouched bytes are reported as one.
    A spliced kext is mostly-but-not-entirely different from the zeros it
    replaced, so byte-exact runs would list it as dozens of fragments and bury
    the handful of edits that are actually worth reading.
    """
    if len(a) != len(b):
        print(f"SIZE CHANGED: {len(a)} -> {len(b)}")
    diff = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    runs = []
    for i in diff:
        if runs and i - runs[-1][1] <= gap:
            runs[-1][1] = i
        else:
            runs.append([i, i])
    print(f"\n{len(diff)} differing bytes in {len(runs)} regions")
    for lo, hi in runs:
        n = hi - lo + 1
        note = ""
        if n <= 4:
            w = struct.unpack_from("<I", b, lo & ~3)[0]
            t = dec_branch(w, base + (lo & ~3))
            if t is not None:
                note = f"  branch -> {t:#x}"
        print(f"  file {lo:#09x}  VA {base+lo:#x}  {n} bytes{note}")


def cmd_package(cfg, img, args):
    """Re-wrap a Mach-O that was patched elsewhere, or re-wrap an IM4P after
    --set-prop.  `insert` packages its own output; this is for the cases where
    the image and its wrapper are edited in separate steps."""
    if img["props"] is None:
        raise SystemExit("no properties element; pass --stock-im4p")
    package(cfg, img, img["raw"], args.out)


def cmd_props(cfg, img, args):
    """Print the kc* properties, and check that the regions still partition
    the payload exactly -- which is the invariant an image that grew breaks."""
    if img["props"] is None:
        raise SystemExit("no IM4P properties element (bare Mach-O input)")
    d = imageio.props_get(img["props"])
    for k in sorted(d):
        print(f"  {k:<5} {d[k]:#x}  {d[k]}")
    pairs = [("kcrf", "kcrz"), ("kcsf", "kcsz"), ("kcxf", "kcxz"),
             ("kcbf", "kcbz"), ("kcwf", "kcwz"), ("kclf", "kclz")]
    if not all(f in d and z in d for f, z in pairs):
        return
    print("\nprotection regions:")
    for f, z in pairs:
        print(f"  {f[2:]:<3} [{d[f]:#011x}, {d[f] + d[z]:#011x})  {d[z]} bytes")
    total = sum(d[z] for _, z in pairs)
    have = len(img["raw"])
    print(f"\n  regions sum to {total}, payload is {have}", end="")
    if total == have:
        print("  -- exact, as iBoot expects")
    else:
        print(f"  -- MISMATCH, {have - total} bytes outside every region.\n"
              f"  the last region would have to be kclz={d['kclz'] + have - total} "
              "to cover them")


def cmd_verify(cfg, img, args):
    report_diff(img["raw"], open(args.patched, "rb").read(), cfg["map_base"])


# --------------------------------------------------------------- package ----

def package(cfg, img, payload, out):
    """Wrap a patched image as an UNCOMPRESSED IM4P, keeping the stock image's
    properties element.

    Two Apple-specific facts, both of which cost a boot to learn the hard way:
    recompressing with a different LZFSE encoder makes iBoot take a synchronous
    exception before the kernel runs, and iBoot needs the `kc*` properties
    (segment sizes, `kclo`, `kcep`) that the stock image carries.  So the
    payload goes in uncompressed and the stock properties element is spliced on
    rather than regenerated.
    """
    tlv, props = imageio.der_tlv, img["props"]
    if len(payload) > len(img["raw"]):
        # An appended entry's header has to be covered by some region or the
        # image will not load, and the last one is the only size that may
        # change: every other kc* size is refused outright.  It maps the bytes
        # read-only, which is all the header needs -- the code lives in the
        # slack, inside a region that is already executable.
        pr = imageio.props_get(props)
        grew = len(payload) - (pr["kclf"] + pr["kclz"])
        props = imageio.props_set(props, "kclz", pr["kclz"] + grew)
        print(f"\ncovered the appended {grew} bytes: kclz {pr['kclz']} -> "
              f"{pr['kclz'] + grew}")

    body = (tlv(0x16, b"IM4P") + tlv(0x16, img["type"].encode())
            + tlv(0x16, img["version"].encode()) + tlv(0x04, payload) + props)
    open(out, "wb").write(tlv(0x30, body))
    print(f"\npackaged {out}: {len(props)}-byte properties element spliced, "
          "uncompressed (the only form confirmed to boot)")


# ----------------------------------------------------------------- check ----
#
# The end-to-end test.  `insert` writes down what the image SHOULD do; `check`
# goes to a device and asks whether it does.
#
# Everything happens in ONE round trip, and that is not tidiness.  The kernel
# message ring is small and busy -- on the device this was written against it
# wraps in well under a minute -- so a `sysctl` read in one connection and a
# `dmesg` in the next will usually show the read having left no trace.  The
# remote script therefore reads the sysctl and captures the log immediately
# after, in that order, in the same shell.

REMOTE_SCRIPT = r"""
set -u
S=sysctl; D=dmesg; G=ioreg
for d in %(tooldirs)s; do
    [ -x "$d/sysctl" ] && S="$d/sysctl"
    [ -x "$d/dmesg" ]  && D="$d/dmesg"
    [ -x "$d/ioreg" ]  && G="$d/ioreg"
done
echo "###UNAME"
uname -a 2>&1
echo "###NAMES"
%(names)s
echo "###VALUE"
%(value)s
echo "###DESCR"
%(descr)s
echo "###SYSCALL"
%(syscall)s
echo "###IOREG"
%(ioreg)s
echo "###IONODE"
%(ionode)s
echo "###DMESG"
$D 2>/dev/null | tail -n 400
echo "###END"
"""


def _section(text, name):
    try:
        body = text.split("###" + name + "\n", 1)[1]
    except IndexError:
        return ""
    return re.split(r"^###", body, maxsplit=1, flags=re.M)[0].strip()


def cmd_check(cfg, img, args):
    # Accept either the expectations file or the image it sits next to.  The
    # sibling is preferred whenever it exists, because the image path also
    # "exists" and would otherwise be handed to a JSON parser.
    exp_path = args.expect
    sibling = exp_path + ".expect.json"
    if os.path.exists(sibling):
        exp_path = sibling
    elif not (os.path.exists(exp_path) and exp_path.endswith(".json")):
        raise SystemExit(f"no expectations file at {sibling}"
                         + ("" if exp_path.endswith(".json")
                            else f" (and {exp_path} is not a .json)")
                         + ".  It is written next to the image by `insert`.")
    exp = json.load(open(exp_path))
    print(f"expectations: {exp_path}")
    sc = exp.get("sysctl")

    # NOT quoted, so a glob expands on the device -- a tool directory whose
    # name carries a build-specific suffix is the normal case.  The cost is
    # that a path with spaces in it will not work.
    tooldirs = " ".join(args.tool_dir) or '""'
    if sc:
        parent = sc["parent"] or ""
        names = ('$S -N %s 2>/dev/null | grep -x %s || echo "(absent)"'
                 % (parent or sc["path"], sc["path"]))
        value = '$S -n %s 2>&1' % sc["path"]
        descr = '$S -d %s 2>&1' % sc["path"]
    else:
        names = value = descr = 'echo "(no sysctl in this build)"'

    # The syscall probe needs something on the device that can issue a raw
    # syscall.  perl can, and is the likeliest thing to be present; if it is
    # not, the probe reports that rather than failing the run, because a
    # missing probe tool says nothing about the image.
    sy = exp.get("syscall")
    if sy:
        a = sy["args"]
        syscall = ('if command -v perl >/dev/null 2>&1; then '
                   "perl -e 'print syscall(%d, %d, %d, %d), \"\\n\"'; "
                   'else echo "(no perl on the device)"; fi'
                   % (sy["slot"], a[0], a[1], a[2]))
    else:
        syscall = 'echo "(no syscall slot in this build)"'

    # The IO registry probes.  Both run after the sysctl read above, because
    # in the example kext the sysctl handler is what reaches IOKit -- probing
    # before it would correctly find nothing and look like a failure.
    have_ioreg = 'command -v "$G" >/dev/null 2>&1'
    iop = exp.get("ioreg_property")
    if iop:
        ioreg = ('if %s; then "$G" -l -d 1 2>/dev/null | grep -F %s || '
                 'echo "(absent)"; else echo "(no ioreg)"; fi'
                 % (have_ioreg, shlex.quote('"%s" = ' % iop["key"])))
    else:
        ioreg = 'echo "(no ioreg property in this build)"'
    ion = exp.get("ioreg_node")
    if ion:
        ionode = ('if %s; then "$G" 2>/dev/null | grep -F %s || '
                  'echo "(absent)"; else echo "(no ioreg)"; fi'
                  % (have_ioreg, shlex.quote("+-o %s  <class" % ion["name"])))
    else:
        ionode = 'echo "(no ioreg node in this build)"'

    script = REMOTE_SCRIPT % dict(tooldirs=tooldirs, names=names,
                                  value=value, descr=descr, syscall=syscall,
                                  ioreg=ioreg, ionode=ionode)

    # The script goes as an ARGUMENT, not down stdin.  `ssh host sh -s` needs a
    # working /bin/sh on the far side, and a stripped-down device may not have
    # one -- iOS's is a bash variant that fails to exec when bash lives
    # somewhere else.  Passing the script as one quoted argument lets ssh hand
    # it to whatever the account's login shell actually is.
    if args.ssh:
        cmd = args.ssh + " " + shlex.quote(script)
        print(f"$ {args.ssh} <script>")
    else:
        cmd = script
        print("$ (running locally)")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if "###END" not in r.stdout:
        raise SystemExit("the remote script did not run to completion.\n"
                         f"stdout: {r.stdout[-400:]!r}\nstderr: {r.stderr[-400:]!r}")

    uname = _section(r.stdout, "UNAME")
    dmesg = _section(r.stdout, "DMESG")
    results = []

    def check(name, ok, detail):
        results.append((ok, name, detail))

    # 1. THE IMAGE.  Everything below is meaningless if a different kernel
    #    booted, so this is first and the rest is worth nothing without it.
    tag = exp.get("build_tag")
    if tag:
        check("booted image", tag in uname,
              uname if tag in uname else f"expected {tag!r}, got: {uname}")
    else:
        check("booted image", True, "(no build tag in this image)")

    if sc:
        listed = _section(r.stdout, "NAMES")
        value = _section(r.stdout, "VALUE")
        descr = _section(r.stdout, "DESCR")
        # 2. REGISTERED.  A name walk does not call the leaf handler, so this
        #    separates "the node exists" from "the handler is callable" -- the
        #    two failed independently while this tool's target was written.
        check("sysctl registered", listed == sc["path"],
              f"{sc['path']} listed -- so the hook ran and payload_main "
              f"registered it" if listed == sc["path"]
              else f"not listed ({listed!r})")
        # 3. HANDLER CALLABLE, and returning what was baked in.
        check("sysctl value", value == str(sc["value"]),
              f"{sc['path']} = {value}" if value == str(sc["value"])
              else f"expected {sc['value']}, got {value!r}")
        got_descr = descr.split(":", 1)[1].strip() if ":" in descr else descr
        check("sysctl description", got_descr == sc["descr"],
              got_descr if got_descr == sc["descr"]
              else f"expected {sc['descr']!r}, got {got_descr!r}")

    # 3b. THE SYSCALL CHANNEL, if this image has one.
    if sy:
        got = _section(r.stdout, "SYSCALL")
        if "no perl" in got:
            check("syscall channel", True,
                  "SKIPPED -- no perl on the device to issue syscall(%d); the "
                  "slot is patched and the machine booted, which is not the "
                  "same as the call having been made" % sy["slot"])
        else:
            check("syscall channel", got == str(sy["retval"]),
                  "syscall(%d, %#x, ...) = %s" % (sy["slot"], sy["args"][0], got)
                  if got == str(sy["retval"])
                  else "expected %d, got %r" % (sy["retval"], got))

    # 3c. THE IO REGISTRY.  These say something the sysctl cannot: that the
    #     kext reached IOKit and changed state a completely separate userspace
    #     tool can see.  A missing `ioreg` is reported as a skip rather than a
    #     failure, because an absent probe says nothing about the image.
    if iop:
        got = _section(r.stdout, "IOREG")
        if "no ioreg" in got:
            check("ioreg property", True,
                  "SKIPPED -- no ioreg on the device; nothing was proved either way")
        else:
            want = '"%s" = "%s"' % (iop["key"], iop["value"])
            check("ioreg property", want in got,
                  got.strip() if want in got
                  else "expected %r on the registry root, got %r" % (want, got))
    if ion:
        got = _section(r.stdout, "IONODE")
        if "no ioreg" in got:
            check("ioreg node", True,
                  "SKIPPED -- no ioreg on the device; nothing was proved either way")
        else:
            ok = ("+-o %s  <class" % ion["name"]) in got
            check("ioreg node", ok,
                  got.strip()[:120] if ok
                  else "no %r node in the registry: %r" % (ion["name"], got))

    # 4. THE KEXT ACTUALLY RAN.
    #
    # For the hook there is no log check, on purpose.  The hook's job is to
    # register the sysctl once and then stay quiet, so any line it printed has
    # long since scrolled out of a ring buffer that wraps in under a minute.
    # The registration IS the evidence: nothing else puts that node there.
    #
    # The handler's line is different -- it is printed on demand, by the read
    # this script just performed, which is why the remote script captures the
    # log in the same round trip.
    pats = exp.get("dmesg", {})
    if sy and pats.get("syscall"):
        n = dmesg.count(pats["syscall"])
        check("log: syscall handler", n > 0,
              f"{n} line(s) matching {pats['syscall']!r}" if n
              else f"no line matching {pats['syscall']!r} in the last 400")
    if sc and pats.get("sysctl"):
        n = dmesg.count(pats["sysctl"])
        check("log: sysctl handler", n > 0,
              f"{n} line(s) matching {pats['sysctl']!r}" if n
              else f"no line matching {pats['sysctl']!r} in the last 400")
    elif pats.get("boot"):
        n = dmesg.count(pats["boot"])
        check("log: boot hook", n > 0,
              f"{n} line(s) matching {pats['boot']!r}" if n
              else f"no line matching {pats['boot']!r} in the last 400 -- with "
                   "no sysctl this is one-shot at boot, so a long-running "
                   "device will have scrolled past it")

    print()
    for ok, name, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name:<22} {detail}")
    bad = [x for x in results if not x[0]]
    print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
    if bad and not any(x[1] == "booted image" for x in bad):
        print("the expected image is running, so these are real failures of the "
              "kext rather than of the install", file=sys.stderr)
    return not bad


# -------------------------------------------------------------- selftest ----

def cmd_selftest(cfg, img, args):
    """Differential-test the detour classifier against llvm-objdump.

    The classifier decides whether an instruction may be displaced into the
    kext, and a wrong `no` there is a silently miscomputed address rather than
    a crash.  So it is checked against a real disassembler over real kernel
    text rather than against a table someone typed.

    The comparison is on EXACT mnemonics, not prefixes.  A `startswith("b")`
    test calls `bti`, `bic`, `brk` and `blraa` PC-relative and makes the test
    fail on correct code, which is the kind of harness bug that gets a real
    classifier "fixed" until it is wrong.
    """
    d, base = img["raw"], cfg["map_base"]
    va, size = int(args.va, 0), int(args.size, 0)
    if not (0 <= va - base < len(d) - size):
        raise SystemExit(f"--va {va:#x} --size {size:#x} is not inside the image")
    sl = d[va - base:va - base + size]
    with tempfile.TemporaryDirectory() as t:
        open(os.path.join(t, "f.bin"), "wb").write(sl)
        open(os.path.join(t, "w.s"), "w").write(
            '.section __TEXT,__text\n.incbin "f.bin"\n')
        subprocess.run(["xcrun", "clang", "-c", "-arch", "arm64",
                        "-o", "w.o", "w.s"], cwd=t, check=True)
        dis = subprocess.run(["xcrun", "llvm-objdump", "-d", "--no-show-raw-insn",
                              "w.o"], cwd=t, capture_output=True, text=True,
                             check=True).stdout

    BRANCH = {"b", "bl", "cbz", "cbnz", "tbz", "tbnz", "adr", "adrp"}
    LITERAL = {"ldr", "ldrsw", "prfm"}
    checked = agree = 0
    disagree = []
    for line in dis.splitlines():
        mo = re.match(r"\s+([0-9a-f]+):\s+(\S+)\s*(.*)", line)
        if not mo:
            continue
        off, mn, ops = int(mo.group(1), 16), mo.group(2), mo.group(3)
        if off + 4 > len(sl):
            continue
        w = struct.unpack_from("<I", sl, off)[0]
        # A literal load is the one case the mnemonic alone cannot settle:
        # `ldr x0, [x1]` and `ldr x0, 0x1234` are the same mnemonic and only
        # one of them reads from the PC.
        want = mn in BRANCH or mn.startswith("b.") or \
            (mn in LITERAL and "[" not in ops)
        got = pc_relative(w) is not None
        checked += 1
        if got == want:
            agree += 1
        else:
            disagree.append((va + off, w, mn, ops, got, want))
    for at, w, mn, ops, got, want in disagree[:12]:
        print(f"  MISMATCH {at:#x} {w:#010x}  objdump={mn} {ops}  "
              f"classifier says {'PC-relative' if got else 'displaceable'}")
    print(f"{checked} instructions from {va:#x}: classifier and llvm-objdump "
          f"agree on {agree}, disagree on {len(disagree)}")
    return not disagree


# ------------------------------------------------------------------ main ----

def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", help="config JSON; auto-selected by content if omitted")
    ap.add_argument("--variant", help="which kernelcache to take out of an .ipsw "
                                      "(a substring of its name, e.g. 'research')")
    ap.add_argument("--stock-im4p", help="take the IM4P properties element from "
                                         "here instead (needed to package a bare "
                                         "Mach-O input)")
    ap.add_argument("--set-prop", action="append", default=[], metavar="NAME=VALUE",
                    help="rewrite one kc* IM4P property before packaging, e.g. "
                         "kclz=851968.  Repeatable.  See the `props` subcommand "
                         "for what an image currently carries")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("info", "props"):
        sub.add_parser(name).add_argument("image")
    p = sub.add_parser("package", help="wrap an already-patched Mach-O as a "
                                       "bootable uncompressed IM4P")
    p.add_argument("image", help="the patched Mach-O (or an IM4P to re-wrap)")
    p.add_argument("-o", "--out", required=True)
    p = sub.add_parser("slack"); p.add_argument("image")
    p.add_argument("--min", type=int, default=256)
    p = sub.add_parser("build"); p.add_argument("image")
    p.add_argument("--kext", action="append", help="kext source; repeatable")
    p.add_argument("-o", "--out")
    p = sub.add_parser("verify"); p.add_argument("image"); p.add_argument("patched")
    p = sub.add_parser("check", help="ask a booted device whether the image did "
                                     "what `insert` said it would")
    p.add_argument("expect", help="the .expect.json `insert` wrote, or the image "
                                  "path it sits next to")
    p.add_argument("--ssh", default="", metavar="CMD",
                   help="command that runs a shell on the device, e.g. "
                        "\"ssh -p 2222 root@localhost\".  Omit to run locally.")
    p.add_argument("--tool-dir", action="append", default=[], metavar="DIR",
                   help="directory holding sysctl/dmesg if they are not on the "
                        "device's PATH; repeatable, shell globs allowed")
    p = sub.add_parser("selftest"); p.add_argument("image")
    p.add_argument("--va", default="0xfffffe000ac73000")
    p.add_argument("--size", default="0x10000")

    p = sub.add_parser("insert", help="the whole pipeline")
    p.add_argument("image")
    p.add_argument("-o", "--out", help="output IM4P (default kernelcache.insert_kext.im4p)")
    p.add_argument("--append-kext", metavar="BUNDLE_ID",
                   help="put the kext in a NEW fileset entry appended to the "
                        "end of the image, so the image carries a real named "
                        "bundle instead of only an anonymous blob.  The entry's "
                        "header is appended and its code stays in the slack, "
                        "because appended bytes can be mapped but not made "
                        "executable.  Nothing already in the image moves")
    p.add_argument("--prelink-bundle", action="store_true",
                   help="also add a __PRELINK_INFO bundle dictionary for the "
                        "appended kext, so the kernel's extension registry "
                        "knows it exists.  Codeless, which is what the vendor's "
                        "own pseudo-extensions use")
    p.add_argument("--kext", action="append",
                   help="kext source; repeatable.  Default: kext/hello.c")
    p.add_argument("--hook", action="append", default=[],
                   help="name of a hook set in the config; repeatable")
    p.add_argument("--tail", help="ret | nop | branch:<VA>; required unless "
                                  "--detour, or the hook names a default")
    p.add_argument("--detour", metavar="VA",
                   help="replace the instruction at VA with a branch to the kext; "
                        "the displaced instruction runs from _kp_orig and the "
                        "tail returns to VA+4.  Refuses PC-relative instructions.")
    p.add_argument("--sysctl", metavar="NAME",
                   help="register a sysctl node NAME whose handler is the kext's "
                        "payload_sysctl")
    p.add_argument("--sysctl-value", type=int, default=1,
                   help="the int the sysctl reads back (default 1)")
    p.add_argument("--sysctl-descr", default="insert_kext example node")
    p.add_argument("--extra", action="append", default=[], metavar="NAME",
                   help="apply the config's extra_patches entry NAME; repeatable")
    p.add_argument("--poke", action="append", default=[], metavar="VA=OLD:NEW",
                   help="replace one instruction in kernel text.  OLD is the "
                        "word that must already be there and NEW the "
                        "replacement, both hex; the build FAILS if OLD does not "
                        "match, so a wrong address cannot be patched silently.")
    p.add_argument("--syscall-slot", action="append", default=[], metavar="N",
                   help="point spare sysent slot N at the kext's "
                        "payload_syscall, reachable as syscall(N, a, b, c)")
    p.add_argument("--no-mark", action="store_true",
                   help="skip the build tag.  Strongly discouraged: the tag is "
                        "how `uname -a` tells you which image booted.")

    p = sub.choices["insert"]
    p.add_argument("--expect-ioreg-property", default="insert_kext=hello",
                   metavar="KEY=VALUE",
                   help="what `check` should find on the IO registry root; "
                        "empty to skip.  Recorded only when the config has the "
                        "addresses for it")
    p.add_argument("--expect-ioreg-node", default="insert_kext", metavar="NAME",
                   help="the IOService node `check` should find in the "
                        "registry; empty to skip")
    p.add_argument("--expect-log-boot", default="insert_kext (boot hook)",
                   help="substring `check` should find in the device log to "
                        "prove the boot hook ran")
    p.add_argument("--expect-log-sysctl", default="insert_kext (sysctl)",
                   help="substring `check` should find to prove the sysctl "
                        "handler ran")
    p.add_argument("--expect-log-syscall", default="insert_kext (syscall)",
                   help="substring `check` should find to prove the syscall "
                        "handler ran")
    p.add_argument("--expect-syscall-retval", type=int, default=None,
                   help="what syscall(N, 0x11, 0x22, 0x33) should return; "
                        "defaults to what the example kext returns")

    args = ap.parse_args()
    if args.cmd == "check":
        r = cmd_check(None, None, args)
    else:
        img = imageio.load(args.image, args.variant, args.stock_im4p)
        for spec in args.set_prop:
            if "=" not in spec:
                raise SystemExit(f"--set-prop wants NAME=VALUE, got {spec!r}")
            k, v = spec.split("=", 1)
            if img["props"] is None:
                raise SystemExit("--set-prop needs an IM4P; pass one as <image> "
                                 "or with --stock-im4p")
            was = imageio.props_get(img["props"]).get(k)
            img["props"] = imageio.props_set(img["props"], k, int(v, 0))
            print(f"--set-prop {k}: {was} -> {int(v, 0)}")
        # `props` reads only the IM4P wrapper, so it must work on a patched
        # image, which by definition no config's checksum matches.
        cfg = (None if args.cmd in ("props", "package")
               else pick_config(img, args.config))
        r = globals()["cmd_" + args.cmd](cfg, img, args)
    if r is False:
        sys.exit(1)


if __name__ == "__main__":
    main()
