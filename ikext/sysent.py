"""Point a spare `sysent` slot at the kext, so userspace can reach it directly.

A sysctl is the friendlier interface, but it only carries a number out.  A
syscall carries three full 64-bit arguments in and a value out, which is what
you want for anything that reads or writes on demand.

THE WHOLE DIFFICULTY IS THAT `sy_call` IS NOT A PLAIN POINTER.  The table lives
in __DATA_CONST, so the slot is a DYLD_CHAINED_PTR_64_KERNEL_CACHE link that
the boot loader rebases AND PAC-signs, and the dispatcher authenticates it with
a diversity the file already carries.  Two rules follow, and between them they
are the entire design of this file:

  * REWRITE THE TARGET, NEVER THE PAC FIELDS.  Change the low 30 bits and leave
    diversity, addrDiv, key and isAuth exactly as they were, so the loader signs
    the new target with the same key the call site will authenticate it with.

    This is not a stylistic preference.  Constructing PAC fields instead of
    preserving them is what broke this project's first sysctl attempt: an
    invented `IA / addrDiv=1 / diversity=0` encoding produced a signature the
    CPU refused, on a slot that had no prior value to copy.  Here there IS a
    prior value, so copy it and refuse if it is not what the config expects.

  * REPAIR THE CHAIN.  A value written into a slot the chain does not visit is
    never rebased at all.  The munger quad becomes a new link, and the page is
    re-walked afterwards to prove the chain is exactly what it was plus that
    one offset.

Everything written is COPIED FROM A REFERENCE SLOT the image already contains,
rather than constructed from a specification, so the result has the shape of a
syscall this kernel already dispatches.
"""
import struct

from .macho import MachO, chain_page, chained_fixups, kc_parse, kc_ptr


def patch(cfg, d, slot, target_va):
    """Point sysent[slot].sy_call at `target_va`, as a 3-argument syscall."""
    t = cfg["sysent_table"]
    base = cfg["map_base"]
    stride, ref = t["stride"], t["reference_slot"]
    if not 0 <= slot < t["nslots"]:
        raise SystemExit(f"sysent slot {slot} out of range (0..{t['nslots'] - 1})")
    spare = t.get("spare_slots")
    if spare and slot not in spare:
        raise SystemExit(
            f"sysent slot {slot} is not one of the spare slots the config lists "
            f"({', '.join(str(x) for x in spare)}).  Patching a live slot "
            "replaces a syscall the system uses; refusing.")
    fo = t["va"] - base + slot * stride
    rfo = t["va"] - base + ref * stride

    call, munge, rt, narg, ab = struct.unpack_from("<QQiHH", d, fo)
    rcall, rmunge, rrt, rnarg, rab = struct.unpack_from("<QQiHH", d, rfo)
    c, rc, rm = kc_parse(call), kc_parse(rcall), kc_parse(rmunge)

    # 1. The slot must still be the untouched spare the config says it is.
    if base + c["target"] != t["nosys"]:
        raise SystemExit(f"sysent[{slot}].sy_call targets "
                         f"{base + c['target']:#x}, not nosys {t['nosys']:#x}")
    if munge or narg or ab:
        raise SystemExit(f"sysent[{slot}] is not a bare nosys slot "
                         f"(munge={munge:#x} narg={narg} arg_bytes={ab})")
    # 2. The reference must still be the 3-argument syscall the config says.
    if rnarg != 3 or base + rm["target"] != t["munge_3args"]:
        raise SystemExit(f"reference slot {ref} is not a 3-arg syscall through "
                         f"munge_3args (narg={rnarg}, munge -> "
                         f"{base + rm['target']:#x})")
    for k in ("diversity", "addr_div", "key", "is_auth"):
        if c[k] != rc[k]:
            raise SystemExit(f"sysent[{slot}].sy_call {k}={c[k]} differs from "
                             f"reference slot {ref} ({rc[k]}); the call site "
                             "would authenticate the new pointer differently")

    # 3. Which page's chain are we about to change, and what does it look like?
    m = MachO(bytes(d))
    seg_i = m.seg_of_offset(fo)
    fixups = chained_fixups(d)
    if seg_i not in fixups:
        raise SystemExit(f"segment {m.segs[seg_i]['name']} carries no chained "
                         "fixups, so sy_call is not a rebased pointer; refusing")
    fi = fixups[seg_i]
    page = (fo - fi["seg_off"]) // fi["page_size"]
    if (fo + 8 - fi["seg_off"]) // fi["page_size"] != page:
        raise SystemExit("sy_call and sy_arg_munge32 straddle a fixup page")
    before = chain_page(d, fi, page)
    if fo not in before:
        raise SystemExit(f"sysent[{slot}].sy_call at {fo:#x} is not on its "
                         "page's fixup chain; refusing to guess")
    if fo + 8 in before:
        raise SystemExit("sy_arg_munge32 is already a chain link; refusing")

    # 4. Write.  sy_call keeps every PAC field and takes the reference's `next`
    #    so the chain now steps into sy_arg_munge32; the munger quad is copied
    #    from the reference verbatim, which already carries the `next` that
    #    lands on the following slot's sy_call.
    struct.pack_into("<Q", d, fo,
                     kc_ptr(target_va - base, c["diversity"], c["addr_div"],
                            c["key"], rc["next"], c["is_auth"], c["cache_level"]))
    struct.pack_into("<Q", d, fo + 8, rmunge)
    struct.pack_into("<HH", d, fo + 0x14, rnarg, rab)

    # 5. The chain must now be exactly what it was, plus the munger.
    after = chain_page(d, fi, page)
    if after != sorted(set(before) | {fo + 8}):
        missing = set(before) - set(after)
        raise SystemExit(
            f"chained fixup chain on page {page} changed shape: "
            f"{len(before)} links -> {len(after)}"
            + (f", lost {sorted(hex(x) for x in missing)}" if missing else ""))

    return dict(file_off=fo, slot=slot, target=target_va, reference=ref,
                links_before=len(before), links_after=len(after))
