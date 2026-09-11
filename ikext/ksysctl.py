"""Give the injected kext a real sysctl node, at BUILD time.

WHY THIS IS NOT A CALL TO `sysctl_register_oid`.  It would be, on a desktop.
On this kernel it cannot be, and the reason is worth stating because it is the
first thing anyone tries:

  * A `struct sysctl_oid_list` is a singly linked list whose head lives next
    to the parent node, and every built-in parent node lives in __DATA_CONST.
  * __DATA_CONST is read-only once boot has finished.  So is the tail OID whose
    `oid_link` an insert would have to write.
  * XNU gets away with it because every built-in OID is registered from a
    startup entry, while __DATA_CONST is still writable.  There is no third-
    party kext loading on iOS, so nothing registers a sysctl after that.

A payload hooked into ordinary running code is on the wrong side of that line.
So the registration is done in the image instead: the OID struct is written
into the kernelcache, and the parent's list head is pointed at it, exactly as
the boot-time code would have left things.  The image is doing what the boot
code does, one step earlier.

WHAT MAKES IT CHECKABLE.  The list head in a shipped kernelcache reads ZERO --
the lists really are built at boot -- so we are not editing a structure, we
are initialising an empty one, and if the head is not zero this is not the
image the config describes and the build stops.  Everything else is copied
from a REFERENCE OID that the image already contains, so the result has the
shape of an OID this kernel already dispatches rather than one derived from a
specification someone wrote down.

THE TWO POINTER-AUTHENTICATION DETAILS, both read out of this kernel rather
than assumed, because getting either wrong is a panic on first access:

  `oid_parent` is signed with key DA, address-diversified, discriminator
  0xdb49 -- which is what `sysctl_register_oid_locked` authenticates it with.

  `oid_handler` is signed with key IA, address-diversified, discriminator
  `hash16(oid_arg1 >> 4)`.  The handler is stored UNBLENDED in a shipped image
  (IA, discriminator 0x0e2e, no address diversity) because the boot-time
  registration re-signs it in place with the blend.  Nothing will re-sign
  OURS, so it has to be written already blended.  Keeping `oid_arg1` NULL is
  not an accident: it makes that hash zero, so the diversity is a constant and
  the chained fixup can express it.  A non-NULL arg1 would need the hash of a
  runtime address, which a chained fixup cannot carry.
"""
import struct

from .macho import (MachO, chain_insert, chain_page, chained_fixups, kc_parse,
                    kc_ptr, PAC_KEY_IA, PAC_KEY_DA)

OID_SIZE = 0x50
OFF_PARENT, OFF_LINK, OFF_NUMBER, OFF_KIND = 0x00, 0x08, 0x10, 0x14
OFF_ARG1, OFF_ARG2, OFF_NAME, OFF_HANDLER = 0x18, 0x20, 0x28, 0x30
OFF_FMT, OFF_DESCR, OFF_VERSION, OFF_REFCNT = 0x38, 0x40, 0x48, 0x4c

CTLTYPE_INT = 0x00000002
CTLFLAG_RD = 0x80000000
CTLFLAG_KERN = 0x00400000
CTLFLAG_LOCKED = 0x00800000
CTLFLAG_PERMANENT = 0x00200000

# Read-only int, owned by the kernel, no lock needed, and PERMANENT -- which
# is the flag that matters: sysctl_root skips the refcount increment on a
# permanent OID, and ours must be skipped because the struct is in read-only
# memory by the time anyone can call it.
DEFAULT_KIND = CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED | CTLFLAG_PERMANENT


def _plain(target_off):
    return kc_ptr(target_off)


def _align8(n):
    return (n + 7) & ~7


def check_reference(d, cfg):
    """The reference OID must still look like the OID the config was written
    against.  This is the cheapest check that the PAC fields below are this
    image's and not a previous build's."""
    sc = cfg["sysctl"]
    base = cfg["map_base"]
    ref = sc.get("reference_oid")
    if ref is None:
        return
    p = kc_parse(struct.unpack_from("<Q", d, ref - base + OFF_PARENT)[0])
    want = sc["oid_parent_pac"]
    if (p["key"], p["diversity"], p["addr_div"], p["is_auth"]) != \
       (want["key"], want["diversity"], want["addr_div"], 1):
        raise SystemExit(
            f"reference OID {ref:#x} signs oid_parent with key {p['key']} "
            f"diversity {p['diversity']:#06x} addrDiv {p['addr_div']}, but the "
            f"config says key {want['key']} diversity {want['diversity']:#06x} "
            f"addrDiv {want['addr_div']}.  This is not the image the config "
            "describes; refusing.")
    h = kc_parse(struct.unpack_from("<Q", d, ref - base + OFF_HANDLER)[0])
    if not h["is_auth"] or h["key"] != PAC_KEY_IA:
        raise SystemExit(f"reference OID {ref:#x} does not sign oid_handler "
                         "with key IA; refusing")
    v = struct.unpack_from("<i", d, ref - base + OFF_VERSION)[0]
    if v != sc.get("oid_version", 1):
        raise SystemExit(f"reference OID {ref:#x} has oid_version {v}, config "
                         f"says {sc.get('oid_version', 1)}")


def region_is_unclaimed(d, m, cfg):
    """The staging region must be outside every section of every fileset entry.

    Zero bytes are not evidence of ownership either way -- a zeroed const
    array is also zero -- so the test is structural: no section covers it.
    The space this finds is the padding between the last section in
    __DATA_CONST and the end of the segment, which is the same class of space
    as the executable slack the payload itself goes into.
    """
    base = cfg["map_base"]
    r = cfg["sysctl"]["region"]
    lo, hi = r["va"], r["va"] + r["size"]
    if r["va"] != base + r["foff"]:
        raise SystemExit(f"sysctl region VA {r['va']:#x} != map_base + "
                         f"{r['foff']:#x}; the image is not linearly mapped here")
    seg = None
    for s in m.segs:
        if s["fsize"] and s["va"] <= lo < s["va"] + s["fsize"]:
            seg = s
    if seg is None:
        raise SystemExit(f"sysctl region {lo:#x} is in no segment with file content")
    if hi > seg["va"] + seg["fsize"]:
        raise SystemExit(f"sysctl region runs past the end of {seg['name']}")
    if seg["initprot"] & 2:
        raise SystemExit(
            f"sysctl region is in {seg['name']}, which is writable at runtime.  "
            "A PERMANENT OID belongs in read-only memory, like every built-in "
            "one; refusing.")
    for nm, va in m.fileset:
        try:
            km = MachO(d[va - base:])
        except Exception:
            continue
        for s in km.sects:
            if s["size"] and s["va"] < hi and lo < s["va"] + s["size"]:
                raise SystemExit(
                    f"sysctl region {lo:#x}..{hi:#x} overlaps {nm} "
                    f"{s['seg']},{s['name']} at {s['va']:#x}; refusing")
    if bytes(d[r["foff"]:r["foff"] + r["size"]]).strip(b"\0"):
        raise SystemExit(f"sysctl region at {r['foff']:#x} is not all zeros")
    return seg


def install(d, cfg, handler_va, name, descr, value):
    """Write the OID and splice it onto the parent's list.  Returns a report."""
    base = cfg["map_base"]
    sc = cfg["sysctl"]
    m = MachO(bytes(d))
    seg = region_is_unclaimed(d, m, cfg)
    check_reference(d, cfg)

    head = sc["parent_children"]
    head_raw = struct.unpack_from("<Q", d, head - base)[0]
    if head_raw != 0:
        raise SystemExit(
            f"the parent list head at {head:#x} reads {head_raw:#018x}, not 0.  "
            "A shipped kernelcache builds its sysctl lists at boot and leaves "
            "this zero, so either the image is already patched or the config "
            "names the wrong address.  Refusing.")

    r = sc["region"]
    oid_off, oid_va = r["foff"], r["va"]
    if OID_SIZE > r["size"]:
        raise SystemExit("sysctl region is smaller than one struct sysctl_oid")

    # Strings after the struct.  They need no fixups, being data rather than
    # pointers, which is why they can sit anywhere the OID can reach.
    cur = oid_off + OID_SIZE
    strs = {}
    for key, text in (("name", name), ("fmt", "I"), ("descr", descr)):
        b = text.encode() + b"\0"
        if cur + len(b) > r["foff"] + r["size"]:
            raise SystemExit("sysctl region is too small for the OID strings")
        d[cur:cur + len(b)] = b
        strs[key] = cur
        cur = _align8(cur + len(b))

    # The scalar fields, written first so the chain work below is the only
    # thing left that can fail.
    struct.pack_into("<i", d, oid_off + OFF_NUMBER, sc.get("oid_number", 1))
    struct.pack_into("<I", d, oid_off + OFF_KIND, sc.get("oid_kind", DEFAULT_KIND))
    struct.pack_into("<q", d, oid_off + OFF_ARG1, 0)      # see the module note
    struct.pack_into("<i", d, oid_off + OFF_ARG2, value)
    struct.pack_into("<i", d, oid_off + OFF_VERSION, sc.get("oid_version", 1))
    struct.pack_into("<i", d, oid_off + OFF_REFCNT, 0)
    struct.pack_into("<Q", d, oid_off + OFF_LINK, 0)      # end of list, raw

    fixups = chained_fixups(d)
    seg_i = m.seg_of_offset(oid_off)
    pp = sc["oid_parent_pac"]
    hp = sc["oid_handler_pac"]
    links = [
        (oid_off + OFF_PARENT,
         kc_ptr(head - base, pp["diversity"], pp["addr_div"], pp["key"],
                is_auth=1)),
        (oid_off + OFF_NAME, _plain(strs["name"])),
        (oid_off + OFF_HANDLER,
         kc_ptr(handler_va - base, hp.get("diversity", 0),
                hp.get("addr_div", 1), hp.get("key", PAC_KEY_IA), is_auth=1)),
        (oid_off + OFF_FMT, _plain(strs["fmt"])),
        (oid_off + OFF_DESCR, _plain(strs["descr"])),
    ]
    for off, val in links:
        chain_insert(d, fixups, seg_i, off, val)

    # And the list head, which is the step that makes the node reachable.
    chain_insert(d, fixups, m.seg_of_offset(head - base), head - base,
                 _plain(oid_off))

    return verify(d, cfg, handler_va, name)


def verify(d, cfg, handler_va, name):
    """Decode what was written, as a reader of the image would see it."""
    base = cfg["map_base"]
    sc = cfg["sysctl"]
    head = sc["parent_children"]
    oid_va = sc["region"]["va"]
    got = base + kc_parse(struct.unpack_from("<Q", d, head - base)[0])["target"]
    if got != oid_va:
        raise SystemExit(f"list head points at {got:#x}, not the new OID {oid_va:#x}")
    o = oid_va - base
    p = kc_parse(struct.unpack_from("<Q", d, o + OFF_PARENT)[0])
    h = kc_parse(struct.unpack_from("<Q", d, o + OFF_HANDLER)[0])
    n = kc_parse(struct.unpack_from("<Q", d, o + OFF_NAME)[0])
    nm_off = n["target"]
    nm = bytes(d[nm_off:d.index(b"\0", nm_off)]).decode()
    if nm != name:
        raise SystemExit(f"oid_name decodes to {nm!r}, not {name!r}")
    if base + p["target"] != head:
        raise SystemExit("oid_parent does not point at the parent list")
    if base + h["target"] != handler_va:
        raise SystemExit("oid_handler does not point at the payload handler")
    return dict(oid_va=oid_va, name=nm, head=head,
                kind=struct.unpack_from("<I", d, o + OFF_KIND)[0],
                number=struct.unpack_from("<i", d, o + OFF_NUMBER)[0],
                arg2=struct.unpack_from("<i", d, o + OFF_ARG2)[0],
                handler=handler_va,
                parent_pac=(p["key"], p["diversity"], p["addr_div"]),
                handler_pac=(h["key"], h["diversity"], h["addr_div"]))
