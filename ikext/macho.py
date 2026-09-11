"""Mach-O and chained-fixup support for insert_kext.

A kernelcache of this era is an MH_FILESET that maps LINEARLY, so
``VA == map_base + file_offset`` for every segment with file content.  Every
address calculation in this tool assumes that, and ``insert_kext.py info``
refuses to continue on an image where it does not hold.

Pointers in __DATA, __DATA_CONST and __DATA_SPTM are not plain VAs in the
file.  They are links in a singly linked list threaded THROUGH THE POINTERS
THEMSELVES, one chain per page, which the loader walks at boot to rebase and
to sign.  The encoding (DYLD_CHAINED_PTR_64_KERNEL_CACHE, pointer_format 8) is

    bits  0..29   target, an offset from map_base   (30 bits)
    bits 30..31   cacheLevel
    bits 32..47   PAC diversity
    bit  48       addrDiv
    bits 49..50   PAC key   (0=IA 1=IB 2=DA 3=DB)
    bits 51..62   next, in 4-byte units; 0 ends the chain
    bit  63       isAuth

Two consequences, and they are why this file exists rather than a struct.pack:

  * You cannot just store a VA.  Rewrite the low 30 bits and leave the PAC
    fields alone, so the loader signs the new target with the same key and
    diversity the reader will authenticate it with.
  * You cannot add a pointer without repairing the chain.  A value written
    into a slot the chain does not visit is never rebased, and a mangled
    `next` detaches every fixup after it on that page.

`chain_insert` is the one operation that adds a link, and it verifies the
result by re-walking the page rather than by trusting its own arithmetic.
"""
import struct

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_FILESET_ENTRY = 0x80000035

CHAINED_PTR_START_NONE = 0xffff

PAC_KEY_IA, PAC_KEY_IB, PAC_KEY_DA, PAC_KEY_DB = 0, 1, 2, 3


class MachO:
    """Enough of a Mach-O reader for a kernelcache and for our own payload."""

    def __init__(self, data):
        self.d = data
        if data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("not a little-endian 64-bit Mach-O")
        self.filetype = struct.unpack_from("<I", data, 12)[0]
        ncmds, szcmds = struct.unpack_from("<II", data, 16)
        self.ncmds, self.sizeofcmds = ncmds, szcmds
        self.segs, self.sects, self.fileset, self.syms = [], [], [], {}
        off = 32
        for _ in range(ncmds):
            cmd, cs = struct.unpack_from("<II", data, off)
            if cmd == LC_SEGMENT_64:
                name = data[off + 8:off + 24].split(b"\0")[0].decode()
                va, vsz, fo, fsz = struct.unpack_from("<QQQQ", data, off + 24)
                maxp, initp, nsects = struct.unpack_from("<iiI", data, off + 56)
                self.segs.append(dict(name=name, va=va, vsize=vsz, foff=fo,
                                      fsize=fsz, maxprot=maxp, initprot=initp))
                so = off + 72
                for _ in range(nsects):
                    sn = data[so:so + 16].split(b"\0")[0].decode()
                    sa, ssz, sf = struct.unpack_from("<QQI", data, so + 32)
                    self.sects.append(dict(seg=name, name=sn, va=sa,
                                           size=ssz, foff=sf))
                    so += 80
            elif cmd == LC_FILESET_ENTRY:
                va, fo, noff = struct.unpack_from("<QQI", data, off + 8)
                nm = data[off + noff:off + cs].split(b"\0")[0]
                self.fileset.append((nm.decode("ascii", "replace"), va))
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, _ = struct.unpack_from("<IIII", data, off + 8)
                for i in range(nsyms):
                    n_strx = struct.unpack_from("<I", data, symoff + i * 16)[0]
                    n_value = struct.unpack_from("<Q", data, symoff + i * 16 + 8)[0]
                    end = data.index(b"\0", stroff + n_strx)
                    self.syms[data[stroff + n_strx:end].decode()] = n_value
            off += cs

    def segment(self, name):
        for s in self.segs:
            if s["name"] == name:
                return s
        return None

    def section(self, seg, name):
        for s in self.sects:
            if s["seg"] == seg and s["name"] == name:
                return s
        return None

    def seg_of_offset(self, fo):
        """Index of the segment whose file content covers `fo`."""
        for i, s in enumerate(self.segs):
            if s["fsize"] and s["foff"] <= fo < s["foff"] + s["fsize"]:
                return i
        return None

    def prot(self, s):
        return "".join(c if s["initprot"] & b else "-"
                       for c, b in (("r", 1), ("w", 2), ("x", 4)))


# ------------------------------------------------------- chained fixups ----

def chained_fixups(d):
    """Parse LC_DYLD_CHAINED_FIXUPS -> {segment index: starts-in-segment}."""
    ncmds = struct.unpack_from("<I", d, 16)[0]
    off, blob = 32, None
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", d, off)
        if cmd == LC_DYLD_CHAINED_FIXUPS:
            blob = struct.unpack_from("<I", d, off + 8)[0]
        off += cs
    if blob is None:
        return {}
    starts_off = struct.unpack_from("<I", d, blob + 4)[0]
    si = blob + starts_off
    seg_count = struct.unpack_from("<I", d, si)[0]
    out = {}
    for i in range(seg_count):
        so = struct.unpack_from("<I", d, si + 4 + i * 4)[0]
        if so == 0:
            continue
        p = si + so
        size, page_size, fmt, seg_off, maxv, page_count = \
            struct.unpack_from("<IHHQIH", d, p)
        out[i] = dict(page_size=page_size, fmt=fmt, seg_off=seg_off,
                      page_count=page_count,
                      pages=list(struct.unpack_from(f"<{page_count}H", d, p + 22)),
                      at=p, pages_at=p + 22)
    return out


def chain_page(d, info, page):
    """File offsets of every fixup on one page, in chain order."""
    start = info["pages"][page]
    if start == CHAINED_PTR_START_NONE:
        return []
    at = info["seg_off"] + page * info["page_size"] + start
    seen, guard = [], 0
    while True:
        seen.append(at)
        nxt = (struct.unpack_from("<Q", d, at)[0] >> 51) & 0xfff
        if nxt == 0:
            return seen
        at += nxt * 4
        guard += 1
        if guard > info["page_size"] // 4:
            raise SystemExit(f"chained fixup chain on page {page} does not terminate")


def kc_ptr(target, diversity=0, addr_div=0, key=0, nxt=0, is_auth=0, cache_level=0):
    if target >= (1 << 30):
        raise SystemExit(f"chained pointer target {target:#x} does not fit 30 bits")
    return (target | (cache_level << 30) | (diversity << 32) | (addr_div << 48)
            | (key << 49) | (nxt << 51) | (is_auth << 63))


def kc_parse(raw):
    return dict(target=raw & 0x3fffffff, cache_level=(raw >> 30) & 3,
                diversity=(raw >> 32) & 0xffff, addr_div=(raw >> 48) & 1,
                key=(raw >> 49) & 3, next=(raw >> 51) & 0xfff,
                is_auth=(raw >> 63) & 1)


def _set_next(d, at, nxt):
    raw = struct.unpack_from("<Q", d, at)[0]
    struct.pack_into("<Q", d, at, (raw & ~(0xfff << 51)) | (nxt << 51))


def chain_insert(d, fixups, seg_i, file_off, value):
    """Make `file_off` a link on its page's chain, holding `value`.

    `value` is a chained pointer word WITHOUT its `next` field; this sets the
    `next` for it and repairs the predecessor's.  Returns the new chain.

    Three cases, and the tool relies on all three:

      * the page has no chain at all (`start == NONE`) -- the case for a fresh
        page claimed out of __DATA_CONST zero space.  We become its start.
      * we sort before every existing link -- we become the start and point at
        what used to be first.
      * we sort after some link -- that link's `next` comes to us and we
        inherit the one it had.

    The page is re-walked afterwards and the result must be exactly the old
    chain plus this one offset, in order.  Arithmetic that is merely plausible
    is how a page of pointers stops being rebased with nothing looking wrong.
    """
    if seg_i not in fixups:
        raise SystemExit(f"segment index {seg_i} carries no chained fixups; "
                         "a pointer written there would never be rebased")
    fi = fixups[seg_i]
    ps = fi["page_size"]
    if file_off % 8:
        raise SystemExit(f"chain link {file_off:#x} is not 8-byte aligned")
    page = (file_off - fi["seg_off"]) // ps
    if not 0 <= page < fi["page_count"]:
        raise SystemExit(f"{file_off:#x} is outside the fixup pages of segment {seg_i}")
    before = chain_page(d, fi, page)
    if file_off in before:
        raise SystemExit(f"{file_off:#x} is already a chain link; refusing to guess")

    after_links = [x for x in before if x > file_off]
    succ = after_links[0] if after_links else None
    nxt = (succ - file_off) // 4 if succ is not None else 0
    if nxt > 0xfff:
        raise SystemExit(f"distance to the next chain link ({nxt * 4} bytes) "
                         "does not fit the 12-bit `next` field")
    struct.pack_into("<Q", d, file_off, value | (nxt << 51))

    pred = [x for x in before if x < file_off]
    if pred:
        p = pred[-1]
        delta = (file_off - p) // 4
        if delta > 0xfff:
            raise SystemExit(f"distance from the previous chain link "
                             f"({delta * 4} bytes) does not fit `next`")
        _set_next(d, p, delta)
    else:
        start = file_off - (fi["seg_off"] + page * ps)
        struct.pack_into("<H", d, fi["pages_at"] + page * 2, start)
        fi["pages"][page] = start

    got = chain_page(d, fi, page)
    want = sorted(set(before) | {file_off})
    if got != want:
        raise SystemExit(
            f"chained fixup chain on page {page} changed shape: "
            f"{len(before)} links -> {len(got)}; expected exactly one more")
    return got
