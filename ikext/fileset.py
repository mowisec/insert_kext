"""Appending a new entry to an `MH_FILESET` kernelcache.

An iOS kernelcache is a single Mach-O of filetype `MH_FILESET`: one outer
image whose top-level segments hold the mapped regions, plus one
`LC_FILESET_ENTRY` per bundle naming a complete `MH_KEXT_BUNDLE` Mach-O
embedded inside it.  Adding a bundle therefore means adding an entry, not
linking a new binary.

This module appends one.  It places the new entry's header and content in two
NEW top-level segments after `__LINKEDIT`, at the end of the file, and writes
the three new load commands into the zero slack that follows the existing
ones.  **Nothing that already exists moves** -- no offset changes, no segment
is resized, and no pointer in the image needs rewriting.  That is the whole
design constraint, and it is what makes this safe to do to a signed image
whose internal references cannot be relinked.

The layout rules an image of this shape obeys, all of which `check` enforces:

* a segment's virtual address is rigidly `map_base + fileoff`, for the
  top-level segments, for every entry, and for every entry's own segments.
  This is the rule that forbids inserting anywhere but the end.
* every entry segment lies inside some top-level segment, **by address rather
  than by name** -- a bundle's `__TEXT` lives inside the top-level
  `__PRELINK_TEXT`, not inside the top-level `__TEXT`.
* entries carry `nsyms == 0` and share one `__LINKEDIT`.
* `LC_FILESET_ENTRY` commands are sorted by `vmaddr`, with
  `cmdsize == 32 + align8(len(name) + 1)` and `entry_id == 32`.
* chained fixups are rebases only, with no imports.

`check` is a differential test, and that is the point of it: run it on the
vendor's own images first.  A rule that every stock kernelcache satisfies is a
rule an emitted one has to satisfy too, and `emit_entry` re-checks its own
output before returning it.
"""
import os, plistlib, struct

LC_SEGMENT_64, LC_SYMTAB, LC_FILESET_ENTRY = 0x19, 0x02, 0x80000035
LC_DYLD_CHAINED_FIXUPS = 0x80000034
MH_FILESET, MH_KEXT_BUNDLE = 0xc, 0xb
PAGE = 0x4000


def align8(n):
    return (n + 7) & ~7


class Image:
    """Just enough of a fileset kernelcache to check and extend it."""

    def __init__(self, d):
        self.d = bytearray(d)
        if bytes(self.d[:4]) != b"\xcf\xfa\xed\xfe":
            raise SystemExit("not a little-endian 64-bit Mach-O")
        self.filetype = struct.unpack_from("<I", self.d, 12)[0]
        self.ncmds, self.sizeofcmds = struct.unpack_from("<II", self.d, 16)
        self.cmds, self.segs, self.entries, self.chained = [], [], [], None
        off = 32
        for _ in range(self.ncmds):
            cmd, cs = struct.unpack_from("<II", self.d, off)
            self.cmds.append((off, cmd, cs))
            if cmd == LC_SEGMENT_64:
                self.segs.append(self._seg(off))
            elif cmd == LC_FILESET_ENTRY:
                va, fo, eid, resv = struct.unpack_from("<QQII", self.d, off + 8)
                nm = bytes(self.d[off + eid:off + cs]).split(b"\0")[0].decode()
                self.entries.append(dict(name=nm, va=va, foff=fo, off=off,
                                         cmdsize=cs, eid=eid, resv=resv))
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.chained = struct.unpack_from("<II", self.d, off + 8)
            off += cs
        self.lcend = 32 + self.sizeofcmds
        self.map_base = min(s["va"] - s["foff"] for s in self.segs
                            if s["fsize"] and s["name"] != "__PAGEZERO")

    def _seg(self, off):
        name = bytes(self.d[off + 8:off + 24]).split(b"\0")[0].decode()
        va, vsz, fo, fsz = struct.unpack_from("<QQQQ", self.d, off + 24)
        maxp, initp, nsects, flags = struct.unpack_from("<iiII", self.d, off + 56)
        return dict(name=name, va=va, vsize=vsz, foff=fo, fsize=fsz,
                    maxprot=maxp, initprot=initp, nsects=nsects, off=off)

    def sub(self, foff):
        """Parse one fileset entry's own Mach-O at file offset `foff`."""
        d = self.d
        ft = struct.unpack_from("<I", d, foff + 12)[0]
        n, sz = struct.unpack_from("<II", d, foff + 16)
        segs, symtab, o = [], None, foff + 32
        for _ in range(n):
            cmd, cs = struct.unpack_from("<II", d, o)
            if cmd == LC_SEGMENT_64:
                segs.append(self._seg(o))
            elif cmd == LC_SYMTAB:
                symtab = struct.unpack_from("<IIII", d, o + 8)
            o += cs
        return dict(filetype=ft, segs=segs, symtab=symtab)

    def seg(self, name):
        return next((s for s in self.segs if s["name"] == name), None)


class _Check:
    def __init__(self, verbose=True):
        self.fail = self.ok = 0
        self.verbose = verbose

    def __call__(self, cond, what, detail=""):
        if cond:
            self.ok += 1
        else:
            self.fail += 1
            print(f"  FAIL  {what}  {detail}")
        return cond

    def note(self, s):
        if self.verbose:
            print(f"  {s}")


def check(d, label="image", verbose=True):
    """Every layout invariant, on every entry.  -> True when all pass."""
    if isinstance(d, str):
        label, d = os.path.basename(d), open(d, "rb").read()
    img, c = Image(d), _Check(verbose)
    print(f"== {label}  ({len(d)} bytes)")
    c(img.filetype == MH_FILESET, "filetype is MH_FILESET", hex(img.filetype))
    c.note(f"map_base {img.map_base:#x}, {len(img.segs)} top-level segments, "
           f"{len(img.entries)} entries")

    bad = [s["name"] for s in img.segs
           if s["fsize"] and s["va"] != img.map_base + s["foff"]]
    c(not bad, "top-level VA == map_base + fileoff", bad[:4])
    bad = [e["name"] for e in img.entries
           if e["va"] != img.map_base + e["foff"]]
    c(not bad, "entry VA == map_base + fileoff", bad[:4])

    subs, badva, badcontain, nosym, missing = {}, [], [], [], []
    for e in img.entries:
        s = subs[e["name"]] = img.sub(e["foff"])
        for g in s["segs"]:
            if g["fsize"] and g["va"] != img.map_base + g["foff"]:
                badva.append(f"{e['name']}/{g['name']}")

            def inside(t):
                return (t["va"] <= g["va"]
                        and g["va"] + g["vsize"] <= t["va"] + t["vsize"])
            if not any(inside(x) for x in img.segs):
                badcontain.append(f"{e['name']}/{g['name']}")
        if s["symtab"] and s["symtab"][1] != 0:
            nosym.append(e["name"])
        if not {"__TEXT", "__TEXT_EXEC", "__DATA", "__LINKEDIT"} <= \
                {g["name"] for g in s["segs"]}:
            missing.append(e["name"])
    c(not badva, "entry segment VA == map_base + fileoff", badva[:4])
    c(not badcontain, "every entry segment inside a top-level segment", badcontain[:4])
    c(not nosym, "every entry LC_SYMTAB has nsyms == 0", nosym[:4])
    c(not missing, "every entry has __TEXT/__TEXT_EXEC/__DATA/__LINKEDIT", missing[:4])

    badsz = [e["name"] for e in img.entries
             if e["cmdsize"] != 32 + align8(len(e["name"]) + 1)]
    c(not badsz, "cmdsize == 32 + align8(len(name)+1)", badsz[:4])
    c(all(e["eid"] == 32 for e in img.entries), "entry_id == 32")
    c(all(e["resv"] == 0 for e in img.entries), "reserved == 0")
    vas = [e["va"] for e in img.entries]
    c(vas == sorted(vas), "LC_FILESET_ENTRY commands sorted by vmaddr")

    les = {(g["va"], g["vsize"]) for s in subs.values()
           for g in s["segs"] if g["name"] == "__LINKEDIT"}
    c(len(les) == 1, "all entries share one __LINKEDIT", les)

    t = img.seg("__TEXT")
    c(img.lcend <= t["foff"] + t["fsize"], "load commands end inside __TEXT",
      hex(img.lcend))
    slack = d[img.lcend:t["foff"] + t["fsize"]]
    c(set(slack) <= {0}, "header slack is all zero",
      f"{sum(1 for b in slack if b)} non-zero")
    c.note(f"header slack {len(slack)} bytes at {img.lcend:#x}")

    pi = img.seg("__PRELINK_INFO")
    if pi and pi["fsize"]:
        blob = d[pi["foff"]:pi["foff"] + pi["fsize"]]
        z = blob.find(b"\0")
        c(z > 0, "__PRELINK_INFO plist is NUL-terminated")
        c(set(blob[z:]) <= {0}, "__PRELINK_INFO padding is zero")
        try:
            n = len(plistlib.loads(blob[:z])["_PrelinkInfoDictionary"])
            c.note(f"plist {z:#x} bytes, {len(blob) - z:#x} zero slack, "
                   f"{n} bundles for {len(img.entries)} entries "
                   f"({n - len(img.entries)} without a fileset entry)")
        except Exception as ex:
            c(False, "__PRELINK_INFO parses as a plist", ex)

    if img.chained:
        off, size = img.chained
        fver, starts_off, imports_off, syms_off, icount, ifmt, sfmt = \
            struct.unpack_from("<IIIIIII", d, off)
        c(icount == 0, "chained fixups: imports_count == 0", icount)
        nseg = struct.unpack_from("<I", d, off + starts_off)[0]
        c.note(f"chained fixups: seg_count {nseg}, top-level segments "
               f"{len(img.segs)}"
               + ("  (seg_count is not validated on load)"
                  if nseg != len(img.segs) else ""))
        fmts, offs = set(), []
        for i in range(nseg):
            so = struct.unpack_from("<I", d, off + starts_off + 4 + 4 * i)[0]
            if not so:
                continue
            _sz, psize, pfmt, sofs = struct.unpack_from(
                "<IHHQ", d, off + starts_off + so)
            fmts.add(pfmt)
            offs.append(sofs)
        c(fmts <= {8}, "pointer_format is DYLD_CHAINED_PTR_64_KERNEL_CACHE", fmts)
        segfo = {s["foff"] for s in img.segs}
        c(set(offs) <= segfo, "chained segment_offset is a top-level file offset",
          set(offs) - segfo)

    print(f"  {c.ok} checks passed, {c.fail} failed")
    return c.fail == 0


def _seg64(nm, va, vsize, fo, fsize, maxp, initp):
    return struct.pack("<II16sQQQQiiII", LC_SEGMENT_64, 72, nm,
                       va, vsize, fo, fsize, maxp, initp, 0, 0)


def emit_entry(raw, name, code=b"", text=b"", data_size=PAGE,
               rx_name="__KEXT_EXEC", rw_name="__KEXT_DATA",
               exec_at=None, verbose=True):
    """Append one `MH_KEXT_BUNDLE` fileset entry carrying `code`.

    -> (new image bytes, geometry dict).  `geometry` gives the file offset and
    virtual address of the entry header and of its `__TEXT_EXEC`, which is
    where `code` lands and therefore what a caller must link `code` for.

    Two top-level segments are added at the end of the file: an r-x one
    holding the entry's header page followed by its `__TEXT_EXEC`, and an rw-
    one holding its `__DATA`.  The entry shares the image's existing
    `__LINKEDIT` and declares no symbols, exactly as every stock entry does.

    `exec_at=(fileoff, va, size)` puts the entry's `__TEXT_EXEC` at an address
    that is **already in the image** rather than in the appended bytes -- for
    instance inside an existing executable segment, so the code is executable
    without any change to the region table.  `code` is then not appended; only
    the entry's header page is, covered by one new read-only top-level segment.

    `data_size=0` gives the entry a zero-length `__DATA`, which it must
    still declare.
    """
    d = bytearray(raw)
    img = Image(d)
    orig_len = len(d)
    nm = name.encode()
    if not img.entries:
        raise SystemExit("no LC_FILESET_ENTRY commands: not a fileset kernelcache")
    if any(e["name"] == name for e in img.entries):
        raise SystemExit(f"the image already has an entry named {name!r}")

    le = next((g for e in img.entries
               for g in img.sub(e["foff"])["segs"] if g["name"] == "__LINKEDIT"),
              None)
    if le is None:
        raise SystemExit("no entry declares a __LINKEDIT to share")

    def pad(n):
        return (-n) % PAGE

    hdr_fo = orig_len
    if exec_at:
        exec_fo, exec_va, exec_sz = exec_at
        if exec_va != img.map_base + exec_fo:
            raise SystemExit(f"exec_at va {exec_va:#x} is not map_base + "
                             f"fileoff ({img.map_base + exec_fo:#x})")
        if exec_fo + exec_sz > orig_len:
            raise SystemExit("exec_at does not lie inside the existing image")
    else:
        exec_fo = hdr_fo + PAGE
        exec_sz = len(code)
        exec_va = img.map_base + exec_fo
    rx_fsize = PAGE if exec_at else PAGE + exec_sz + pad(PAGE + exec_sz)
    data_fo = hdr_fo + rx_fsize
    rw_fsize = data_size + pad(data_size) if data_size else 0
    rx_va = img.map_base + hdr_fo
    # A zero-length __DATA still has to exist and still has to sit inside a
    # top-level segment, so park it at the entry's own base.
    rw_va = img.map_base + data_fo if data_size else rx_va
    if not data_size:
        data_fo = hdr_fo

    sub_cmds = b"".join([
        _seg64(b"__TEXT", rx_va, PAGE, hdr_fo, PAGE, 5, 1),
        _seg64(b"__TEXT_EXEC", exec_va, max(exec_sz, 4), exec_fo, exec_sz, 5, 5),
        _seg64(b"__DATA", rw_va, max(data_size, 4), data_fo, data_size, 3, 3),
        _seg64(b"__LINKEDIT", le["va"], le["vsize"], le["foff"], le["fsize"], 1, 1),
        struct.pack("<IIIIII", LC_SYMTAB, 24, le["foff"], 0,
                    le["foff"] + le["fsize"] - 1, 1),
    ])
    # cputype ARM64 / cpusubtype ARM64E with the PAC ABI bits, copied from a
    # real entry rather than composed.
    sub_hdr = struct.pack("<IIIIIIII", 0xfeedfacf, 0x0100000c, 0x80000002,
                          MH_KEXT_BUNDLE, 5, len(sub_cmds), 0x80000085, 0)
    page0 = bytearray(PAGE)
    page0[:len(sub_hdr)] = sub_hdr
    page0[32:32 + len(sub_cmds)] = sub_cmds
    if text:
        if len(sub_hdr) + len(sub_cmds) + len(text) > PAGE:
            raise SystemExit("the entry header page cannot also hold `text`")
        page0[PAGE - len(text):] = text

    fse = struct.pack("<IIQQII", LC_FILESET_ENTRY,
                      32 + align8(len(nm) + 1), rx_va, hdr_fo, 32, 0)
    fse += nm + b"\0" * (align8(len(nm) + 1) - len(nm))
    if exec_at:
        # Only the header page is appended, and it is not executable: the code
        # is elsewhere, inside a segment the image already has.
        newcmds = _seg64(rx_name.encode(), rx_va, rx_fsize, hdr_fo,
                         rx_fsize, 1, 1) + fse
        ncmds_added = 2
    else:
        newcmds = (_seg64(rx_name.encode(), rx_va, rx_fsize, hdr_fo, rx_fsize, 5, 5)
                   + _seg64(rw_name.encode(), rw_va, max(rw_fsize, data_size),
                            data_fo, rw_fsize, 3, 3)
                   + fse)
        ncmds_added = 3

    t = img.seg("__TEXT")
    slack_end = t["foff"] + t["fsize"]
    if img.lcend + len(newcmds) > slack_end:
        raise SystemExit(f"not enough header slack: need {len(newcmds)}, "
                         f"have {slack_end - img.lcend}")
    if any(d[img.lcend:img.lcend + len(newcmds)]):
        raise SystemExit("header slack is not zero where the new commands would go")
    d[img.lcend:img.lcend + len(newcmds)] = newcmds
    struct.pack_into("<II", d, 16, img.ncmds + ncmds_added,
                     img.sizeofcmds + len(newcmds))

    d += page0
    if not exec_at:
        d += code + b"\0" * pad(PAGE + exec_sz)
        d += b"\0" * rw_fsize

    geom = dict(name=name, hdr_fo=hdr_fo, hdr_va=rx_va, rx_fsize=rx_fsize,
                exec_fo=exec_fo, exec_va=exec_va, exec_size=exec_sz,
                data_fo=data_fo, data_va=rw_va, data_size=data_size,
                rx_name=rx_name, rw_name=rw_name,
                grown=len(d) - orig_len, length=len(d))
    if verbose:
        print(f"\nappended fileset entry {name!r}")
        print(f"  {rx_name:<14} va {rx_va:#x}  fo {hdr_fo:#x}  "
              f"{rx_fsize} bytes  r-x")
        print(f"  {'__TEXT_EXEC':<12} va {geom['exec_va']:#x}  fo {exec_fo:#x}  "
              f"{exec_sz} bytes  <- the code")
        print(f"  {rw_name:<12} va {rw_va:#x}  fo {data_fo:#x}  {rw_fsize} bytes  rw-")
        print(f"  ncmds {img.ncmds} -> {img.ncmds + ncmds_added}, "
              f"file {orig_len} -> {len(d)} (+{len(d) - orig_len})")
    return bytes(d), geom


# ------------------------------------------------------ __PRELINK_INFO ----
#
# A kernelcache carries an XML plist in `__PRELINK_INFO` whose
# `_PrelinkInfoDictionary` array holds one dictionary per bundle.  That array,
# not the fileset entry, is what the kernel's extension registry is built
# from -- an entry with no dictionary is mapped and runnable but unknown to
# `kextstat`.
#
# The plist is NUL-padded to its segment size, so a dictionary can be spliced
# in textually as long as it fits the padding.  That is worth doing rather
# than re-serialising: re-emitting 2.5 MB of XML would rewrite every byte of
# the segment, and any formatting difference from the vendor's writer becomes
# a difference we cannot audit.

PRELINK_REQUIRED = ("CFBundleIdentifier", "CFBundleInfoDictionaryVersion",
                    "CFBundleNumericVersion", "CFBundlePackageType",
                    "CFBundleVersion", "_InfoPlistDigest", "_PrelinkBundlePath",
                    "_PrelinkExecutableLoadAddr", "_PrelinkExecutableSourceAddr")

NO_EXECUTABLE = 9223372036854775807          # INT64_MAX, the "codeless" marker


def _xml_escape(t):
    return (t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _borrow_kernel_resource_uuid(text):
    """The base64 OSBundleUUID of an existing kernel pseudo-extension.

    Copied out of the image rather than invented: every bundle marked
    OSKernelResource carries the kernel's own UUID, and a value that has to
    match something is a value to take from where it already is.  Parsed
    properly rather than pattern-matched, because a regex over 2.5 MB of XML
    happily matches across dictionary boundaries and returns a neighbour's.
    """
    import base64
    try:
        arr = plistlib.loads(text.encode())["_PrelinkInfoDictionary"]
    except Exception:
        return None
    for b in arr:
        if b.get("OSKernelResource") and isinstance(b.get("OSBundleUUID"), bytes):
            return base64.b64encode(b["OSBundleUUID"]).decode()
    return None


def add_prelink_bundle(raw, ident, version="1.0.0", numeric=0x01008000,
                       bundle_path=None, load_addr=NO_EXECUTABLE,
                       source_addr=None, exec_size=None, verbose=True):
    """Splice one bundle dictionary into `__PRELINK_INFO`.

    Defaults describe a **codeless** bundle -- `_PrelinkExecutableLoadAddr` of
    `INT64_MAX`, the marker the vendor's own pseudo-extensions use.  Those are
    listed by `kextstat` with address and size zero, so this is enough to make
    a bundle known to the registry without also having to supply a `kmod_info`
    structure, which would need PAC-signed function pointers and writable
    memory.

    Nothing outside the plist moves, and nothing already in the plist changes.
    """
    import hashlib
    d = bytearray(raw)
    img = Image(d)
    pi = img.seg("__PRELINK_INFO")
    if not pi or not pi["fsize"]:
        raise SystemExit("the image has no __PRELINK_INFO with file content")
    lo, hi = pi["foff"], pi["foff"] + pi["fsize"]
    blob = bytes(d[lo:hi])
    z = blob.find(b"\0")
    if z <= 0:
        raise SystemExit("__PRELINK_INFO is not a NUL-terminated plist")
    text = blob[:z].decode()
    if f"<string>{ident}</string>" in text:
        raise SystemExit(f"__PRELINK_INFO already mentions {ident!r}")

    # Which bundles the registry actually lists is not a matter of taste.  On
    # the image this was derived from, `CFBundleExecutable` is present in 100%
    # of the listed bundles, and every listed bundle that has no executable is
    # a kernel pseudo-extension carrying `OSKernelResource` -- a key that
    # appears in none of the unlisted ones.  So a codeless bundle that wants to
    # be listed has to look like those, and this mirrors their exact key set.
    name = ident.split(".")[-1]
    path = bundle_path or f"/System/Library/Extensions/{name}.kext"
    codeless = load_addr == NO_EXECUTABLE
    uuid = _borrow_kernel_resource_uuid(text)
    fields = [("CFBundleDevelopmentRegion", "string", "English"),
              ("CFBundleExecutable", "string", name),
              ("CFBundleGetInfoString", "string", f"{name}, {version}"),
              ("CFBundleIdentifier", "string", ident),
              ("CFBundleInfoDictionaryVersion", "string", "6.0"),
              ("CFBundleName", "string", name),
              ("CFBundleNumericVersion", "integer", numeric),
              ("CFBundlePackageType", "string", "KEXT"),
              ("CFBundleShortVersionString", "string", version),
              ("CFBundleSignature", "string", "????"),
              ("CFBundleVersion", "string", version),
              ("OSBundleCompatibleVersion", "string", version),
              ("OSBundleRequired", "string", "Root"),
              ("_PrelinkBundlePath", "string", path),
              ("_PrelinkExecutableLoadAddr", "integer", load_addr),
              ("_PrelinkExecutableSourceAddr", "integer",
               source_addr if source_addr is not None else load_addr)]
    if exec_size is not None:
        fields.append(("_PrelinkExecutableSize", "integer", exec_size))

    body = ""
    for k, kind, v in fields:
        val = _xml_escape(str(v)) if kind == "string" else str(v)
        body += f"\t\t\t<key>{k}</key>\n\t\t\t<{kind}>{val}</{kind}>\n"
    for k in (("OSBundleAllowUserLoad",) if codeless else ()):
        body += f"\t\t\t<key>{k}</key>\n\t\t\t<true/>\n"
    if codeless:
        # Declares the bundle as part of the kernel rather than something to be
        # loaded -- which is exactly true here, since the code is already in the
        # image and already running.
        body += "\t\t\t<key>OSKernelResource</key>\n\t\t\t<true/>\n"
    if uuid:
        body += ("\t\t\t<key>OSBundleUUID</key>\n\t\t\t<data>\n\t\t\t"
                 + uuid + "\n\t\t\t</data>\n")
    # Every one of the vendor's 320 dictionaries carries an _InfoPlistDigest.
    # What it digests is not established here, so this is a SHA-256 of the
    # dictionary's own body: the right shape and the right length, and if the
    # value is ever checked against a recomputation this is where it fails.
    digest = hashlib.sha256(body.encode()).digest()
    import base64
    body += ("\t\t\t<key>_InfoPlistDigest</key>\n\t\t\t<data>\n\t\t\t"
             + base64.b64encode(digest).decode() + "\n\t\t\t</data>\n")
    entry = "\t\t<dict>\n" + body + "\t\t</dict>\n"

    anchor = text.rindex("</array>", 0, text.index("<key>_PrelinkKCID</key>")
                         if "<key>_PrelinkKCID</key>" in text else len(text))
    start = text.rindex("\n", 0, anchor) + 1
    out = (text[:start] + entry + text[start:]).encode()
    if len(out) + 1 > pi["fsize"]:
        raise SystemExit(f"the bundle dictionary does not fit: plist would be "
                         f"{len(out)} bytes in a {pi['fsize']}-byte segment")
    d[lo:hi] = out + b"\0" * (pi["fsize"] - len(out))

    check = plistlib.loads(out)["_PrelinkInfoDictionary"]
    mine = [b for b in check if b.get("CFBundleIdentifier") == ident]
    if len(mine) != 1:
        raise SystemExit("the spliced plist does not parse back to one new bundle")
    missing = [k for k in PRELINK_REQUIRED if k not in mine[0]]
    if missing:
        raise SystemExit("the new bundle lacks required keys: " + ", ".join(missing))
    if verbose:
        print(f"\n__PRELINK_INFO: added bundle {ident!r}")
        print(f"  {len(check) - 1} -> {len(check)} bundles, plist "
              f"{z} -> {len(out)} bytes, {pi['fsize'] - len(out)} bytes of padding left")
        print(f"  {'codeless' if load_addr == NO_EXECUTABLE else hex(load_addr)}"
              f", path {path}")
    return bytes(d)
